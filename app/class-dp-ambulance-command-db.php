<?php
/**
 * ambulance db
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scan posts, comments, and meta tables for implant / webshell markers.
 */
class DP_Ambulance_Command_Db extends DP_Ambulance_Command {

	const ROW_LIMIT = 25;

	/**
	 * Option/post/meta value needles for SQL LIKE scans.
	 *
	 * @var string[]
	 */
	public static $db_value_needles = array(
		'__SC_BOOT',
		'SC_ADV_BEGIN',
		'SC_CORE_BOOT',
		'SC_WC',
		'SCOCV',
		'retadpu-ohce',
		'echo-updater-x',
		'Vista Connector Box',
		'0x9A4752cAA1C15868487A0ACb691F81bfA901E063',
		'eval(base64_decode',
		'gzinflate(base64_decode',
		'FilesMan',
		'PBN-LINKS',
		'_ticker_slot_html',
		'content_sync_helper_footer_links',
		'wp_helper_uid',
		'Widget cache bootstrap, ver b2ccbcd25e',
		'Runtime dependencies bootstrap 9b66554fd3',
	);

	/**
	 * Scan post/comment/usermeta content for known implant and webshell strings.
	 *
	 * ## OPTIONS
	 *
	 * [--network]
	 * : Run on every site.
	 *
	 * [--format=<format>]
	 * : table, csv, json, json_pretty, or count. Default: table.
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		if ( ! empty( $assoc_args['network'] ) && is_multisite() ) {
			$this->run_per_site( array( $this, '__invoke' ), $args, $assoc_args );
			return;
		}

		unset( $args );
		global $wpdb;

		WP_CLI::log( '== Database content (' . home_url( '/' ) . ') ==' );

		$targets = array(
			array(
				'table'   => $wpdb->posts,
				'id_col'  => 'ID',
				'name_col'=> 'post_type',
				'value'   => 'post_content',
			),
			array(
				'table'   => $wpdb->postmeta,
				'id_col'  => 'meta_id',
				'name_col'=> 'meta_key',
				'value'   => 'meta_value',
			),
			array(
				'table'   => $wpdb->comments,
				'id_col'  => 'comment_ID',
				'name_col'=> 'comment_author',
				'value'   => 'comment_content',
			),
			array(
				'table'   => $wpdb->commentmeta,
				'id_col'  => 'meta_id',
				'name_col'=> 'meta_key',
				'value'   => 'meta_value',
			),
			array(
				'table'   => $wpdb->usermeta,
				'id_col'  => 'umeta_id',
				'name_col'=> 'meta_key',
				'value'   => 'meta_value',
			),
		);

		$rows = array();
		foreach ( $targets as $target ) {
			foreach ( self::$db_value_needles as $needle ) {
				$like = '%' . $wpdb->esc_like( $needle ) . '%';
				$found = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT {$target['id_col']} AS row_id, {$target['name_col']} AS name, LENGTH({$target['value']}) AS bytes
						FROM {$target['table']}
						WHERE {$target['value']} LIKE %s
						LIMIT %d",
						$like,
						self::ROW_LIMIT
					),
					ARRAY_A
				);
				if ( ! $found ) {
					continue;
				}
				foreach ( $found as $hit ) {
					$rows[] = array(
						'table'  => $target['table'],
						'row_id' => $hit['row_id'],
						'name'   => $hit['name'],
						'bytes'  => $hit['bytes'],
						'needle' => $needle,
					);
				}
			}
		}

		$rows = array_merge( $rows, $this->scan_snippet_tables() );
		$rows = $this->unique_db_rows( $rows );

		if ( ! $rows ) {
			WP_CLI::success( 'No matching post/comment/meta/snippet values.' );
			return;
		}

		$this->output_rows( $rows, array( 'table', 'row_id', 'name', 'bytes', 'needle' ), $assoc_args );
		WP_CLI::warning( count( $rows ) . ' row(s). Review in the DB; this command does not delete content.' );
	}

	/**
	 * Scan Code Snippets / WPCode tables if they exist.
	 *
	 * @return array
	 */
	protected function scan_snippet_tables() {
		global $wpdb;

		$sources = array(
			array(
				'table' => $wpdb->prefix . 'snippets',
				'id'    => 'id',
				'name'  => 'name',
				'code'  => 'code',
			),
			array(
				'table' => $wpdb->prefix . 'wpcode_snippets',
				'id'    => 'id',
				'name'  => 'note',
				'code'  => 'code',
			),
		);

		$rows = array();
		foreach ( $sources as $source ) {
			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $source['table'] ) );
			if ( $exists !== $source['table'] ) {
				continue;
			}
			foreach ( self::$db_value_needles as $needle ) {
				$like  = '%' . $wpdb->esc_like( $needle ) . '%';
				$found = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT `{$source['id']}` AS row_id, `{$source['name']}` AS name, LENGTH(`{$source['code']}`) AS bytes
						FROM `{$source['table']}`
						WHERE `{$source['code']}` LIKE %s
						LIMIT %d",
						$like,
						self::ROW_LIMIT
					),
					ARRAY_A
				);
				if ( ! $found ) {
					continue;
				}
				foreach ( $found as $hit ) {
					$rows[] = array(
						'table'  => $source['table'],
						'row_id' => $hit['row_id'],
						'name'   => $hit['name'],
						'bytes'  => $hit['bytes'],
						'needle' => $needle,
					);
				}
			}
		}

		return $rows;
	}

	/**
	 * Collapse duplicate table/row_id pairs, joining needles.
	 *
	 * @param array $rows Rows.
	 * @return array
	 */
	protected function unique_db_rows( $rows ) {
		$out = array();
		foreach ( $rows as $row ) {
			$key = $row['table'] . ':' . $row['row_id'];
			if ( isset( $out[ $key ] ) ) {
				$needles = array_filter( array_map( 'trim', explode( ',', $out[ $key ]['needle'] ) ) );
				if ( ! in_array( $row['needle'], $needles, true ) ) {
					$out[ $key ]['needle'] .= ', ' . $row['needle'];
				}
				continue;
			}
			$out[ $key ] = $row;
		}
		return array_values( $out );
	}
}
