<?php
/**
 * ambulance options
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * List matching wp_options rows for the current site.
 */
class DP_Ambulance_Command_Options extends DP_Ambulance_Command {

	/**
	 * Option names written by this implant family.
	 *
	 * @var string[]
	 */
	public static $option_names = array(
		'sc_cron_fetch',
		'sc_payload_t',
		'sc_payload_persistent',
		'sc_plugin_rules',
		'sc_inject_rules',
		'sc_js',
		'sc_errors',
		'sc_purge',
		'sc_pending_invalidate',
		'sc_last_recovery_check',
		'sc_last_rpc',
		'sc_last_fetch_ts',
		'sc_last_fetch_fail_ts',
		'sc_fetch_fails',
		'sc_interval',
		'sc_page',
		'sc_sw',
		'sc_last_rescan',
		'sc_migration_timeout',
		'sc_initialized',
		'sc_recover_check',
		'sc_recover_throttle',
		'sc_admin_tick',
		'sc_spread_interval',
		'sc_spread_nr',
		'sc_persist',
		'sc_persist_manifest',
		'sc_guard',
		'sc_dedup_took',
		'_transient_sc_payload_t',
		'_transient_timeout_sc_payload_t',
		// Fake "Content Sync Helper" / PBN injector footer store.
		'content_sync_helper_footer_links',
		// cg-restore host implant: serialized map of base64 payloads → restore paths.
		'_wp_cg_652_fs',
		// Passwordless admin-session backdoor coordination option.
		'wp_helper_uid',
	);

	/**
	 * Option-name LIKE patterns (SC/SCOCV persistence + cg-restore).
	 *
	 * @var string[]
	 */
	public static $option_name_likes = array(
		'sc_%',
		'_wp_cg_%',
		'_transient_sc_%',
		'_transient_timeout_sc_%',
	);

	/**
	 * Value signatures that make a bare-hex option name worth reporting.
	 *
	 * @var string[]
	 */
	public static $hex_option_value_needles = array(
		'SCOCV',
		'SC_CORE_BOOT',
		'SC_WC',
		'SC_ADV_BEGIN',
		'retadpu-ohce',
		'__PATH__',
		'echo-updater-x',
	);

	/**
	 * Byte threshold for optional large-option triage (report only; not purged).
	 *
	 * @var int
	 */
	public static $large_option_bytes = 100000;

	/**
	 * Resolve option names that purge-options / export should delete.
	 *
	 * Known list + LIKE matches that currently exist in the DB.
	 *
	 * @return string[] Unique option_name values.
	 */
	public static function resolve_purgeable_option_names() {
		global $wpdb;

		$names = self::$option_names;
		foreach ( self::$option_name_likes as $like ) {
			$extra = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
					$like
				)
			);
			if ( $extra ) {
				$names = array_merge( $names, $extra );
			}
		}

		return array_values( array_unique( $names ) );
	}

	/**
	 * List matching wp_options rows for the current site.
	 *
	 * By default searches option values for implant/C2 markers (deep).
	 * Pass --quick to only match known option names / LIKE patterns (faster).
	 *
	 * ## OPTIONS
	 *
	 * [--quick]
	 * : Skip option_value blob / hex-name / large-option scans; only known names + LIKE patterns.
	 *
	 * [--format=<format>]
	 * : table, csv, json, json_pretty, or count. Default: table.
	 *
	 * [--network]
	 * : Run on every site.
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

		$quick = ! empty( $assoc_args['quick'] );

		WP_CLI::log( '== Options (' . home_url( '/' ) . ')' . ( $quick ? ' [quick]' : ' [deep]' ) . ' ==' );

		$likes        = self::$option_name_likes;
		$placeholders = implode( ',', array_fill( 0, count( self::$option_names ), '%s' ) );
		$like_sql     = implode( ' OR ', array_fill( 0, count( $likes ), 'option_name LIKE %s' ) );
		$query        = $wpdb->prepare(
			"SELECT option_id, option_name, autoload, LENGTH(option_value) AS bytes FROM {$wpdb->options} WHERE option_name IN ($placeholders) OR $like_sql ORDER BY option_name",
			array_merge( self::$option_names, $likes )
		);
		$rows = $wpdb->get_results( $query, ARRAY_A );

		if ( ! $quick ) {
			$value_needles = array(
				'%SCOCV%',
				'%SC_CORE_BOOT%',
				'%SC_WC%',
				'%retadpu-ohce%',
				'%__SC_BOOT%',
				'%SC_ADV_BEGIN%',
				'%Vista Connector Box%',
				'%0x9A4752cAA1C15868487A0ACb691F81bfA901E063%',
				'%Widget cache bootstrap, ver b2ccbcd25e%',
				'%Runtime dependencies bootstrap 9b66554fd3%',
			);
			foreach ( $value_needles as $like ) {
				$extra = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT option_id, option_name, autoload, LENGTH(option_value) AS bytes FROM {$wpdb->options} WHERE option_value LIKE %s",
						$like
					),
					ARRAY_A
				);
				$rows = array_merge( $rows, $extra ?: array() );
			}

			$hex_rows = $wpdb->get_results(
				"SELECT option_id, option_name, autoload, LENGTH(option_value) AS bytes, option_value FROM {$wpdb->options} WHERE option_name REGEXP '^[a-f0-9]{8,12}$'",
				ARRAY_A
			);
			foreach ( $hex_rows ?: array() as $hex ) {
				$value = isset( $hex['option_value'] ) ? (string) $hex['option_value'] : '';
				$match = false;
				foreach ( self::$hex_option_value_needles as $needle ) {
					if ( false !== strpos( $value, $needle ) ) {
						$match = true;
						break;
					}
				}
				if ( ! $match ) {
					continue;
				}
				unset( $hex['option_value'] );
				$rows[] = $hex;
			}

			// Triage pivot (case-study kit): large blobs — report only, never auto-purged.
			$large = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_id, option_name, autoload, LENGTH(option_value) AS bytes FROM {$wpdb->options} WHERE LENGTH(option_value) >= %d ORDER BY bytes DESC, option_id",
					self::$large_option_bytes
				),
				ARRAY_A
			);
			if ( $large ) {
				WP_CLI::log( '' );
				WP_CLI::log( '== Large options (>= ' . self::$large_option_bytes . ' bytes; triage only, not auto-purged) ==' );
				WP_CLI\Utils\format_items( 'table', $large, array( 'option_id', 'option_name', 'autoload', 'bytes' ) );
				WP_CLI::warning( 'Size alone is not malware evidence. Review ownership before deleting.' );
			}
		}

		$rows = $this->unique_rows_by_id( $rows, 'option_id' );

		if ( ! $rows ) {
			$hint = $quick ? ' (ran --quick; omit it for option_value / hex-name / large-option scans)' : '';
			WP_CLI::success( 'No matching option names or SC/SCOCV values.' . $hint );
			return;
		}

		$this->output_rows( $rows, array( 'option_id', 'option_name', 'autoload', 'bytes' ), $assoc_args );
		WP_CLI::warning( count( $rows ) . ' option row(s). Review, then: wp ambulance purge-options --yes' );
	}
}
