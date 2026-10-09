<?php
/**
 * ambulance dropins
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Check drop-ins and prepend config under wp-content.
 */
class DP_Ambulance_Command_Dropins extends DP_Ambulance_Command_Files {

	/**
	 * Check drop-ins and prepend config under wp-content.
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		unset( $args, $assoc_args );
		$content = WP_CONTENT_DIR;
		$paths   = array(
			$content . '/advanced-cache.php',
			$content . '/db.php',
			$content . '/object-cache.php',
			$content . '/.user.ini',
			$content . '/.htaccess',
			$content . '/uploads/.htaccess',
			ABSPATH . '.user.ini',
			ABSPATH . '.htaccess',
		);

		// Expected .htaccess locations: only report when markers/prepend hit.
		$marker_only = array(
			wp_normalize_path( $content . '/.htaccess' )         => true,
			wp_normalize_path( $content . '/uploads/.htaccess' ) => true,
		);

		$rows = array();
		foreach ( $paths as $path ) {
			if ( ! is_file( $path ) ) {
				continue;
			}
			$hits = $this->scan_file_for_needles( $path );
			$auto = $this->file_mentions_auto_prepend( $path );
			if ( $hits || $auto ) {
				$rows[] = array(
					'file'    => $path,
					'hits'    => $hits ? implode( ', ', $hits ) : '',
					'prepend' => $auto ? 'auto_prepend_file' : '',
				);
			} elseif ( isset( $marker_only[ wp_normalize_path( $path ) ] ) ) {
				continue;
			} else {
				$rows[] = array(
					'file'    => $path,
					'hits'    => '(present, no known markers)',
					'prepend' => '',
				);
			}
		}

		WP_CLI::log( '== Drop-ins / prepend ==' );
		if ( ! $rows ) {
			WP_CLI::success( 'No drop-in or prepend files found at the usual paths.' );
			return;
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'file', 'hits', 'prepend' ) );
	}
}
