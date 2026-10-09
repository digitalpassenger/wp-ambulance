<?php
/**
 * Shared helpers for ambulance subcommands (CLI plumbing + thin FS path utils).
 *
 * Filesystem scanning / path classification lives on DP_Ambulance_Command_Files.
 * Destructive collectors live on DP_Ambulance_Command_Purge_Files (extends Files).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base command: multisite runner, output helpers, skip/relative path utils.
 */
class DP_Ambulance_Command {

	/**
	 * Run a site-scoped callback, optionally across the network.
	 *
	 * @param callable $callback   Callback receiving ( $args, $assoc_args ).
	 * @param array    $args       Positional args.
	 * @param array    $assoc_args Assoc args.
	 */
	protected function run_per_site( $callback, $args, $assoc_args ) {
		if ( empty( $assoc_args['network'] ) || ! is_multisite() ) {
			$callback( $args, $assoc_args );
			return;
		}

		unset( $assoc_args['network'] );

		$sites = get_sites( array( 'number' => 0 ) );
		foreach ( $sites as $site ) {
			switch_to_blog( (int) $site->blog_id );
			WP_CLI::log( '' );
			WP_CLI::log( '---- site ' . $site->blog_id . ' ----' );
			$callback( $args, $assoc_args );
			restore_current_blog();
		}
	}

	/**
	 * @param string $path Path.
	 */
	protected function should_skip_path( $path ) {
		$skip_bits = array(
			'/node_modules/',
			'/.git/',
			'/vendor/',
		);
		foreach ( $skip_bits as $bit ) {
			if ( false !== strpos( $path, $bit ) ) {
				return true;
			}
		}

		$plugin_dir = wp_normalize_path( DP_AMBULANCE_DIR );
		$normalized = wp_normalize_path( $path );
		if ( 0 === strpos( $normalized, $plugin_dir ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param string $path Absolute path.
	 */
	protected function relative_to_content( $path ) {
		$root = wp_normalize_path( WP_CONTENT_DIR );
		$path = wp_normalize_path( $path );
		if ( 0 === strpos( $path, $root ) ) {
			return ltrim( substr( $path, strlen( $root ) ), '/' );
		}
		return $path;
	}

	/**
	 * @param array  $rows Rows.
	 * @param string $key  Unique key.
	 */
	protected function unique_rows_by_id( $rows, $key ) {
		$out = array();
		foreach ( $rows as $row ) {
			if ( ! isset( $row[ $key ] ) ) {
				$out[] = $row;
				continue;
			}
			$out[ $row[ $key ] ] = $row;
		}
		return array_values( $out );
	}

	/**
	 * @param array  $assoc_args Assoc args.
	 * @param string $default    Default format.
	 * @return string
	 */
	protected function output_format( $assoc_args, $default = 'table' ) {
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : $default;
		if ( ! in_array( $format, array( 'table', 'csv', 'json', 'json_pretty', 'count' ), true ) ) {
			WP_CLI::error( 'Invalid --format. Use table, csv, json, json_pretty, or count.' );
		}
		return $format;
	}

	/**
	 * @param array $rows       Rows.
	 * @param array $fields     Field names.
	 * @param array $assoc_args Assoc args.
	 */
	protected function output_rows( $rows, $fields, $assoc_args ) {
		WP_CLI\Utils\format_items( $this->output_format( $assoc_args ), $rows, $fields );
	}

	/**
	 * Parse --since into a unix timestamp, or 0 for no filter.
	 * Accepts "24h", "7d", or any strtotime() string. Uses file ctime.
	 *
	 * @param array $assoc_args Assoc args.
	 * @return int
	 */
	protected function parse_since( $assoc_args ) {
		if ( empty( $assoc_args['since'] ) ) {
			return 0;
		}
		$raw = trim( (string) $assoc_args['since'] );
		if ( preg_match( '/^(\d+)\s*h$/i', $raw, $m ) ) {
			return time() - ( (int) $m[1] * HOUR_IN_SECONDS );
		}
		if ( preg_match( '/^(\d+)\s*d$/i', $raw, $m ) ) {
			return time() - ( (int) $m[1] * DAY_IN_SECONDS );
		}
		$ts = strtotime( $raw );
		if ( false === $ts ) {
			WP_CLI::error( 'Invalid --since value. Try 24h, 7d, or a date.' );
		}
		return (int) $ts;
	}

	/**
	 * Run a WP-CLI subcommand in-process and return stdout/stderr/code.
	 *
	 * @param string $command Command without leading wp.
	 * @return array{stdout:string,stderr:string,return_code:int}
	 */
	protected function run_wp_command( $command ) {
		$result = WP_CLI::runcommand(
			$command,
			array(
				'return'     => 'all',
				'parse'      => false,
				'exit_error' => false,
				'launch'     => false,
			)
		);

		return array(
			'stdout'      => isset( $result->stdout ) ? (string) $result->stdout : '',
			'stderr'      => isset( $result->stderr ) ? (string) $result->stderr : '',
			'return_code' => isset( $result->return_code ) ? (int) $result->return_code : 1,
		);
	}
}
