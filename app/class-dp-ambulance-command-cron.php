<?php
/**
 * ambulance cron
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * List cron hooks whose names look like this family.
 */
class DP_Ambulance_Command_Cron extends DP_Ambulance_Command {

	/**
	 * Cron hook prefixes from this implant family.
	 *
	 * @var string[]
	 */
	public static $hook_prefixes = array(
		'sc_',
	);

	/**
	 * Cron hook name fragments (match anywhere).
	 *
	 * @var string[]
	 */
	public static $hook_fragments = array(
		'sc_cron',
		'sc_admin',
	);

	/**
	 * List cron hooks whose names look like this family.
	 *
	 * ## OPTIONS
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

		unset( $args, $assoc_args );
		WP_CLI::log( '== Cron (' . home_url( '/' ) . ') ==' );

		$cron = _get_cron_array();
		if ( ! is_array( $cron ) ) {
			WP_CLI::success( 'No cron array.' );
			return;
		}

		$rows = array();
		foreach ( $cron as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}
			foreach ( $hooks as $hook => $events ) {
				$match = false;
				foreach ( self::$hook_prefixes as $prefix ) {
					if ( 0 === strpos( $hook, $prefix ) ) {
						$match = true;
						break;
					}
				}
				if ( ! $match ) {
					foreach ( self::$hook_fragments as $fragment ) {
						if ( false !== strpos( $hook, $fragment ) ) {
							$match = true;
							break;
						}
					}
				}
				if ( ! $match ) {
					continue;
				}
				$rows[] = array(
					'hook'      => $hook,
					'timestamp' => $timestamp,
					'when'      => gmdate( 'c', (int) $timestamp ),
					'events'    => is_array( $events ) ? (string) count( $events ) : '1',
				);
			}
		}

		if ( ! $rows ) {
			WP_CLI::success( 'No sc_* cron hooks found.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $rows, array( 'hook', 'timestamp', 'when', 'events' ) );
		WP_CLI::warning( 'Clear after file cleanup: wp cron event delete <hook>' );
	}
}
