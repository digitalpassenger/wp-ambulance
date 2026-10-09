<?php
/**
 * ambulance scan
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Run every check.
 */
class DP_Ambulance_Command_Scan extends DP_Ambulance_Command {

	/**
	 * Run every check.
	 *
	 * Options scan is deep by default. Pass --quick to skip option_value blob searches.
	 *
	 * ## OPTIONS
	 *
	 * [--quick]
	 * : Passed to options: skip option_value / hex-name scans (faster on large databases).
	 *
	 * [--since=<when>]
	 * : Passed to file/heuristic scans (ctime filter). Examples: 24h, 7d.
	 *
	 * [--network]
	 * : On multisite, run per-site DB checks on every site.
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		( new DP_Ambulance_Command_Dropins() )->__invoke( $args, $assoc_args );
		( new DP_Ambulance_Command_Files() )->__invoke( $args, $assoc_args );
		( new DP_Ambulance_Command_Integrity() )->__invoke( $args, $assoc_args );
		( new DP_Ambulance_Command_Options() )->__invoke( $args, $assoc_args );
		( new DP_Ambulance_Command_Db() )->__invoke( $args, $assoc_args );
		( new DP_Ambulance_Command_Users() )->__invoke( $args, $assoc_args );
		( new DP_Ambulance_Command_Cron() )->__invoke( $args, $assoc_args );

		WP_CLI::log( '' );
		WP_CLI::warning( 'This command does not delete PHP files. Review hits, then: wp ambulance playbook' );
	}
}
