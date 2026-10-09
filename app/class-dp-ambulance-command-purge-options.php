<?php
/**
 * ambulance purge-options
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Delete known implant option keys on the current site. Does not delete files.
 */
class DP_Ambulance_Command_Purge_Options extends DP_Ambulance_Command {

	/**
	 * Delete known implant option keys on the current site. Does not delete files.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Confirm deletion.
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
		if ( empty( $assoc_args['yes'] ) ) {
			WP_CLI::error( 'Refusing to delete options without --yes. This only removes known implant option keys, not PHP files.' );
		}

		if ( ! empty( $assoc_args['network'] ) && is_multisite() ) {
			$this->run_per_site( array( $this, '__invoke' ), $args, $assoc_args );
			return;
		}

		unset( $args );
		global $wpdb;

		$deleted = 0;
		$names   = DP_Ambulance_Command_Options::resolve_purgeable_option_names();

		foreach ( $names as $name ) {
			$exists = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT option_id FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
					$name
				)
			);
			if ( ! $exists ) {
				continue;
			}
			if ( delete_option( $name ) ) {
				WP_CLI::log( 'Deleted option: ' . $name );
				++$deleted;
			}
		}

		WP_CLI::success( "Removed {$deleted} known option(s) on " . home_url( '/' ) . '.' );
	}
}
