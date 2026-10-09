<?php
/**
 * ambulance fix
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bundled remediation in SC/SCOCV engine-first order.
 *
 * @see https://github.com/vapvarun/wp-malware-cleanup-mcp/blob/master/docs/case-studies/sc-scocv-dropin-backdoor-2026-09.md#remediation-engine-first-quarantine-first
 */
class DP_Ambulance_Command_Fix extends DP_Ambulance_Command {

	/**
	 * Engine-first cleanup: purge-files (reinfector/drop-ins first), purge-options, then clear cron.
	 *
	 * Destructive. Does not delete rogue admins, reinstall core/plugins, or reset passwords.
	 * Follow with: wp ambulance scan && wp ambulance playbook
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Confirm destructive actions.
	 *
	 * [--dry-run]
	 * : Preview only; do not delete files, options, or cron events.
	 *
	 * [--quarantine]
	 * : Pass through to purge-files: move targets instead of deleting.
	 *
	 * [--quarantine-dir=<path>]
	 * : Pass through to purge-files.
	 *
	 * [--network]
	 * : On multisite, purge options and clear cron on every site (file purge still once).
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		$dry     = ! empty( $assoc_args['dry-run'] );
		$network = ! empty( $assoc_args['network'] ) && is_multisite();

		if ( ! $dry && empty( $assoc_args['yes'] ) ) {
			WP_CLI::error( 'Refusing to fix without --yes (or pass --dry-run to preview).' );
		}

		WP_CLI::log( '== Ambulance fix' . ( $dry ? ' [dry-run]' : '' ) . ' ==' );
		WP_CLI::log( 'Order (engine-first): 1) purge-files  2) purge-options  3) clear ALL cron events' );

		// 1–2. Files: phase 1 reinfector+drop-ins, phase 2 payload/decoys (inside purge-files).
		WP_CLI::log( '' );
		WP_CLI::log( '---- step 1–2: purge-files (engine-first) ----' );
		$purge_files_args = $dry ? array( 'dry-run' => true ) : array( 'yes' => true );
		if ( ! empty( $assoc_args['quarantine'] ) ) {
			$purge_files_args['quarantine'] = true;
		}
		if ( ! empty( $assoc_args['quarantine-dir'] ) ) {
			$purge_files_args['quarantine-dir'] = $assoc_args['quarantine-dir'];
		}
		( new DP_Ambulance_Command_Purge_Files() )->__invoke( $args, $purge_files_args );

		// 3. Database persistence (known sc_* keys).
		WP_CLI::log( '' );
		WP_CLI::log( '---- step 3: purge-options ----' );
		if ( $dry ) {
			if ( $network ) {
				$sites = get_sites( array( 'number' => 0 ) );
				foreach ( $sites as $site ) {
					switch_to_blog( (int) $site->blog_id );
					WP_CLI::log( '' );
					WP_CLI::log( '---- site ' . $site->blog_id . ' options ----' );
					$this->preview_purge_options();
					restore_current_blog();
				}
			} else {
				$this->preview_purge_options();
			}
		} else {
			$purge_opts_args = array( 'yes' => true );
			if ( $network ) {
				$purge_opts_args['network'] = true;
			}
			( new DP_Ambulance_Command_Purge_Options() )->__invoke( $args, $purge_opts_args );
		}

		// Cron last — after engine/DB so reinfection hooks are less likely to rewrite during cleanup.
		WP_CLI::log( '' );
		WP_CLI::log( '---- step 4: clear all cron events ----' );
		WP_CLI::warning( 'Clears ALL WordPress cron events (not only sc_*). Plugins reschedule on next load.' );
		if ( $network ) {
			$sites = get_sites( array( 'number' => 0 ) );
			foreach ( $sites as $site ) {
				switch_to_blog( (int) $site->blog_id );
				WP_CLI::log( '' );
				WP_CLI::log( '---- site ' . $site->blog_id . ' cron ----' );
				$this->clear_all_cron_events( $dry );
				restore_current_blog();
			}
		} else {
			$this->clear_all_cron_events( $dry );
		}

		WP_CLI::log( '' );
		WP_CLI::success(
			$dry
				? 'Dry-run complete. Re-run with --yes to apply.'
				: 'Fix finished (files → options → cron).'
		);
		WP_CLI::warning( 'Still manual (case-study steps 4–6): delete rogue admins, verify with wp ambulance scan, harden via wp ambulance playbook.' );
	}

	/**
	 * List known sc_* options that purge-options would delete.
	 */
	protected function preview_purge_options() {
		WP_CLI::log( '== Options (' . home_url( '/' ) . ') [dry-run] ==' );

		$found = array();
		foreach ( DP_Ambulance_Command_Options::resolve_purgeable_option_names() as $name ) {
			$found[] = array( 'option_name' => $name );
		}

		if ( ! $found ) {
			WP_CLI::success( '[dry-run] no known sc_* / _transient_sc_* / _wp_cg_* options to delete.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $found, array( 'option_name' ) );
		WP_CLI::success( '[dry-run] would delete ' . count( $found ) . ' known option(s).' );
	}

	/**
	 * Remove every event from the cron array.
	 *
	 * @param bool $dry Dry-run.
	 */
	protected function clear_all_cron_events( $dry ) {
		WP_CLI::log( '== Cron (' . home_url( '/' ) . ') ==' );

		$cron = _get_cron_array();
		if ( ! is_array( $cron ) || ! $cron ) {
			WP_CLI::success( 'No cron events scheduled.' );
			return;
		}

		$hooks  = array();
		$events = 0;
		foreach ( $cron as $timestamp => $hook_list ) {
			if ( ! is_array( $hook_list ) ) {
				continue;
			}
			foreach ( $hook_list as $hook => $hook_events ) {
				$n              = is_array( $hook_events ) ? count( $hook_events ) : 1;
				$events        += $n;
				$hooks[ $hook ] = isset( $hooks[ $hook ] ) ? $hooks[ $hook ] + $n : $n;
			}
		}

		ksort( $hooks );
		$rows = array();
		foreach ( $hooks as $hook => $count ) {
			$rows[] = array(
				'hook'   => $hook,
				'events' => (string) $count,
			);
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'hook', 'events' ) );

		if ( $dry ) {
			WP_CLI::success( "[dry-run] would clear {$events} event(s) across " . count( $hooks ) . ' hook(s).' );
			return;
		}

		_set_cron_array( array() );
		WP_CLI::success( "Cleared {$events} event(s) across " . count( $hooks ) . ' hook(s). Plugins will reschedule their own hooks on next load.' );
	}
}
