<?php
/**
 * ambulance integrity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Compare core/plugin/theme files against wordpress.org checksums.
 */
class DP_Ambulance_Command_Integrity extends DP_Ambulance_Command {

	/**
	 * Verify WordPress core, plugins, and themes against published checksums.
	 *
	 * Unknown files (not in the official package) are the interesting IR signal:
	 * extra PHP in wp-admin/wp-includes, or modified plugin files.
	 *
	 * ## OPTIONS
	 *
	 * [--skip-plugins]
	 * : Skip plugin checksums.
	 *
	 * [--skip-themes]
	 * : Skip theme checksums.
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		unset( $args );
		$failed = 0;

		WP_CLI::log( '== Core checksums ==' );
		$core = $this->run_wp_command( 'core verify-checksums' );
		$this->echo_wp_result( $core );
		if ( 0 !== $core['return_code'] ) {
			++$failed;
		}

		if ( empty( $assoc_args['skip-plugins'] ) ) {
			WP_CLI::log( '' );
			WP_CLI::log( '== Plugin checksums ==' );
			$plugins = $this->run_wp_command( 'plugin verify-checksums --all' );
			$this->echo_wp_result( $plugins );
			if ( 0 !== $plugins['return_code'] ) {
				++$failed;
			}
		}

		if ( empty( $assoc_args['skip-themes'] ) ) {
			WP_CLI::log( '' );
			WP_CLI::log( '== Theme checksums ==' );
			$themes = $this->run_wp_command( 'theme verify-checksums --all' );
			if ( false !== strpos( $themes['stderr'] . $themes['stdout'], "'verify-checksums' is not a registered" ) ) {
				WP_CLI::log( 'This WP-CLI version has no theme verify-checksums. Skip, or upgrade WP-CLI.' );
			} else {
				$this->echo_wp_result( $themes );
				if ( 0 !== $themes['return_code'] ) {
					++$failed;
				}
			}
		}

		$this->flag_risky_plugins();

		if ( $failed ) {
			WP_CLI::warning( "{$failed} checksum check(s) reported problems. Review modified/unknown files; replace from clean packages." );
			return;
		}

		WP_CLI::success( 'Checksum commands finished without a non-zero exit.' );
	}

	/**
	 * File-manager plugins are a common RCE entry vector for this family.
	 */
	protected function flag_risky_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();
		$risky   = array();
		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug ) {
				$slug = (string) $file;
			}
			$haystack = $slug . ' ' . ( isset( $data['Name'] ) ? $data['Name'] : '' );
			if ( ! preg_match( '/file[\s_-]*manager|file[\s_-]*browser/i', $haystack ) ) {
				continue;
			}
			$risky[] = array(
				'plugin' => $file,
				'name'   => isset( $data['Name'] ) ? $data['Name'] : $slug,
				'note'   => 'file-manager class plugin (common RCE entry; review/remove)',
			);
		}

		WP_CLI::log( '' );
		WP_CLI::log( '== Risky plugins ==' );
		if ( ! $risky ) {
			WP_CLI::success( 'No file-manager class plugins installed.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $risky, array( 'plugin', 'name', 'note' ) );
		WP_CLI::warning( count( $risky ) . ' file-manager plugin(s). This family has used WP File Manager as the foothold.' );
	}

	/**
	 * @param array $result run_wp_command() result.
	 */
	protected function echo_wp_result( $result ) {
		$text = trim( $result['stdout'] . "\n" . $result['stderr'] );
		if ( '' !== $text ) {
			WP_CLI::log( $text );
		} else {
			WP_CLI::log( '(no output, exit ' . $result['return_code'] . ')' );
		}
	}
}
