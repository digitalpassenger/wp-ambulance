<?php
/**
 * ambulance users
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * List administrators and flag logins matching this family’s prefixes.
 */
class DP_Ambulance_Command_Users extends DP_Ambulance_Command {

	/**
	 * Suspicious administrator login prefixes from the sample.
	 *
	 * @var string[]
	 */
	public static $user_prefixes = array(
		'admin_',
		'adm_',
		'administrator_',
		'backup_',
		'content_',
		'support_',
		'editor_',
		'dev_',
		'team_',
	);

	/**
	 * Stronger login shapes (hex suffix / wp2shell / mail-daemon).
	 *
	 * @var string[]
	 */
	public static $user_login_regexes = array(
		'/^(admin|administrator|content|support|backup|editor|dev|team|adm)_[0-9a-f]{6,}$/i',
		'/^(w2s|wp2)_[0-9a-f]{6,}$/i',
		'/^mail_daemon[0-9a-f]*$/i',
	);

	/**
	 * List administrators and flag logins matching this family’s prefixes.
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
		WP_CLI::log( '== Administrators (' . home_url( '/' ) . ') ==' );

		$helper_uid = (int) get_option( 'wp_helper_uid', 0 );
		if ( $helper_uid > 0 ) {
			WP_CLI::warning(
				'Option wp_helper_uid=' . $helper_uid
				. ' (passwordless admin-session backdoor). Audit that user; remove admin-helper.php + boot-loader.php before/with the option. Destroy all sessions after cleanup.'
			);
		}

		$users = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'ID', 'user_login', 'user_email', 'user_registered' ),
			)
		);

		$rows = array();
		foreach ( $users as $user ) {
			$flag   = '';
			$labels = array( 'regex:hex-suffix', 'regex:wp2shell', 'regex:mail-daemon' );
			foreach ( self::$user_login_regexes as $i => $regex ) {
				if ( preg_match( $regex, $user->user_login ) ) {
					$flag = isset( $labels[ $i ] ) ? $labels[ $i ] : 'regex';
					break;
				}
			}
			if ( ! $flag ) {
				foreach ( self::$user_prefixes as $prefix ) {
					if ( 0 === strpos( $user->user_login, $prefix ) ) {
						$flag = 'prefix:' . $prefix;
						break;
					}
				}
			}
			if ( $helper_uid > 0 && (int) $user->ID === $helper_uid ) {
				$flag = $flag ? $flag . ';wp_helper_uid' : 'wp_helper_uid';
			}
			$rows[] = array(
				'ID'         => $user->ID,
				'login'      => $user->user_login,
				'email'      => $user->user_email,
				'registered' => $user->user_registered,
				'flag'       => $flag,
			);
		}

		if ( ! $rows ) {
			WP_CLI::warning( 'No administrators returned.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $rows, array( 'ID', 'login', 'email', 'registered', 'flag' ) );
		WP_CLI::log( 'Flagged logins are hints only. Verify every admin. Rotate passwords + destroy sessions after cleanup.' );
	}
}
