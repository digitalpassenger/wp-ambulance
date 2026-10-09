<?php
/**
 * ambulance playbook
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Print helpful WP-CLI remediation commands. Does not run them.
 */
class DP_Ambulance_Command_Playbook extends DP_Ambulance_Command {

	/**
	 * Print a cleanup / hardening cheat sheet of WP-CLI commands.
	 *
	 * Read-only: lists commands you can copy. Does not execute them.
	 *
	 * ## OPTIONS
	 *
	 * [--section=<section>]
	 * : Only show one section: backup, scan, files, core, plugins, themes,
	 *   database, users, harden, verify. Default: all.
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		unset( $args );

		$sections = $this->sections();
		$want     = isset( $assoc_args['section'] ) ? strtolower( (string) $assoc_args['section'] ) : '';

		if ( $want && ! isset( $sections[ $want ] ) ) {
			WP_CLI::error(
				'Unknown --section. Use: ' . implode( ', ', array_keys( $sections ) )
			);
		}

		WP_CLI::log( '== Ambulance playbook (copy/paste; nothing is executed) ==' );
		WP_CLI::log( 'Run from the WordPress root. Take a full backup before destructive steps.' );
		WP_CLI::log( '' );

		foreach ( $sections as $key => $section ) {
			if ( $want && $want !== $key ) {
				continue;
			}
			WP_CLI::log( '## ' . $section['title'] );
			if ( ! empty( $section['note'] ) ) {
				WP_CLI::log( $section['note'] );
			}
			foreach ( $section['commands'] as $row ) {
				WP_CLI::log( '' );
				WP_CLI::log( '# ' . $row['why'] );
				WP_CLI::log( $row['cmd'] );
			}
			WP_CLI::log( '' );
		}

		WP_CLI::warning( 'Review every command before running. Premium/custom plugins and themes cannot be reinstalled from wordpress.org.' );
	}

	/**
	 * @return array<string,array{title:string,note?:string,commands:array<int,array{why:string,cmd:string}>}>
	 */
	protected function sections() {
		return array(
			'backup'   => array(
				'title'    => 'Backup first',
				'commands' => array(
					array(
						'why' => 'Database dump',
						'cmd' => 'wp db export backup-$(date +%Y%m%d-%H%M%S).sql',
					),
					array(
						'why' => 'Also snapshot files (host tool, rsync, or tar of ABSPATH + wp-content)',
						'cmd' => 'tar -czf backup-files-$(date +%Y%m%d-%H%M%S).tgz .',
					),
				),
			),
			'scan'     => array(
				'title'    => 'Scan with ambulance',
				'commands' => array(
					array(
						'why' => 'Full read-only assessment (deep options scan by default)',
						'cmd' => 'wp ambulance scan',
					),
					array(
						'why' => 'Faster triage (skip option_value blob searches)',
						'cmd' => 'wp ambulance scan --quick',
					),
					array(
						'why' => 'Files changed recently (ctime)',
						'cmd' => 'wp ambulance files --since=7d',
					),
				),
			),
			'files'    => array(
				'title'    => 'Known-bad files (ambulance)',
				'note'     => 'Every wp-content-root .php/.zip (incl. index.php/drop-ins), hex staging zips/PHP, hidden files+dirs, known basenames, .thumbnails, trace-wrapper-bit. Review dry-run first.',
				'commands' => array(
					array(
						'why' => 'Preferred when reinfects on WP load: export manifests + offline bash cleaners (no delete)',
						'cmd' => 'wp am export',
					),
					array(
						'why' => 'After export: preview offline cleanup (no WordPress)',
						'cmd' => 'cd ../ambulance-ir/<stamp> && DRY_RUN=1 ./clean-all.sh',
					),
					array(
						'why' => 'After export: apply offline cleanup (no WordPress)',
						'cmd' => 'cd ../ambulance-ir/<stamp> && ./clean-all.sh',
					),
					array(
						'why' => 'Bundled fix: clear ALL cron + purge-files + purge-options (preview)',
						'cmd' => 'wp ambulance fix --dry-run',
					),
					array(
						'why' => 'Bundled fix: clear ALL cron + purge-files + purge-options',
						'cmd' => 'wp ambulance fix --yes',
					),
					array(
						'why' => 'Preview known malicious basenames / .thumbnails trees only',
						'cmd' => 'wp ambulance purge-files --dry-run',
					),
					array(
						'why' => 'Quarantine purge-files targets (first+newest copies; preferred over delete)',
						'cmd' => 'wp ambulance purge-files --quarantine --yes',
					),
					array(
						'why' => 'Delete purge-files targets only',
						'cmd' => 'wp ambulance purge-files --yes',
					),
					array(
						'why' => 'Surgical SC marker strip (theme/config/drop-ins/prepend) — preview',
						'cmd' => 'wp ambulance sanitize --dry-run',
					),
					array(
						'why' => 'Surgical SC marker strip (backs up full infected files first)',
						'cmd' => 'wp ambulance sanitize --yes',
					),
					array(
						'why' => 'After export: short live containment while cleanup continues',
						'cmd' => 'cd ../ambulance-ir/<stamp> && INTERVAL=5 ./guard.sh',
					),
					array(
						'why' => 'Delete known sc_* / wp_helper_uid option keys (after PHP is gone)',
						'cmd' => 'wp ambulance purge-options --yes',
					),
				),
			),
			'core'     => array(
				'title'    => 'WordPress core',
				'note'     => 'Overwrites wp-admin, wp-includes, and root PHP. Keeps wp-content and wp-config.php.',
				'commands' => array(
					array(
						'why' => 'Force re-download core files',
						'cmd' => 'wp core download --force --skip-content',
					),
					array(
						'why' => 'Verify core against wordpress.org checksums',
						'cmd' => 'wp core verify-checksums',
					),
					array(
						'why' => 'Update core (if not already latest)',
						'cmd' => 'wp core update && wp core update-db',
					),
				),
			),
			'plugins'  => array(
				'title'    => 'Plugins',
				'note'     => 'wordpress.org plugins only. Skip or restore premium plugins from a clean zip.',
				'commands' => array(
					array(
						'why' => 'List installed plugins',
						'cmd' => 'wp plugin list',
					),
					array(
						'why' => 'Reinstall every plugin from wordpress.org (force)',
						'cmd' => 'wp plugin install $(wp plugin list --field=name --status=active,inactive) --force',
					),
					array(
						'why' => 'Reinstall one plugin',
						'cmd' => 'wp plugin install <slug> --force',
					),
					array(
						'why' => 'Verify plugin checksums',
						'cmd' => 'wp plugin verify-checksums --all',
					),
					array(
						'why' => 'Update all plugins',
						'cmd' => 'wp plugin update --all',
					),
					array(
						'why' => 'Remove a file-manager / leftover malware plugin',
						'cmd' => 'wp plugin delete <slug>',
					),
				),
			),
			'themes'   => array(
				'title'    => 'Themes',
				'commands' => array(
					array(
						'why' => 'List themes',
						'cmd' => 'wp theme list',
					),
					array(
						'why' => 'Reinstall every theme from wordpress.org (force)',
						'cmd' => 'wp theme install $(wp theme list --field=name) --force',
					),
					array(
						'why' => 'Reinstall one theme',
						'cmd' => 'wp theme install <slug> --force',
					),
					array(
						'why' => 'Verify theme checksums (WP-CLI version permitting)',
						'cmd' => 'wp theme verify-checksums --all',
					),
					array(
						'why' => 'Update all themes',
						'cmd' => 'wp theme update --all',
					),
				),
			),
			'database' => array(
				'title'    => 'Database / cron leftovers',
				'commands' => array(
					array(
						'why' => 'List suspicious sc_* options',
						'cmd' => 'wp ambulance options',
					),
					array(
						'why' => 'List sc_* cron hooks',
						'cmd' => 'wp ambulance cron',
					),
					array(
						'why' => 'Delete one cron hook after file cleanup',
						'cmd' => 'wp cron event delete <hook>',
					),
					array(
						'why' => 'Flush rewrite rules',
						'cmd' => 'wp rewrite flush',
					),
					array(
						'why' => 'Flush object cache (if a cache drop-in is present)',
						'cmd' => 'wp cache flush',
					),
				),
			),
			'users'    => array(
				'title'    => 'Users / sessions',
				'note'     => 'Save new passwords somewhere safe. Never delete user ID 1 without a replacement admin. If wp_helper_uid is set, remove admin-helper.php + boot-loader.php first, then destroy all sessions.',
				'commands' => array(
					array(
						'why' => 'List admins (flags suspicious logins + wp_helper_uid target)',
						'cmd' => 'wp ambulance users',
					),
					array(
						'why' => 'Reset one user password',
						'cmd' => 'wp user update <login> --user_pass="$(openssl rand -base64 24)"',
					),
					array(
						'why' => 'Reset every administrator password (prints new passwords)',
						'cmd' => 'wp user list --role=administrator --field=ID | xargs -I{} wp user update {} --user_pass="$(openssl rand -base64 24)"',
					),
					array(
						'why' => 'Delete a rogue admin; reassign content to a good admin',
						'cmd' => 'wp user delete <bad-login> --reassign=<good-admin-id>',
					),
					array(
						'why' => 'Revoke all application passwords for one user',
						'cmd' => 'wp user application-password list <login> --field=uuid | xargs -I{} wp user application-password delete <login> {}',
					),
					array(
						'why' => 'Destroy all sessions (everyone must log in again)',
						'cmd' => 'wp user session destroy --all',
					),
				),
			),
			'harden'   => array(
				'title'    => 'Hardening',
				'commands' => array(
					array(
						'why' => 'Regenerate salts in wp-config.php (invalidates cookies/sessions)',
						'cmd' => 'wp config shuffle-salts',
					),
					array(
						'why' => 'Disable theme/plugin file editor',
						'cmd' => "wp config set DISALLOW_FILE_EDIT true --raw",
					),
					array(
						'why' => 'Prefer HTTPS admin',
						'cmd' => 'wp config set FORCE_SSL_ADMIN true --raw',
					),
					array(
						'why' => 'Secure permissions (host-dependent; review first)',
						'cmd' => 'find . -type d -exec chmod 755 {} \; && find . -type f -exec chmod 644 {} \;',
					),
				),
			),
			'verify'   => array(
				'title'    => 'Verify clean',
				'commands' => array(
					array(
						'why' => 'Re-run full ambulance scan',
						'cmd' => 'wp ambulance scan',
					),
					array(
						'why' => 'Core + plugin checksums',
						'cmd' => 'wp ambulance integrity',
					),
					array(
						'why' => 'Confirm no sc_* options left',
						'cmd' => 'wp ambulance options',
					),
				),
			),
		);
	}
}
