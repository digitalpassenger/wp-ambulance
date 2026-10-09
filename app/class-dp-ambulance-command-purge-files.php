<?php
/**
 * ambulance purge-files
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Delete known malicious files, drop-ins, zips, hidden files, and fixed malware folders.
 */
class DP_Ambulance_Command_Purge_Files extends DP_Ambulance_Command_Files {

	/**
	 * Known malicious basenames. Deleted wherever found under wp-content.
	 *
	 * @var string[]
	 */
	public static $malicious_basenames = array(
		'db-45.php',
		'sunrise-45.php',
		'maintenance-45.php',
		// PBN inject hide-self MU copy of "Content Sync Helper".
		'content-sync-helper.php',
		// Hide-self / all_plugins + ?sp= gate (same family pattern as Content Sync Helper).
		'advanced-linkflow-control.php',
		// Fake "WP Security Helper" plugin identity.
		'wp-security-helper.php',
		// sc-loader restores plugins/system-control from .sc-backup/system-control.
		'sc-loader.php',
		'system-control.php',
		// cg-restore / cron-helper family companions (from infected wp-config sample).
		'custom-constants-652.php',
	);

	/**
	 * Fixed relative paths under wp-content to delete (files).
	 *
	 * @var string[]
	 */
	public static $fixed_content_files = array(
		'object-cache.php',
		'advanced-cache.php',
		'db.php',
		'.user.ini',
		'user.ini',
		'mu-plugins/content-sync-helper.php',
		'plugins/content-sync-helper.php',
		'mu-plugins/advanced-linkflow-control.php',
		'plugins/advanced-linkflow-control.php',
		'mu-plugins/wp-security-helper.php',
		'plugins/wp-security-helper.php',
		'sc-loader.php',
		'plugins/system-control/system-control.php',
		'.sc-backup/system-control/system-control.php',
		'mu-plugins/menu-queue-bit.php',
		'mu-plugins/custom-constants-652.php',
	);

	/**
	 * Candidate basenames for the wp_helper_uid pair — purged only when hash/markers match.
	 *
	 * @var string[]
	 */
	public static $wp_helper_uid_candidate_basenames = array(
		'admin-helper.php',
		'boot-loader.php',
	);

	/**
	 * Exact relative paths under wp-content for the observed wp_helper_uid placement
	 * (still require hash/marker confirmation before purge).
	 *
	 * @var string[]
	 */
	public static $wp_helper_uid_fixed_rels = array(
		'admin-helper.php',
		'mu-plugins/boot-loader.php',
	);

	/**
	 * Known decoy mu-plugin basenames from the SC/SCOCV swarm (case study).
	 *
	 * @var string[]
	 */
	public static $decoy_mu_plugin_basenames = array(
		'echo-updater-x.php',
		'file-handler-jet.php',
		'forge-analyzer-pad.php',
		'menu-patcher-tag.php',
		'menu-queue-bit.php',
		'pulse-worker-pad.php',
		'ridge-backup-mod.php',
		'trace-toolkit-go.php',
		'vital-resolver-edge.php',
	);

	/**
	 * Legitimate mu-plugin PHP files never purged by decoy/empty rules.
	 *
	 * @var string[]
	 */
	public static $mu_plugin_allowlist = array(
		'autoloader.php',
		'automation-by-installatron.php',
		'0-loader.php',
	);

	/**
	 * Fixed relative paths under wp-content to remove as directory trees.
	 *
	 * @var string[]
	 */
	public static $fixed_content_dirs = array(
		'plugins/trace-wrapper-bit',
		'mu-plugins/trace-wrapper-bit',
		'plugins/echo-updater-x',
		'mu-plugins/echo-updater-x',
		'plugins/wp-file-manager',
		// https://github.com/advisories/GHSA-p2hj-vx9x-4rh8
		'plugins/link-factory',
		// Fake "Content Sync Helper" / PBN-LINKS injector (hides from Plugins UI, copies to mu-plugins).
		'plugins/content-sync-helper',
		'mu-plugins/content-sync-helper',
		// Advanced LinkFlow Control (same hide-self / ?sp= gate family).
		'plugins/advanced-linkflow-control',
		'mu-plugins/advanced-linkflow-control',
		// Fake "WP Security Helper".
		'plugins/wp-security-helper',
		'mu-plugins/wp-security-helper',
		// sc-loader destination + backup staging.
		'plugins/system-control',
		'.sc-backup/system-control',
		'.sc-backup',
		'plugins/mailpoet-652',
	);

	/**
	 * Delete or quarantine known malware files and IR cleanup targets under wp-content.
	 *
	 * Always targets (when present):
	 * - drop-ins at wp-content root: object-cache.php, advanced-cache.php, db.php
	 * - .user.ini / user.ini at wp-content root
	 * - known malicious basenames (db-45.php, sunrise-45.php, maintenance-45.php) anywhere under wp-content
	 * - every .php and .zip directly in wp-content/ (including index.php / drop-ins)
	 * - hex-named staging zips (e.g. c76e59a3.zip) and hex drop PHP (e.g. 9dd16321.php) anywhere
	 * - every hidden file (name starts with .) under wp-content
	 * - every hidden directory (name starts with .) under wp-content (e.g. .sc_*)
	 * - plugins/trace-wrapper-bit/ and mu-plugins/trace-wrapper-bit/ (and matching .php files)
	 * - echo-updater-x* files/dirs; known decoy mu-plugin names; mu-plugins/sc_*
	 * - every 0-byte file under mu-plugins/ (except allowlisted names / dp-ambulance)
	 * - plugins/wp-file-manager/ (common RCE entry vector for this family)
	 * - plugins/link-factory/ — https://github.com/advisories/GHSA-p2hj-vx9x-4rh8
	 * - plugins/content-sync-helper/ (+ mu-plugins copy / content-sync-helper.php) — fake sync / PBN injector
	 * - plugins/advanced-linkflow-control/ (+ mu-plugins / .php copies) — hide-self / all_plugins + ?sp= gate
	 * - plugins/wp-security-helper/ (+ mu-plugins / .php copies) — fake WP Security Helper
	 * - sc-loader.php; plugins/system-control/; .sc-backup/ (+ .sc-backup/system-control backup source)
	 * - any filename containing cron-helper / db-helper / maintenance-helper; custom-constants-652.php; plugins/mailpoet-652/
	 * - themes/custom-file-* directories (file-manager theme drops, e.g. custom-file-4-1787062890)
	 * - plugins/security_<digits> directories (e.g. security_1787155594)
	 * - every uploads/.../.thumbnails directory tree
	 * - wp_helper_uid pair when hash/markers match: admin-helper.php, boot-loader.php
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Confirm deletion or quarantine.
	 *
	 * [--dry-run]
	 * : List targets only; do not delete or move.
	 *
	 * [--quarantine]
	 * : Move targets to a quarantine folder (outside the web root) instead of deleting.
	 *   Keeps a durable first copy and a newest copy per relative path.
	 *
	 * [--quarantine-dir=<path>]
	 * : Quarantine run directory. Default: {ABSPATH}/../ambulance-quarantine/{Ymd-His}/
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		unset( $args );
		$dry        = ! empty( $assoc_args['dry-run'] );
		$quarantine = ! empty( $assoc_args['quarantine'] );

		if ( ! $dry && empty( $assoc_args['yes'] ) ) {
			WP_CLI::error( 'Refusing to purge files without --yes (or pass --dry-run to preview).' );
		}

		$q_run = '';
		if ( $quarantine ) {
			$q_run = $this->resolve_quarantine_run_dir( $assoc_args );
			if ( ! $dry && ! wp_mkdir_p( $q_run ) ) {
				WP_CLI::error( 'Could not create quarantine dir: ' . $q_run );
			}
			WP_CLI::log( 'Quarantine run dir: ' . $q_run );
			WP_CLI::log( 'First-copy root:    ' . $this->quarantine_first_root( $q_run ) );
		}

		$files = $this->collect_file_targets();
		$dirs  = $this->collect_dir_targets();

		if ( ! $files && ! $dirs ) {
			WP_CLI::success( 'Nothing to purge.' );
			return;
		}

		// Engine-first (SC/SCOCV): kill reinfector + drop-ins before payload/decoy cleanup.
		$phases = $this->partition_engine_first( $files, $dirs );
		$total_files = 0;
		$total_dirs  = 0;

		foreach ( $phases as $phase ) {
			WP_CLI::log( '' );
			WP_CLI::log( '== ' . $phase['title'] . ' ==' );
			$count_files = $this->purge_file_list( $phase['files'], $dry, $q_run );
			$count_dirs  = $this->purge_dir_list( $phase['dirs'], $dry, $q_run );
			$total_files += $count_files;
			$total_dirs  += $count_dirs;
			if ( ! $count_files && ! $count_dirs ) {
				WP_CLI::log( '(none)' );
			}
		}

		if ( $dry ) {
			$verb = $quarantine ? 'Would quarantine' : 'Would remove';
		} else {
			$verb = $quarantine ? 'Quarantined' : 'Removed';
		}
		WP_CLI::success(
			"{$verb} {$total_files} file(s) and {$total_dirs} director(y/ies) (engine-first order)."
		);
		WP_CLI::warning( 'Drop-in removal (object-cache.php / advanced-cache.php / db.php) also drops legitimate cache/db drop-ins; reinstall Object Cache Pro / Redis / Query Monitor db.php etc. if needed.' );
	}

	/**
	 * Resolve this run's quarantine directory (…/ambulance-quarantine/{stamp}/).
	 *
	 * @param array $assoc_args Assoc args.
	 * @return string Absolute path without trailing slash.
	 */
	protected function resolve_quarantine_run_dir( $assoc_args ) {
		if ( ! empty( $assoc_args['quarantine-dir'] ) ) {
			return rtrim( (string) $assoc_args['quarantine-dir'], '/\\' );
		}
		return dirname( untrailingslashit( ABSPATH ) ) . '/ambulance-quarantine/' . gmdate( 'Ymd-His' );
	}

	/**
	 * Durable first-copy root sibling to the run dir (…/ambulance-quarantine/first/).
	 *
	 * @param string $run_dir Run quarantine directory.
	 * @return string
	 */
	protected function quarantine_first_root( $run_dir ) {
		return dirname( $run_dir ) . '/first';
	}

	/**
	 * Relative key used under quarantine (prefer path under WP_CONTENT_DIR).
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	protected function quarantine_rel_key( $path ) {
		$rel = $this->relative_to_content( $path );
		if ( $rel !== $path && '' !== $rel ) {
			return 'wp-content/' . ltrim( $rel, '/' );
		}
		$abs = wp_normalize_path( untrailingslashit( ABSPATH ) );
		$norm = wp_normalize_path( $path );
		if ( 0 === strpos( $norm, $abs . '/' ) ) {
			return ltrim( substr( $norm, strlen( $abs ) ), '/' );
		}
		return 'outside/' . basename( $path );
	}

	/**
	 * Split targets into engine (reinfector + drop-ins) then remaining payload/decoys.
	 *
	 * @param string[] $files File paths.
	 * @param string[] $dirs  Dir paths.
	 * @return array<int,array{title:string,files:string[],dirs:string[]}>
	 */
	protected function partition_engine_first( $files, $dirs ) {
		$engine_files = array();
		$rest_files   = array();
		foreach ( $files as $path ) {
			if ( $this->is_engine_file_path( $path ) ) {
				$engine_files[] = $path;
			} else {
				$rest_files[] = $path;
			}
		}

		$engine_dirs = array();
		$rest_dirs   = array();
		foreach ( $dirs as $path ) {
			if ( $this->is_engine_dir_path( $path ) ) {
				$engine_dirs[] = $path;
			} else {
				$rest_dirs[] = $path;
			}
		}

		return array(
			array(
				'title' => 'Phase 1 — engine (reinfector + drop-ins)',
				'files' => $engine_files,
				'dirs'  => $engine_dirs,
			),
			array(
				'title' => 'Phase 2 — payload / decoys / husks',
				'files' => $rest_files,
				'dirs'  => $rest_dirs,
			),
		);
	}

	/**
	 * @param string $path Absolute file path.
	 */
	protected function is_engine_file_path( $path ) {
		$name = strtolower( basename( $path ) );
		$rel  = strtolower( $this->relative_to_content( $path ) );

		if ( in_array( $name, array( 'object-cache.php', 'advanced-cache.php', 'db.php', '.user.ini', 'user.ini' ), true ) ) {
			// Root drop-ins / prepend only (not nested copies).
			if ( false === strpos( $rel, '/' ) ) {
				return true;
			}
		}
		// Passwordless admin-session gates — remove before payload/decoy sweep.
		if ( in_array( $name, array( 'admin-helper.php', 'boot-loader.php' ), true ) ) {
			return true;
		}
		if ( $this->is_echo_updater_name( $name ) || $this->is_trace_wrapper_bit_name( $name ) || $this->is_host_helper_implant_name( $name ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @param string $path Absolute dir path.
	 */
	protected function is_engine_dir_path( $path ) {
		$name = strtolower( basename( $path ) );
		return in_array( $name, array( 'echo-updater-x', 'trace-wrapper-bit', 'wp-file-manager', 'link-factory' ), true );
	}

	/**
	 * @param string[] $files  Paths.
	 * @param bool     $dry    Dry-run.
	 * @param string   $q_run  Quarantine run dir, or empty to delete.
	 * @return int Count acted on.
	 */
	protected function purge_file_list( $files, $dry, $q_run = '' ) {
		$count = 0;
		foreach ( $files as $path ) {
			if ( ! is_file( $path ) ) {
				continue;
			}
			if ( $q_run ) {
				WP_CLI::log( ( $dry ? '[dry-run] would quarantine: ' : 'Quarantining: ' ) . $path );
				if ( ! $dry && ! $this->quarantine_path( $path, $q_run ) ) {
					WP_CLI::warning( 'Failed to quarantine: ' . $path );
					continue;
				}
			} else {
				WP_CLI::log( ( $dry ? '[dry-run] would delete: ' : 'Deleting: ' ) . $path );
				if ( ! $dry && ! $this->delete_path( $path ) ) {
					WP_CLI::warning( 'Failed to delete: ' . $path );
					continue;
				}
			}
			++$count;
		}
		return $count;
	}

	/**
	 * @param string[] $dirs  Paths.
	 * @param bool     $dry   Dry-run.
	 * @param string   $q_run Quarantine run dir, or empty to delete.
	 * @return int Count acted on.
	 */
	protected function purge_dir_list( $dirs, $dry, $q_run = '' ) {
		$count = 0;
		foreach ( $dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			if ( $q_run ) {
				WP_CLI::log( ( $dry ? '[dry-run] would quarantine tree: ' : 'Quarantining tree: ' ) . $dir );
				if ( ! $dry && ! $this->quarantine_path( $dir, $q_run ) ) {
					WP_CLI::warning( 'Failed to quarantine: ' . $dir );
					continue;
				}
			} else {
				WP_CLI::log( ( $dry ? '[dry-run] would remove tree: ' : 'Removing tree: ' ) . $dir );
				if ( ! $dry && ! $this->delete_tree( $dir ) ) {
					WP_CLI::warning( 'Failed to remove: ' . $dir );
					continue;
				}
			}
			++$count;
		}
		return $count;
	}

	/**
	 * Move a file or directory into quarantine: durable first copy + newest run copy.
	 *
	 * @param string $path  Absolute path still under the site.
	 * @param string $q_run Quarantine run directory.
	 * @return bool
	 */
	protected function quarantine_path( $path, $q_run ) {
		if ( ! is_file( $path ) && ! is_dir( $path ) ) {
			return false;
		}

		$rel   = $this->quarantine_rel_key( $path );
		$first = $this->quarantine_first_root( $q_run ) . '/' . $rel;
		$dest  = $q_run . '/' . $rel;

		if ( ! is_file( $first ) && ! is_dir( $first ) ) {
			if ( ! $this->copy_path_preserve( $path, $first ) ) {
				return false;
			}
			@chmod( dirname( $first ), 0700 );
		}

		if ( is_file( $dest ) || is_dir( $dest ) ) {
			if ( is_dir( $dest ) ) {
				$this->delete_tree( $dest );
			} else {
				@unlink( $dest );
			}
		}

		if ( ! $this->move_path( $path, $dest ) ) {
			return false;
		}
		@chmod( dirname( $dest ), 0700 );
		return true;
	}

	/**
	 * Copy file or directory tree to $dest (parents created).
	 *
	 * @param string $src  Source.
	 * @param string $dest Destination.
	 * @return bool
	 */
	protected function copy_path_preserve( $src, $dest ) {
		$parent = dirname( $dest );
		if ( ! is_dir( $parent ) && ! wp_mkdir_p( $parent ) ) {
			return false;
		}
		if ( is_file( $src ) ) {
			return @copy( $src, $dest );
		}
		if ( ! is_dir( $src ) ) {
			return false;
		}
		if ( ! is_dir( $dest ) && ! wp_mkdir_p( $dest ) ) {
			return false;
		}
		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $src, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			return false;
		}
		foreach ( $iterator as $item ) {
			$target = $dest . '/' . $iterator->getSubPathName();
			if ( $item->isDir() ) {
				if ( ! is_dir( $target ) && ! wp_mkdir_p( $target ) ) {
					return false;
				}
			} elseif ( ! @copy( $item->getPathname(), $target ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Move file or directory (rename, else copy+delete).
	 *
	 * @param string $src  Source.
	 * @param string $dest Destination.
	 * @return bool
	 */
	protected function move_path( $src, $dest ) {
		$parent = dirname( $dest );
		if ( ! is_dir( $parent ) && ! wp_mkdir_p( $parent ) ) {
			return false;
		}
		if ( @rename( $src, $dest ) ) {
			return true;
		}
		if ( ! $this->copy_path_preserve( $src, $dest ) ) {
			return false;
		}
		if ( is_dir( $src ) ) {
			return $this->delete_tree( $src );
		}
		return $this->delete_path( $src );
	}

	/**
	 * Absolute file paths to delete (unique, sorted).
	 *
	 * @return string[]
	 */
	protected function collect_file_targets() {
		$root = WP_CONTENT_DIR;
		$hits = array();

		foreach ( self::$fixed_content_files as $rel ) {
			$path = $root . '/' . $rel;
			if ( is_file( $path ) ) {
				$hits[ $path ] = true;
			}
		}

		foreach ( self::$wp_helper_uid_fixed_rels as $rel ) {
			$path = $root . '/' . $rel;
			if ( is_file( $path ) && $this->is_wp_helper_uid_sample( $path ) ) {
				$hits[ $path ] = true;
			}
		}

		$want = array_fill_keys(
			array_map( 'strtolower', self::$malicious_basenames ),
			true
		);
		$helper_uid_names = array_fill_keys(
			array_map( 'strtolower', self::$wp_helper_uid_candidate_basenames ),
			true
		);
		$decoys = array_fill_keys(
			array_map( 'strtolower', self::$decoy_mu_plugin_basenames ),
			true
		);
		$allow = array_fill_keys(
			array_map( 'strtolower', self::$mu_plugin_allowlist ),
			true
		);

		$mu_root = wp_normalize_path( WP_CONTENT_DIR . '/mu-plugins' );

		if ( ! is_dir( $root ) ) {
			return array_keys( $hits );
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
			);
		} catch ( UnexpectedValueException $e ) {
			WP_CLI::warning( 'Could not walk ' . $root . ': ' . $e->getMessage() );
			return array_keys( $hits );
		}

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			$path = $file->getPathname();
			if ( $this->should_skip_path( $path ) ) {
				continue;
			}

			$name     = $file->getFilename();
			$low      = strtolower( $name );
			$norm     = wp_normalize_path( $path );
			$in_mu    = ( 0 === strpos( $norm, $mu_root . '/' ) || $norm === $mu_root );
			$allowed  = isset( $allow[ $low ] );

			if ( isset( $want[ $low ] ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( isset( $helper_uid_names[ $low ] ) && $this->is_wp_helper_uid_sample( $path ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( $this->is_trace_wrapper_bit_name( $name ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( $this->is_echo_updater_name( $name ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( $this->is_host_helper_implant_name( $name ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( isset( $decoys[ $low ] ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( $this->is_purgeable_staging_artifact( $name, $this->relative_to_content( $path ) ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( 0 === strpos( $name, '.' ) ) {
				$hits[ $path ] = true;
				continue;
			}
			if ( $in_mu && ! $allowed ) {
				if ( 0 === (int) $file->getSize() ) {
					$hits[ $path ] = true;
					continue;
				}
				if ( 0 === strpos( $low, 'sc_' ) ) {
					$hits[ $path ] = true;
					continue;
				}
				// Three-word hyphen decoys: file-handler-jet.php (not installatron allowlist).
				if ( preg_match( '/^[a-z]+-[a-z]+-[a-z]+\.php$/', $low ) ) {
					$hits[ $path ] = true;
				}
			}
		}

		$paths = array_keys( $hits );
		sort( $paths );
		return $paths;
	}

	/**
	 * Basenames belonging to the trace-wrapper-bit implant family.
	 *
	 * @param string $name Basename.
	 */
	protected function is_trace_wrapper_bit_name( $name ) {
		$low = strtolower( $name );
		return 'trace-wrapper-bit' === $low
			|| 'trace-wrapper-bit.php' === $low
			|| 0 === strpos( $low, 'trace-wrapper-bit.' );
	}

	/**
	 * Basenames belonging to the echo-updater-x reinfector family.
	 *
	 * @param string $name Basename.
	 */
	protected function is_echo_updater_name( $name ) {
		$low = strtolower( $name );
		if ( 'echo-updater-x' === $low || 'echo-updater-x.php' === $low ) {
			return true;
		}
		if ( 0 === strpos( $low, 'echo-updater-x.' ) ) {
			return true;
		}
		// State markers like .bt_echo-updater-x (also caught as hidden files).
		return (bool) preg_match( '/(^|[._-])echo-updater-x([._-]|$)/', $low );
	}

	/**
	 * Absolute directory trees to remove (deepest first).
	 *
	 * @return string[]
	 */
	protected function collect_dir_targets() {
		$root  = WP_CONTENT_DIR;
		$found = array();

		foreach ( self::$fixed_content_dirs as $rel ) {
			$path = $root . '/' . $rel;
			if ( is_dir( $path ) ) {
				$found[ $path ] = true;
			}
		}

		// Implant / entry-vector folders anywhere under wp-content.
		foreach ( array( 'trace-wrapper-bit', 'echo-updater-x', 'wp-file-manager', 'link-factory', 'content-sync-helper', 'advanced-linkflow-control', 'wp-security-helper', 'system-control', 'mailpoet-652' ) as $dirname ) {
			foreach ( $this->find_named_dirs( $root, $dirname ) as $dir ) {
				$found[ $dir ] = true;
			}
		}

		// Non-hidden sc_* dirs under mu-plugins (decoy swarm).
		$mu = $root . '/mu-plugins';
		if ( is_dir( $mu ) ) {
			foreach ( glob( $mu . '/sc_*', GLOB_ONLYDIR ) ?: array() as $dir ) {
				if ( ! $this->should_skip_path( $dir ) ) {
					$found[ $dir ] = true;
				}
			}
		}

		foreach ( $this->find_uploads_thumbnails_dirs() as $dir ) {
			$found[ $dir ] = true;
		}

		foreach ( $this->find_custom_file_theme_dirs( $root ) as $dir ) {
			$found[ $dir ] = true;
		}

		foreach ( $this->find_security_timestamp_plugin_dirs( $root ) as $dir ) {
			$found[ $dir ] = true;
		}

		foreach ( $this->find_hidden_dirs( $root ) as $dir ) {
			$found[ $dir ] = true;
		}

		$paths = array_keys( $found );
		usort(
			$paths,
			static function ( $a, $b ) {
				return substr_count( $b, DIRECTORY_SEPARATOR ) - substr_count( $a, DIRECTORY_SEPARATOR );
			}
		);

		return $paths;
	}

	/**
	 * themes/custom-file-* directories (file-manager entry-vector drops).
	 *
	 * @param string $root Absolute wp-content root.
	 * @return string[]
	 */
	protected function find_custom_file_theme_dirs( $root ) {
		$themes = $root . '/themes';
		$found  = array();

		if ( ! is_dir( $themes ) ) {
			return $found;
		}

		$entries = @scandir( $themes );
		if ( ! is_array( $entries ) ) {
			return $found;
		}

		foreach ( $entries as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			if ( ! $this->is_custom_file_drop_dirname( $name ) ) {
				continue;
			}
			$path = $themes . '/' . $name;
			if ( is_dir( $path ) && ! $this->should_skip_path( $path ) ) {
				$found[] = $path;
			}
		}

		return $found;
	}

	/**
	 * plugins/security_<digits> directories (e.g. security_1787155594).
	 *
	 * @param string $root Absolute wp-content root.
	 * @return string[]
	 */
	protected function find_security_timestamp_plugin_dirs( $root ) {
		$plugins = $root . '/plugins';
		$found   = array();

		if ( ! is_dir( $plugins ) ) {
			return $found;
		}

		$entries = @scandir( $plugins );
		if ( ! is_array( $entries ) ) {
			return $found;
		}

		foreach ( $entries as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			if ( ! $this->is_security_timestamp_plugin_dirname( $name ) ) {
				continue;
			}
			$path = $plugins . '/' . $name;
			if ( is_dir( $path ) && ! $this->should_skip_path( $path ) ) {
				$found[] = $path;
			}
		}

		return $found;
	}

	/**
	 * Directories under $root with an exact basename match (case-insensitive).
	 *
	 * @param string $root Absolute root.
	 * @param string $basename Directory basename to find.
	 * @return string[]
	 */
	protected function find_named_dirs( $root, $basename ) {
		$found = array();
		$want  = strtolower( $basename );

		if ( ! is_dir( $root ) ) {
			return $found;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			WP_CLI::warning( 'Could not walk ' . $root . ' for ' . $basename . ': ' . $e->getMessage() );
			return $found;
		}

		foreach ( $iterator as $item ) {
			if ( ! $item->isDir() ) {
				continue;
			}
			$path = $item->getPathname();
			if ( $this->should_skip_path( $path ) ) {
				continue;
			}
			if ( strtolower( $item->getFilename() ) === $want ) {
				$found[] = $path;
			}
		}

		return $found;
	}

	/**
	 * Directories under $root whose basename starts with `.`.
	 *
	 * @param string $root Absolute root.
	 * @return string[]
	 */
	protected function find_hidden_dirs( $root ) {
		$found = array();

		if ( ! is_dir( $root ) ) {
			return $found;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			WP_CLI::warning( 'Could not walk ' . $root . ' for hidden dirs: ' . $e->getMessage() );
			return $found;
		}

		foreach ( $iterator as $item ) {
			if ( ! $item->isDir() ) {
				continue;
			}
			$path = $item->getPathname();
			if ( $this->should_skip_path( $path ) ) {
				continue;
			}
			if ( 0 === strpos( $item->getFilename(), '.' ) ) {
				$found[] = $path;
			}
		}

		return $found;
	}

	/**
	 * Every directory named .thumbnails under the uploads basedir.
	 *
	 * @return string[] Absolute paths.
	 */
	protected function find_uploads_thumbnails_dirs() {
		$upload = wp_upload_dir( null, false );
		$base   = isset( $upload['basedir'] ) ? $upload['basedir'] : '';
		$found  = array();

		if ( ! $base || ! is_dir( $base ) ) {
			return $found;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			WP_CLI::warning( 'Could not walk uploads: ' . $e->getMessage() );
			return $found;
		}

		foreach ( $iterator as $item ) {
			if ( ! $item->isDir() ) {
				continue;
			}
			if ( '.thumbnails' === $item->getFilename() ) {
				$found[] = $item->getPathname();
			}
		}

		return $found;
	}

	/**
	 * @param string $path File path.
	 */
	protected function delete_path( $path ) {
		if ( ! is_file( $path ) ) {
			return false;
		}
		return @unlink( $path );
	}

	/**
	 * Recursively delete a directory tree.
	 *
	 * @param string $dir Directory path.
	 */
	protected function delete_tree( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return false;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			return false;
		}

		foreach ( $iterator as $item ) {
			$path = $item->getPathname();
			if ( $item->isDir() ) {
				if ( ! @rmdir( $path ) ) {
					return false;
				}
			} elseif ( ! @unlink( $path ) ) {
				return false;
			}
		}

		return @rmdir( $dir );
	}
}
