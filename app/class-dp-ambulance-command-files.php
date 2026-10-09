<?php
/**
 * ambulance files
 *
 * Filesystem scanner + path classifiers shared by dropins / heuristics / purge-files.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scan wp-content for implant fingerprints, unexpected PHP, and double extensions.
 *
 * Also owns path-classification helpers used by purge-files (hex drops, helpers, etc.).
 */
class DP_Ambulance_Command_Files extends DP_Ambulance_Command {

	/**
	 * Unique content fingerprints from the analyzed sample.
	 *
	 * @var string[]
	 */
	public static $content_needles = array(
		'Vista Connector Box',
		'Amelia Baker',
		'vista-connector-box',
		'trace-wrapper-bit',
		'ervbi3da9bn0jg',
		'isc8j1ddluwftunz',
		'__SC_BOOT',
		'__SC_ENC',
		'data-sc-',
		'SC_ADV_BEGIN',
		'SC_ADV_END',
		'SC_DB_BEGIN',
		'SC_DB_END',
		'SC_TH_BEGIN',
		'SC_TH_END',
		'SC_ADV_LOADED',
		'SC_DB_LOADED',
		'SC_ADVL_',
		'SC_DBL_',
		'SC_THL_',
		'SC_CORE_BOOT',
		// wp-config cache/temp lines from SC403 live-containment writeups.
		'SC_WC',
		'SC_WC_BEGIN',
		'SC_WC_END',
		'SCOCV',
		'SCV:4.5.3',
		'_sc_fpc',
		'__scf_',
		'retadpu-ohce',
		'echo-updater-x',
		'wp-object-cache-',
		'may contain artifacts of previous malicious infection',
		'Vapor Extension Tag',
		'Logan Roberts',
		'Block for Chrome version',
		'_SC_elFinderConnector_Real',
		'sc_fm_filter',
		'0x9A4752cAA1C15868487A0ACb691F81bfA901E063',
		'0x839d1cE5c3F259e8d3D17114d7186EDabdbeA94b',
		'0x6d2c5435EF70196740a48904B69377935D50abBB',
		'0x3bc5de30',
		'https://0xrpc.io/eth',
		'PA|lPpf',
		// cg-restore / cron-helper host implant (infected wp-config + _wp_cg_*_fs options).
		'cg-restore-652',
		'_wp_cg_652_fs',
		'cron-helper-652',
		'db-helper',
		'maintenance-helper',
		'_T_WCB',
		'_T_WCC',
		'php-cache-652',
		// Content Sync Helper / PBN-LINKS injector (hide-self + ticker/v1 REST).
		'inj_sync_mu_plugin_copy',
		'inj_registry_reveal_gate',
		'wp_plugin_registry_adjust_bump',
		'wp_plugin_registry_adjust_bind',
		'INJ_SYNC_HELPER_BOOTSTRAP',
		'Content_Sync_Helper',
		'PBN-LINKS',
		'PBN-LINKS-START',
		'content_sync_helper_footer_links',
		'_ticker_slot_html',
		'_ticker_slot_position',
		'ticker/v1',
		'https://wpninjas.ch/plugins/content-sync-helper/',
		'WpDevNinjas Team',
		// Advanced LinkFlow Control (hide-self / all_plugins unset + ?sp= visibility gate).
		'Advanced LinkFlow Control',
		'advanced-linkflow-control.php',
		'Advanced_LinkFlow_Control',
		"array_key_exists('sp', \$_REQUEST)",
		// WP Security Helper (higher-confidence fake plugin identity).
		'WP Security Helper',
		'wp-security-helper.php',
		'WP_Security_Helper',
		// sc-loader.php restores plugins/system-control from .sc-backup/system-control.
		'sc-loader.php',
		'.sc-backup/system-control',
		'system-control/system-control.php',
		'plugins/system-control',
		// Compact Extension Vox / menu-queue-bit MU decoy.
		'Compact Extension Vox',
		'menu-queue-bit.php',
		'_ofdyhs',
		// wp_helper_uid dual admin-session backdoor (admin-helper.php + boot-loader.php).
		'wp_helper_uid',
		'admin-helper.php',
		'boot-loader.php',
		'Widget cache bootstrap, ver b2ccbcd25e',
		'Runtime dependencies bootstrap 9b66554fd3',
		'wp_179e4b',
		'wp_4bb239',
		'wp_4960ab',
		// Withheld gate values appear only as these SHA-256 digests in recovered samples.
		'8e753f173a5c428fe6c44646cddb0da04952628bcd098400d6fe9fcd3f3bb435',
		'b6efe58fb91fb0bb9d11fce3b6eb42bcc1b8822deacc39facc657d17cffb1bf5',
	);

	/**
	 * Exact SHA-256 of recovered wp_helper_uid samples (MD Pabel research, 2026-08-30).
	 *
	 * @var array<string,string> hash => sample label
	 */
	public static $wp_helper_uid_file_hashes = array(
		'4bbeaed0845bcd965c92902a1dfb314d4afd79e48029dc22bf5fa7597a0d93cb' => 'admin-helper.php',
		'0cbe6a757abcfe7c8968ae169929164d978f120847c05ca91f5e09c44293c4f3' => 'boot-loader.php',
	);

	/**
	 * SHA-256 digests of withheld gate secrets (literal hex strings embedded in samples).
	 *
	 * @var array<string,string> hash => gate role
	 */
	public static $wp_helper_uid_gate_hashes = array(
		'8e753f173a5c428fe6c44646cddb0da04952628bcd098400d6fe9fcd3f3bb435' => 'direct-endpoint gate',
		'b6efe58fb91fb0bb9d11fce3b6eb42bcc1b8822deacc39facc657d17cffb1bf5' => 'MU-plugin gate',
	);

	/**
	 * Inert clustering probes from the direct endpoint (all three together = high confidence).
	 *
	 * @var string[]
	 */
	public static $wp_helper_uid_cluster_probes = array(
		'wp_179e4b',
		'wp_4bb239',
		'wp_4960ab',
	);

	/**
	 * Strong content markers for the wp_helper_uid pair (not filenames alone).
	 *
	 * @var string[]
	 */
	public static $wp_helper_uid_strong_needles = array(
		'Widget cache bootstrap, ver b2ccbcd25e',
		'Runtime dependencies bootstrap 9b66554fd3',
		'wp_helper_uid',
	);

	/**
	 * .htaccess UA-cloak / implant markers (SC/SCOCV).
	 *
	 * @var string[]
	 */
	public static $htaccess_cloak_regexes = array(
		'/#KH[0-9]+YS/',
		'/Block for Chrome version/i',
	);

	/**
	 * Fake Plugin Name headers used by this family.
	 *
	 * @var string[]
	 */
	public static $fake_plugin_names = array(
		'Vista Connector Box',
		'Connector Box',
		'Asset management',
		'Vapor Extension Tag',
		'Echo Updater',
		'Content Sync Helper',
		'Advanced LinkFlow Control',
		'WP Security Helper',
		'Compact Extension Vox',
	);

	/**
	 * Scan wp-content for implant fingerprints, unexpected PHP, and double extensions.
	 *
	 * ## OPTIONS
	 *
	 * [--since=<when>]
	 * : Only files whose ctime is newer than this. Examples: 24h, 7d, "2026-10-01".
	 *
	 * [--fingerprint-only]
	 * : Skip generic heuristics (webshell strings / double extensions).
	 *
	 * [--format=<format>]
	 * : table, csv, json, json_pretty, or count. Default: table.
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		unset( $args );
		$root   = WP_CONTENT_DIR;
		$since  = $this->parse_since( $assoc_args );
		$found  = $this->collect_file_findings( $root, $since );

		WP_CLI::log( '== Files under ' . $root . ( $since ? ' (ctime >= ' . gmdate( 'c', $since ) . ')' : '' ) . ' ==' );

		$rows = array_merge( $found['hits'], $found['php_upload'] );
		if ( empty( $assoc_args['fingerprint-only'] ) ) {
			$rows = array_merge( $rows, $found['heuristics'], $found['double_ext'] );
		}

		if ( ! $rows ) {
			WP_CLI::success( 'No file hits.' . ( $found['skipped'] ? " Skipped {$found['skipped']} paths." : '' ) );
			return;
		}

		$this->output_rows( $rows, array( 'file', 'note', 'hits' ), $assoc_args );
		WP_CLI::warning(
			count( $found['hits'] ) . ' fingerprint file(s), '
			. count( $found['php_upload'] ) . ' unexpected PHP path(s), '
			. count( $found['heuristics'] ) . ' heuristic file(s), '
			. count( $found['double_ext'] ) . ' double-extension file(s). Skipped '
			. $found['skipped'] . '.'
		);
	}

	/**
	 * True when $path matches a recovered wp_helper_uid sample (hash or strong markers).
	 *
	 * Filenames alone are not enough — legitimate code can reuse admin-helper.php / boot-loader.php.
	 *
	 * @param string      $path     Absolute path.
	 * @param string|null $contents Optional preloaded contents.
	 * @return bool
	 */
	protected function is_wp_helper_uid_sample( $path, $contents = null ) {
		if ( ! is_file( $path ) ) {
			return false;
		}

		$hash = @hash_file( 'sha256', $path );
		if ( is_string( $hash ) && isset( self::$wp_helper_uid_file_hashes[ $hash ] ) ) {
			return true;
		}

		if ( null === $contents ) {
			$contents = @file_get_contents( $path );
		}
		if ( ! is_string( $contents ) || '' === $contents ) {
			return false;
		}

		foreach ( self::$wp_helper_uid_strong_needles as $needle ) {
			if ( false !== strpos( $contents, $needle ) ) {
				return true;
			}
		}

		foreach ( self::$wp_helper_uid_gate_hashes as $gate_hash => $_role ) {
			if ( false !== strpos( $contents, $gate_hash ) ) {
				return true;
			}
		}

		// Clustering probes from the direct endpoint (all three together = high confidence).
		$probes = 0;
		foreach ( self::$wp_helper_uid_cluster_probes as $probe ) {
			if ( false !== strpos( $contents, $probe ) ) {
				++$probes;
			}
		}
		return $probes >= count( self::$wp_helper_uid_cluster_probes );
	}

	/**
	 * @param string $path Absolute path.
	 * @return string[]
	 */
	protected function scan_file_for_needles( $path ) {
		$contents = @file_get_contents( $path );
		if ( false === $contents || '' === $contents ) {
			return array();
		}

		$found = array();
		foreach ( self::$content_needles as $needle ) {
			if ( false !== strpos( $contents, $needle ) ) {
				$found[] = $needle;
			}
		}

		$basename = basename( $path );
		if ( '.user.ini' === $basename || 'user.ini' === $basename || $this->file_mentions_auto_prepend( $path, $contents ) ) {
			if ( $this->file_mentions_auto_prepend( $path, $contents ) && ! in_array( 'auto_prepend_file', $found, true ) ) {
				$found[] = 'auto_prepend_file';
			}
		}

		return $found;
	}

	/**
	 * @param string      $path     Path.
	 * @param string|null $contents Optional contents.
	 */
	protected function file_mentions_auto_prepend( $path, $contents = null ) {
		$name = basename( $path );
		if ( ! in_array( $name, array( '.htaccess', '.user.ini', 'user.ini' ), true ) && ! preg_match( '/\.ini$/', $name ) ) {
			return false;
		}
		if ( null === $contents ) {
			$contents = @file_get_contents( $path );
		}
		return is_string( $contents ) && false !== strpos( $contents, 'auto_prepend_file' );
	}

	/**
	 * @param string $rel Path relative to wp-content.
	 */
	protected function is_unexpected_php_location( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', $rel ), '/' );
		if ( 0 === strpos( $rel, 'uploads/' ) ) {
			return true;
		}
		if ( 0 === strpos( $rel, 'cache/' ) ) {
			return true;
		}
		if ( 0 === strpos( $rel, 'upgrade/' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * File-manager dropped theme dirs like custom-file-4-1787062890.
	 *
	 * @param string $name Basename.
	 * @return bool
	 */
	protected function is_custom_file_drop_dirname( $name ) {
		return (bool) preg_match( '/^custom-file-/i', $name );
	}

	/**
	 * Timestamped fake plugin dirs like security_1787155594.
	 *
	 * @param string $name Basename.
	 * @return bool
	 */
	protected function is_security_timestamp_plugin_dirname( $name ) {
		return (bool) preg_match( '/^security_\d+$/i', $name );
	}

	/**
	 * Host helper reinfectors (e.g. cron-helper-652.php, db-helper-*.php, maintenance-helper-*.php).
	 *
	 * @param string $name Basename.
	 * @return bool
	 */
	protected function is_host_helper_implant_name( $name ) {
		foreach ( array( 'cron-helper', 'db-helper', 'maintenance-helper' ) as $needle ) {
			if ( false !== stripos( $name, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $name Basename.
	 * @return bool
	 */
	protected function is_cron_helper_name( $name ) {
		return $this->is_host_helper_implant_name( $name );
	}

	/**
	 * Whether $rel is a file directly under wp-content (no subdirectory).
	 *
	 * @param string $rel Path relative to wp-content.
	 * @return bool
	 */
	protected function is_content_root_rel( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', $rel ), '/' );
		return '' === $rel || false === strpos( $rel, '/' );
	}

	/**
	 * 8-char hex basename used as malware staging archives (e.g. 01e76646.zip, c76e59a3.zip).
	 *
	 * @param string $name Basename.
	 * @return bool
	 */
	protected function is_hex_named_staging_zip( $name ) {
		return (bool) preg_match( '/^[a-f0-9]{8}\.zip$/i', $name );
	}

	/**
	 * 8-char hex PHP drop (e.g. 9dd16321.php).
	 *
	 * @param string $name Basename.
	 * @return bool
	 */
	protected function is_hex_named_drop_php( $name ) {
		return (bool) preg_match( '/^[a-f0-9]{8}\.php$/i', $name );
	}

	/**
	 * Zips safe to auto-purge: any .zip at wp-content root, or hex-named staging zips anywhere.
	 *
	 * @param string $name Basename.
	 * @param string $rel  Path relative to wp-content.
	 * @return bool
	 */
	protected function is_purgeable_zip( $name, $rel ) {
		if ( ! preg_match( '/\.zip$/i', $name ) ) {
			return false;
		}
		if ( $this->is_content_root_rel( $rel ) ) {
			return true;
		}
		return $this->is_hex_named_staging_zip( $name );
	}

	/**
	 * Staging drops safe to auto-purge:
	 * - every .php and .zip directly in wp-content/ (including index.php / drop-ins)
	 * - hex-named staging zips anywhere
	 * - hex-named drop PHP anywhere
	 *
	 * @param string $name Basename.
	 * @param string $rel  Path relative to wp-content.
	 * @return bool
	 */
	protected function is_purgeable_staging_artifact( $name, $rel ) {
		if ( $this->is_content_root_rel( $rel ) && preg_match( '/\.(?:php|zip)$/i', $name ) ) {
			return true;
		}
		if ( $this->is_hex_named_staging_zip( $name ) ) {
			return true;
		}
		return $this->is_hex_named_drop_php( $name );
	}

	/**
	 * @param string $file Plugin file.
	 */
	protected function plugin_header_name( $file ) {
		$data = get_file_data(
			$file,
			array(
				'Name' => 'Plugin Name',
			)
		);
		return isset( $data['Name'] ) ? $data['Name'] : '';
	}

	/**
	 * @param string $name Plugin Name header.
	 */
	protected function is_fake_plugin_name( $name ) {
		foreach ( self::$fake_plugin_names as $needle ) {
			if ( false !== stripos( $name, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Filename / path persistence used after scanners empty the PHP.
	 *
	 * @param string $filename Basename.
	 * @param string $rel      Path relative to wp-content.
	 * @param int    $size     File size, or 0 for directories.
	 * @param bool   $is_dir   Whether this is a directory.
	 * @return string Note, or empty if no match.
	 */
	protected function persistence_path_note( $filename, $rel, $size, $is_dir = false ) {
		$rel  = ltrim( str_replace( '\\', '/', $rel ), '/' );
		$name = $filename;

		if ( $is_dir ) {
			if ( 0 === strpos( $name, '.sc_' ) ) {
				return 'hidden .sc_* payload dir';
			}
			if ( '.sc-backup' === $name || 0 === strpos( $rel, '.sc-backup/' ) ) {
				return '.sc-backup restore staging (sc-loader)';
			}
			if ( 'echo-updater-x' === strtolower( $name ) ) {
				return 'echo-updater-x directory';
			}
			if ( $this->is_custom_file_drop_dirname( $name ) && 0 === strpos( $rel, 'themes/' ) ) {
				return 'custom-file-* theme drop (file-manager?)';
			}
			if ( $this->is_security_timestamp_plugin_dirname( $name ) && 0 === strpos( $rel, 'plugins/' ) ) {
				return 'security_<timestamp> plugin drop';
			}
			if ( 'content-sync-helper' === strtolower( $name ) ) {
				return 'content-sync-helper PBN injector';
			}
			if ( 'advanced-linkflow-control' === strtolower( $name ) ) {
				return 'advanced-linkflow-control injector';
			}
			if ( 'wp-security-helper' === strtolower( $name ) ) {
				return 'wp-security-helper fake plugin';
			}
			if ( 'system-control' === strtolower( $name ) ) {
				return 'system-control (sc-loader destination/backup)';
			}
			return '';
		}

		if ( false !== strpos( '/' . $rel, '/.sc_' ) ) {
			return 'file under .sc_* dir';
		}
		if ( false !== strpos( '/' . $rel, '/.sc-backup/' ) || 0 === strpos( $rel, '.sc-backup/' ) ) {
			return 'file under .sc-backup (sc-loader staging)';
		}
		if ( false !== stripos( $name, 'echo-updater-x' ) ) {
			return 'echo-updater-x artifact';
		}
		if ( $this->is_host_helper_implant_name( $name ) ) {
			$low = strtolower( $name );
			if ( false !== strpos( $low, 'db-helper' ) ) {
				return 'db-helper host implant';
			}
			if ( false !== strpos( $low, 'maintenance-helper' ) ) {
				return 'maintenance-helper host implant';
			}
			return 'cron-helper host implant';
		}
		if ( 'custom-constants-652.php' === strtolower( $name ) ) {
			return 'cg-restore companion mu-plugin';
		}
		if ( 'ridge-backup-mod.php' === strtolower( $name ) ) {
			return 'ridge-backup-mod decoy mu-plugin';
		}
		if ( 'menu-queue-bit.php' === strtolower( $name ) ) {
			return 'menu-queue-bit decoy mu-plugin (Compact Extension Vox)';
		}
		if ( 'content-sync-helper.php' === strtolower( $name ) || 'content-sync-helper' === strtolower( $name ) ) {
			return 'content-sync-helper PBN injector';
		}
		if ( 'advanced-linkflow-control.php' === strtolower( $name ) || 'advanced-linkflow-control' === strtolower( $name ) ) {
			return 'advanced-linkflow-control injector';
		}
		if ( 'wp-security-helper.php' === strtolower( $name ) || 'wp-security-helper' === strtolower( $name ) ) {
			return 'wp-security-helper fake plugin';
		}
		if ( 'sc-loader.php' === strtolower( $name ) ) {
			return 'sc-loader.php (restores system-control from .sc-backup)';
		}
		if ( 'system-control.php' === strtolower( $name ) ) {
			return 'system-control.php (sc-loader payload)';
		}
		if ( 'admin-helper.php' === strtolower( $name ) ) {
			return 'admin-helper.php (wp_helper_uid candidate)';
		}
		if ( 'boot-loader.php' === strtolower( $name ) ) {
			return 'boot-loader.php (wp_helper_uid MU candidate)';
		}
		if ( '__PATH__' === $name ) {
			return '__PATH__ marker';
		}
		if ( preg_match( '/^\.wp-object-cache-/i', $name ) || preg_match( '/\.dat\.lkg$/i', $name ) ) {
			return 'object-cache state file';
		}
		if ( preg_match( '/^\.(gk|kk|g)_/i', $name ) ) {
			return 'implant state marker';
		}
		if ( preg_match( '/\.(off|disabled)$/i', $name ) ) {
			return 'renamed husk (.off/.disabled)';
		}
		if ( $this->is_hex_named_staging_zip( $name ) ) {
			return 'hex-named staging zip';
		}
		if ( $this->is_hex_named_drop_php( $name ) ) {
			return 'hex-named drop PHP';
		}
		if ( $this->is_content_root_rel( $rel ) && preg_match( '/\.(?:php|zip)$/i', $name ) ) {
			// Legitimate silence file; still reported if fingerprints/heuristics match.
			if ( 'index.php' === strtolower( $name ) ) {
				return '';
			}
			return 'wp-content root php/zip';
		}
		if ( preg_match( '/_\d{10}\.(?:php\d*|phtml)$/i', $name ) ) {
			return 'timestamp-named PHP (file-manager drop?)';
		}
		if ( 0 === strpos( $rel, 'mu-plugins/' ) ) {
			if ( 0 === (int) $size ) {
				return 'empty mu-plugin (decoy)';
			}
			if ( 0 === strpos( strtolower( $name ), 'sc_' ) ) {
				return 'sc_* file in mu-plugins';
			}
		}

		return '';
	}

	/**
	 * True when the filename looks like PHP, including double extensions (shell.php.jpg).
	 *
	 * @param string $filename Basename.
	 */
	protected function is_phpish_filename( $filename ) {
		return (bool) preg_match( '/\.(?:php(?:\d+)?|phtml)(?:\.|$)/i', $filename );
	}

	/**
	 * @param \SplFileInfo $file File.
	 */
	protected function should_read_file( $file ) {
		$name = $file->getFilename();
		$ext  = strtolower( $file->getExtension() );
		if ( in_array( $name, array( '.htaccess', '.user.ini', 'user.ini' ), true ) ) {
			return true;
		}
		if ( $this->is_phpish_filename( $name ) ) {
			return true;
		}
		if ( '__PATH__' === $name ) {
			return true;
		}
		return in_array( $ext, array( 'php', 'ini', 'htaccess', 'txt', 'js', 'html', 'htm', 'svg', 'phtml', 'off', 'disabled', 'dat', 'lkg' ), true );
	}

	/**
	 * Generic webshell heuristics. Cheap strings first; regex only after a hit.
	 *
	 * @param string $contents File contents.
	 * @return string[]
	 */
	protected function scan_contents_for_heuristics( $contents ) {
		if ( '' === $contents ) {
			return array();
		}

		$cheap = array();
		foreach ( DP_Ambulance_Command_Heuristics::$heuristic_needles as $needle ) {
			if ( false !== strpos( $contents, $needle ) ) {
				$cheap[] = $needle;
			}
		}

		if ( ! $cheap ) {
			return array();
		}

		$found = array();
		foreach ( $cheap as $needle ) {
			if ( in_array( $needle, DP_Ambulance_Command_Heuristics::$heuristic_always, true ) ) {
				$found[] = $needle;
			}
		}
		if ( count( $cheap ) >= 2 ) {
			$found = array_merge( $found, $cheap );
		}

		foreach ( DP_Ambulance_Command_Heuristics::$heuristic_regexes as $name => $regex ) {
			if ( preg_match( $regex, $contents ) ) {
				$found[] = $name;
			}
		}

		return array_values( array_unique( $found ) );
	}

	/**
	 * Walk a directory and collect implant fingerprints, heuristics, and odd PHP paths.
	 *
	 * @param string $root  Directory to walk.
	 * @param int    $since Unix ctime lower bound, or 0.
	 * @return array{hits:array,php_upload:array,heuristics:array,double_ext:array,skipped:int}
	 */
	protected function collect_file_findings( $root, $since = 0 ) {
		$hits             = array();
		$php_upload       = array();
		$heuristics       = array();
		$double_ext       = array();
		$skipped          = 0;
		$malicious_lookup = array_fill_keys(
			array_map( 'strtolower', DP_Ambulance_Command_Purge_Files::$malicious_basenames ),
			true
		);

		if ( ! is_dir( $root ) ) {
			return compact( 'hits', 'php_upload', 'heuristics', 'double_ext', 'skipped' );
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( UnexpectedValueException $e ) {
			WP_CLI::warning( 'Could not walk ' . $root . ': ' . $e->getMessage() );
			return compact( 'hits', 'php_upload', 'heuristics', 'double_ext', 'skipped' );
		}

		foreach ( $iterator as $file ) {
			$path = $file->getPathname();
			if ( $this->should_skip_path( $path ) ) {
				++$skipped;
				continue;
			}
			if ( $since && filectime( $path ) < $since ) {
				++$skipped;
				continue;
			}

			$rel      = $this->relative_to_content( $path );
			$filename = $file->getFilename();

			if ( $file->isDir() ) {
				$note = $this->persistence_path_note( $filename, $rel, 0, true );
				if ( $note ) {
					$hits[] = array(
						'file' => $path,
						'note' => $note,
						'hits' => $filename,
					);
				}
				continue;
			}

			if ( ! $file->isFile() ) {
				continue;
			}

			$phpish = $this->is_phpish_filename( $filename );
			$size   = (int) $file->getSize();
			$note   = $this->persistence_path_note( $filename, $rel, $size, false );
			if ( $note ) {
				$hits[] = array(
					'file' => $path,
					'note' => $note,
					'hits' => $filename,
				);
			}

			if ( isset( $malicious_lookup[ strtolower( $filename ) ] ) ) {
				$hits[] = array(
					'file' => $path,
					'note' => 'known malicious basename',
					'hits' => $filename,
				);
			}

			if ( $phpish && $this->is_unexpected_php_location( $rel ) ) {
				$php_upload[] = array(
					'file' => $path,
					'note' => 'PHP in uploads/cache (review)',
					'hits' => '',
				);
			}

			if ( $phpish && preg_match( '/\.(?:php(?:\d+)?|phtml)\./i', $filename ) ) {
				$double_ext[] = array(
					'file' => $path,
					'note' => 'PHP double extension',
					'hits' => $filename,
				);
			}

			if ( ! $this->should_read_file( $file ) ) {
				continue;
			}

			if ( $file->getSize() > 8 * 1024 * 1024 ) {
				++$skipped;
				continue;
			}

			$contents = @file_get_contents( $path );
			if ( false === $contents || '' === $contents ) {
				continue;
			}

			$needles = array();
			foreach ( self::$content_needles as $needle ) {
				if ( false !== strpos( $contents, $needle ) ) {
					$needles[] = $needle;
				}
			}
			if ( $this->file_mentions_auto_prepend( $path, $contents ) && ! in_array( 'auto_prepend_file', $needles, true ) ) {
				$needles[] = 'auto_prepend_file';
			}
			foreach ( self::$htaccess_cloak_regexes as $regex ) {
				if ( preg_match( $regex, $contents ) ) {
					$needles[] = 'htaccess-cloak';
					break;
				}
			}
			$hash = @hash_file( 'sha256', $path );
			$hash_hit = ( is_string( $hash ) && isset( self::$wp_helper_uid_file_hashes[ $hash ] ) );
			if ( $needles || $hash_hit ) {
				$note = $hash_hit ? 'wp_helper_uid exact hash' : 'fingerprint';
				if ( $hash_hit && $needles ) {
					$note = 'wp_helper_uid exact hash + fingerprint';
				} elseif ( ! $hash_hit && $this->is_wp_helper_uid_sample( $path, $contents ) ) {
					$note = 'wp_helper_uid markers';
				}
				$hits[] = array(
					'file' => $path,
					'note' => $note,
					'hits' => $needles ? implode( ', ', $needles ) : ( $hash_hit ? $hash : '' ),
				);
			}

			$heuristic = $this->scan_contents_for_heuristics( $contents );
			if ( $heuristic ) {
				$heuristics[] = array(
					'file' => $path,
					'note' => 'heuristic',
					'hits' => implode( ', ', $heuristic ),
				);
			}
		}

		$mu = $root . '/mu-plugins';
		if ( is_dir( $mu ) ) {
			foreach ( glob( $mu . '/*.php' ) ?: array() as $mu_file ) {
				if ( $this->should_skip_path( $mu_file ) ) {
					continue;
				}
				if ( $since && filectime( $mu_file ) < $since ) {
					continue;
				}
				$header = $this->plugin_header_name( $mu_file );
				if ( $header && $this->is_fake_plugin_name( $header ) ) {
					$hits[] = array(
						'file' => $mu_file,
						'note' => 'fake plugin header in mu-plugins',
						'hits' => $header,
					);
				}
			}
		}

		return compact( 'hits', 'php_upload', 'heuristics', 'double_ext', 'skipped' );
	}
}
