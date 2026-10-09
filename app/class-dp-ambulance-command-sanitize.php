<?php
/**
 * ambulance sanitize
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Surgical cleaners: remove only confirmed SC marker blocks / bad prepend lines.
 *
 * Prefer this over wiping whole theme or config files when infection is marker-bounded.
 */
class DP_Ambulance_Command_Sanitize extends DP_Ambulance_Command_Files {

	/**
	 * Strip known SC marker blocks from themes, wp-config.php, and auto_prepend lines.
	 *
	 * Rules (fail closed — incomplete/ambiguous markers → report only):
	 * - theme functions.php: exactly one SC_TH_BEGIN and one SC_TH_END → remove that block
	 * - drop-ins with SC_ADV_* / SC_DB_* blocks: same (one begin + one end)
	 * - wp-config.php: remove lines containing SC_WC (and optional SC_WC_BEGIN…SC_WC_END block)
	 * - .user.ini / user.ini / .htaccess: remove auto_prepend_file lines when SC evidence is present
	 *
	 * Full pre-clean copies are written under the quarantine first/ + run dirs.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Confirm writes.
	 *
	 * [--dry-run]
	 * : Report only; do not write.
	 *
	 * [--quarantine-dir=<path>]
	 * : Where to store full infected backups. Default: {ABSPATH}/../ambulance-quarantine/{Ymd-His}/
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function __invoke( $args, $assoc_args ) {
		unset( $args );
		$dry = ! empty( $assoc_args['dry-run'] );

		if ( ! $dry && empty( $assoc_args['yes'] ) ) {
			WP_CLI::error( 'Refusing to sanitize without --yes (or pass --dry-run to preview).' );
		}

		$q_run = '';
		if ( ! empty( $assoc_args['quarantine-dir'] ) ) {
			$q_run = rtrim( (string) $assoc_args['quarantine-dir'], '/\\' );
		} else {
			$q_run = dirname( untrailingslashit( ABSPATH ) ) . '/ambulance-quarantine/' . gmdate( 'Ymd-His' );
		}

		if ( ! $dry && ! wp_mkdir_p( $q_run ) ) {
			WP_CLI::error( 'Could not create quarantine dir: ' . $q_run );
		}

		WP_CLI::log( '== Sanitize (marker-bounded)' . ( $dry ? ' [dry-run]' : '' ) . ' ==' );
		WP_CLI::log( 'Backup run dir: ' . $q_run );

		$rows    = array();
		$changed = 0;

		foreach ( $this->collect_sanitize_candidates() as $item ) {
			$result = $this->sanitize_one( $item['path'], $item['kind'], $dry, $q_run );
			$rows[] = array(
				'file'   => $item['path'],
				'kind'   => $item['kind'],
				'action' => $result['action'],
				'note'   => $result['note'],
			);
			if ( ! empty( $result['changed'] ) ) {
				++$changed;
			}
		}

		if ( ! $rows ) {
			WP_CLI::success( 'No sanitize candidates found.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $rows, array( 'file', 'kind', 'action', 'note' ) );
		WP_CLI::success(
			$dry
				? "[dry-run] {$changed} file(s) would be sanitized."
				: "Sanitized {$changed} file(s). Full infected copies kept under quarantine."
		);
	}

	/**
	 * @return array<int,array{path:string,kind:string}>
	 */
	protected function collect_sanitize_candidates() {
		$out = array();

		$config = ABSPATH . 'wp-config.php';
		if ( is_file( $config ) ) {
			$out[] = array(
				'path' => $config,
				'kind' => 'wp-config',
			);
		}

		foreach ( array(
			WP_CONTENT_DIR . '/.user.ini',
			WP_CONTENT_DIR . '/user.ini',
			WP_CONTENT_DIR . '/.htaccess',
			ABSPATH . '.user.ini',
			ABSPATH . 'user.ini',
			ABSPATH . '.htaccess',
		) as $path ) {
			if ( is_file( $path ) ) {
				$out[] = array(
					'path' => $path,
					'kind' => 'prepend-config',
				);
			}
		}

		foreach ( array(
			WP_CONTENT_DIR . '/advanced-cache.php',
			WP_CONTENT_DIR . '/object-cache.php',
			WP_CONTENT_DIR . '/db.php',
		) as $path ) {
			if ( is_file( $path ) ) {
				$out[] = array(
					'path' => $path,
					'kind' => 'dropin-block',
				);
			}
		}

		$themes = WP_CONTENT_DIR . '/themes';
		if ( is_dir( $themes ) ) {
			foreach ( glob( $themes . '/*/functions.php' ) ?: array() as $path ) {
				if ( is_file( $path ) && ! $this->should_skip_path( $path ) ) {
					$out[] = array(
						'path' => $path,
						'kind' => 'theme-functions',
					);
				}
			}
		}

		return $out;
	}

	/**
	 * @param string $path  Absolute path.
	 * @param string $kind  Candidate kind.
	 * @param bool   $dry   Dry-run.
	 * @param string $q_run Quarantine run dir.
	 * @return array{action:string,note:string,changed:bool}
	 */
	protected function sanitize_one( $path, $kind, $dry, $q_run ) {
		$contents = @file_get_contents( $path );
		if ( false === $contents ) {
			return array(
				'action'  => 'skip',
				'note'    => 'unreadable',
				'changed' => false,
			);
		}

		switch ( $kind ) {
			case 'theme-functions':
				$cleaned = $this->strip_unique_block( $contents, 'SC_TH_BEGIN', 'SC_TH_END' );
				break;
			case 'dropin-block':
				$cleaned = $this->strip_dropin_blocks( $contents );
				break;
			case 'wp-config':
				$cleaned = $this->strip_wp_config_infection( $contents );
				break;
			case 'prepend-config':
				$cleaned = $this->strip_prepend_lines( $contents, $path );
				break;
			default:
				return array(
					'action'  => 'skip',
					'note'    => 'unknown kind',
					'changed' => false,
				);
		}

		if ( is_wp_error( $cleaned ) ) {
			return array(
				'action'  => 'manual-review',
				'note'    => $cleaned->get_error_message(),
				'changed' => false,
			);
		}

		if ( null === $cleaned ) {
			return array(
				'action'  => 'clean',
				'note'    => 'no markers',
				'changed' => false,
			);
		}

		if ( $cleaned === $contents ) {
			return array(
				'action'  => 'clean',
				'note'    => 'unchanged',
				'changed' => false,
			);
		}

		if ( $dry ) {
			return array(
				'action'  => 'would-sanitize',
				'note'    => 'markers matched',
				'changed' => true,
			);
		}

		if ( ! $this->backup_before_sanitize( $path, $contents, $q_run ) ) {
			return array(
				'action'  => 'failed',
				'note'    => 'backup failed',
				'changed' => false,
			);
		}

		if ( false === file_put_contents( $path, $cleaned ) ) {
			return array(
				'action'  => 'failed',
				'note'    => 'write failed',
				'changed' => false,
			);
		}

		return array(
			'action'  => 'sanitized',
			'note'    => 'markers removed; backup kept',
			'changed' => true,
		);
	}

	/**
	 * @param string $path     Absolute path.
	 * @param string $contents Original contents.
	 * @param string $q_run    Quarantine run dir.
	 * @return bool
	 */
	protected function backup_before_sanitize( $path, $contents, $q_run ) {
		$rel   = $this->sanitize_rel_key( $path );
		$first = dirname( $q_run ) . '/first/' . $rel;
		$dest  = $q_run . '/' . $rel;

		if ( ! is_file( $first ) ) {
			$parent = dirname( $first );
			if ( ! is_dir( $parent ) && ! wp_mkdir_p( $parent ) ) {
				return false;
			}
			if ( false === file_put_contents( $first, $contents ) ) {
				return false;
			}
			@chmod( $parent, 0700 );
		}

		$parent = dirname( $dest );
		if ( ! is_dir( $parent ) && ! wp_mkdir_p( $parent ) ) {
			return false;
		}
		if ( false === file_put_contents( $dest, $contents ) ) {
			return false;
		}
		@chmod( $parent, 0700 );
		return true;
	}

	/**
	 * @param string $path Absolute path.
	 * @return string
	 */
	protected function sanitize_rel_key( $path ) {
		$rel = $this->relative_to_content( $path );
		if ( $rel !== $path && '' !== $rel ) {
			return 'wp-content/' . ltrim( $rel, '/' );
		}
		$abs  = wp_normalize_path( untrailingslashit( ABSPATH ) );
		$norm = wp_normalize_path( $path );
		if ( 0 === strpos( $norm, $abs . '/' ) ) {
			return ltrim( substr( $norm, strlen( $abs ) ), '/' );
		}
		return 'outside/' . basename( $path );
	}

	/**
	 * @param string $contents File contents.
	 * @param string $begin    Begin marker.
	 * @param string $end      End marker.
	 * @return string|null|\WP_Error Cleaned contents, null if no markers, WP_Error if ambiguous.
	 */
	protected function strip_unique_block( $contents, $begin, $end ) {
		$n_begin = substr_count( $contents, $begin );
		$n_end   = substr_count( $contents, $end );

		if ( 0 === $n_begin && 0 === $n_end ) {
			return null;
		}
		if ( 1 !== $n_begin || 1 !== $n_end ) {
			return new WP_Error(
				'ambiguous_markers',
				sprintf( 'begin=%d end=%d (need exactly one each)', $n_begin, $n_end )
			);
		}

		$pattern = '/' . preg_quote( $begin, '/' ) . '.*?' . preg_quote( $end, '/' ) . '/s';
		$cleaned = preg_replace( $pattern, '', $contents, 1, $count );
		if ( null === $cleaned || 1 !== $count ) {
			return new WP_Error( 'strip_failed', 'could not strip unique block' );
		}

		// Collapse accidental blank runs left by the cut.
		$cleaned = preg_replace( "/\n{3,}/", "\n\n", $cleaned );
		return $cleaned;
	}

	/**
	 * Strip SC_ADV / SC_DB marker blocks from drop-ins (one pair each, independently).
	 *
	 * @param string $contents Contents.
	 * @return string|null|\WP_Error
	 */
	protected function strip_dropin_blocks( $contents ) {
		$pairs = array(
			array( 'SC_ADV_BEGIN', 'SC_ADV_END' ),
			array( 'SC_DB_BEGIN', 'SC_DB_END' ),
		);

		$working = $contents;
		$any     = false;
		foreach ( $pairs as $pair ) {
			if ( false === strpos( $working, $pair[0] ) && false === strpos( $working, $pair[1] ) ) {
				continue;
			}
			$next = $this->strip_unique_block( $working, $pair[0], $pair[1] );
			if ( is_wp_error( $next ) ) {
				return $next;
			}
			if ( null === $next ) {
				continue;
			}
			$working = $next;
			$any     = true;
		}

		return $any ? $working : null;
	}

	/**
	 * @param string $contents Contents.
	 * @return string|null|\WP_Error
	 */
	protected function strip_wp_config_infection( $contents ) {
		$working = $contents;
		$any     = false;

		if ( false !== strpos( $working, 'SC_WC_BEGIN' ) || false !== strpos( $working, 'SC_WC_END' ) ) {
			$block = $this->strip_unique_block( $working, 'SC_WC_BEGIN', 'SC_WC_END' );
			if ( is_wp_error( $block ) ) {
				return $block;
			}
			if ( null !== $block ) {
				$working = $block;
				$any     = true;
			}
		}

		if ( false !== strpos( $working, 'SC_WC' ) ) {
			$lines   = preg_split( "/\r\n|\n|\r/", $working );
			$kept    = array();
			$removed = 0;
			foreach ( $lines as $line ) {
				if ( false !== strpos( $line, 'SC_WC' ) ) {
					++$removed;
					continue;
				}
				$kept[] = $line;
			}
			if ( $removed > 0 ) {
				$working = implode( "\n", $kept );
				// Preserve trailing newline if original had one.
				if ( preg_match( "/\n\z/", $contents ) && ! preg_match( "/\n\z/", $working ) ) {
					$working .= "\n";
				}
				$any = true;
			}
		}

		return $any ? $working : null;
	}

	/**
	 * Remove auto_prepend_file lines only when the file also has SC / implant evidence.
	 *
	 * @param string $contents Contents.
	 * @param string $path     Path (for logging context).
	 * @return string|null|\WP_Error
	 */
	protected function strip_prepend_lines( $contents, $path ) {
		unset( $path );
		if ( false === strpos( $contents, 'auto_prepend_file' ) ) {
			return null;
		}

		$evidence = false;
		foreach ( array( 'SC_WC', 'SC_ADV_', 'SC_DB_', 'SC_TH_', '__SC_BOOT', 'SCOCV', 'echo-updater-x', 'retadpu-ohce' ) as $needle ) {
			if ( false !== strpos( $contents, $needle ) ) {
				$evidence = true;
				break;
			}
		}
		// Also treat prepend targets that look like hex drops / hidden loaders as evidence.
		if ( ! $evidence && preg_match( '/auto_prepend_file\s*=\s*.*([0-9a-f]{8}\.php|\.sc_|echo-updater|cron-helper|db-helper)/i', $contents ) ) {
			$evidence = true;
		}

		if ( ! $evidence ) {
			return new WP_Error(
				'prepend_no_evidence',
				'auto_prepend_file present but no SC evidence — leave for manual review'
			);
		}

		$lines   = preg_split( "/\r\n|\n|\r/", $contents );
		$kept    = array();
		$removed = 0;
		foreach ( $lines as $line ) {
			if ( preg_match( '/^\s*auto_prepend_file\s*=/i', $line ) || preg_match( '/php_value\s+auto_prepend_file/i', $line ) ) {
				++$removed;
				continue;
			}
			$kept[] = $line;
		}

		if ( 0 === $removed ) {
			return null;
		}

		$working = implode( "\n", $kept );
		if ( preg_match( "/\n\z/", $contents ) && ! preg_match( "/\n\z/", $working ) ) {
			$working .= "\n";
		}
		return $working;
	}
}
