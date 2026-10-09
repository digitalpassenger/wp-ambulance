<?php
/**
 * ambulance heuristics
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generic webshell heuristics (eval/base64 chains, known shells, double extensions).
 */
class DP_Ambulance_Command_Heuristics extends DP_Ambulance_Command_Files {

	/**
	 * Cheap generic malware strings. Noisy ones only flag when combined.
	 *
	 * @var string[]
	 */
	public static $heuristic_needles = array(
		'eval(',
		'assert(',
		'create_function(',
		'gzinflate(',
		'gzuncompress(',
		'str_rot13(',
		'base64_decode(',
		'shell_exec(',
		'passthru(',
		'proc_open(',
		'system(',
		'FilesMan',
		'c99shell',
		'r57shell',
		'b374k',
		'WSO_VERSION',
	);

	/**
	 * Single-hit strings that are almost never legitimate.
	 *
	 * @var string[]
	 */
	public static $heuristic_always = array(
		'FilesMan',
		'c99shell',
		'r57shell',
		'b374k',
		'WSO_VERSION',
	);

	/**
	 * High-signal regexes, run only after a cheap needle matches.
	 *
	 * @var array<string,string>
	 */
	public static $heuristic_regexes = array(
		'eval_superglobal'   => '/eval\s*\(\s*(base64_decode|gzinflate|\$_(GET|POST|REQUEST|COOKIE))/i',
		'assert_superglobal' => '/assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
		'preg_replace_e'     => '/preg_replace\s*\([^;]{0,200}\/[imsxADSUXu]*e[imsxADSUXu]*/',
	);

	/**
	 * Scan wp-content for generic malware heuristics, not implant-specific fingerprints.
	 *
	 * Cheap strings are a prefilter; regex only runs after a cheap hit. Two cheap
	 * hits, a known-shell string, or a high-signal regex is required to flag a file.
	 *
	 * ## OPTIONS
	 *
	 * [--since=<when>]
	 * : Only files whose ctime is newer than this. Examples: 24h, 7d, "2026-10-01".
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
		$root  = WP_CONTENT_DIR;
		$since = $this->parse_since( $assoc_args );
		$found = $this->collect_file_findings( $root, $since );
		$rows  = array_merge( $found['heuristics'], $found['double_ext'] );

		WP_CLI::log( '== Heuristics under ' . $root . ' ==' );

		if ( ! $rows ) {
			WP_CLI::success( 'No heuristic hits.' . ( $found['skipped'] ? " Skipped {$found['skipped']} paths." : '' ) );
			return;
		}

		$this->output_rows( $rows, array( 'file', 'note', 'hits' ), $assoc_args );
		WP_CLI::warning( count( $found['heuristics'] ) . ' heuristic file(s), ' . count( $found['double_ext'] ) . ' double-extension file(s). Review; many plugins use base64/eval legitimately.' );
	}
}
