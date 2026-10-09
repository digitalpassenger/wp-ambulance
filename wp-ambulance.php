<?php
/**
 * Plugin Name:       Digital Passenger - Hack removal helper
 * Description:       WP-CLI scanner for the fake Self Healing Hack a.k.a. sc_* WordPress implant. Drop in mu-plugins. Does nothing on the front end.
 * Version:           1.6.0
 * Author:            Jaime Martínez
 * License:           GPL-3.0-or-later
 * Requires at least: 5.8
 * Requires PHP:      7.4
 *
 * Usage (from the WordPress root):
 *   wp am scan                   (alias: wp ambulance …)
 *   wp am files
 *   wp am files --since=24h --format=csv
 *   wp am heuristics
 *   wp am integrity
 *   wp am dropins
 *   wp am options
 *   wp am options --quick
 *   wp am db
 *   wp am users
 *   wp am cron
 *   wp am purge-options --yes
 *   wp am purge-files --dry-run
 *   wp am purge-files --yes
 *   wp am purge-files --quarantine --yes
 *   wp am sanitize --dry-run
 *   wp am sanitize --yes
 *   wp am fix --dry-run
 *   wp am fix --yes
 *   wp am fix --quarantine --yes
 *   wp am export
 *   wp am export --dir=/path/to/out
 *   wp am playbook
 *   wp am playbook --section=core
 *
 * Multisite: add --url=<site-url> or --network.
 *
 * Mostly report-only. Destructive exceptions:
 *   - purge-options: deletes known sc_* / _transient_sc_* / _wp_cg_% option keys
 *   - purge-files: every wp-content-root .php/.zip (incl. index.php/drop-ins), hex staging zips/PHP, hidden files/dirs, known basenames, .thumbnails, trace-wrapper-bit
 *     (optional --quarantine moves to ambulance-quarantine/ with first+newest copies)
 *   - sanitize: marker-bounded strip of SC_TH / SC_ADV / SC_DB / SC_WC / evidenced auto_prepend
 *   - fix: engine-first purge-files, then purge-options, then clear ALL cron
 *   - export: write manifests + offline bash cleaners + guard.sh (no delete; bash runs without WP)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

define( 'DP_AMBULANCE_DIR', __DIR__ );

require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-files.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-heuristics.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-dropins.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-integrity.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-options.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-db.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-users.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-cron.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-purge-options.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-purge-files.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-sanitize.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-fix.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-export.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-playbook.php';
require_once DP_AMBULANCE_DIR . '/app/class-dp-ambulance-command-scan.php';

$dp_ambulance_commands = array(
	'scan'            => 'DP_Ambulance_Command_Scan',
	'dropins'         => 'DP_Ambulance_Command_Dropins',
	'files'           => 'DP_Ambulance_Command_Files',
	'heuristics'      => 'DP_Ambulance_Command_Heuristics',
	'integrity'       => 'DP_Ambulance_Command_Integrity',
	'options'         => 'DP_Ambulance_Command_Options',
	'db'              => 'DP_Ambulance_Command_Db',
	'users'           => 'DP_Ambulance_Command_Users',
	'cron'            => 'DP_Ambulance_Command_Cron',
	'purge-options'   => 'DP_Ambulance_Command_Purge_Options',
	'purge-files'     => 'DP_Ambulance_Command_Purge_Files',
	'sanitize'        => 'DP_Ambulance_Command_Sanitize',
	'fix'             => 'DP_Ambulance_Command_Fix',
	'export'          => 'DP_Ambulance_Command_Export',
	'playbook'        => 'DP_Ambulance_Command_Playbook',
);

foreach ( $dp_ambulance_commands as $subcommand => $class ) {
	WP_CLI::add_command( "am {$subcommand}", $class );
}
