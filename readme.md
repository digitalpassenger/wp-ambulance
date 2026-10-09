# Digital Passenger — Hack removal helper

WP-CLI incident-response scanner for the self healing hack / `sc_*` WordPress implant, plus generic webshell heuristics and checksum checks.

Drop this folder in `wp-content/mu-plugins`. It does nothing on the front end: it only loads when WP-CLI runs.

Run commands from the WordPress root. Short alias: `wp am …`.

## Background information 
When brought in to cleanup a hacked site and noticing that it came back and spread throughout all other site I started to create to to to cleanup this WordPress installation. 

The thing is... having a `wp am fix` command doesn't help, because it invokes WordPress which heals the hack. So I changed to `wp am export` which exports all infected `files`, `directories` and database `rows` like options and scheduled crons.

More about the Self-Healing WordPress hack:

- [SC-403 Self-Healing WordPress Malware (MD Pabel)](https://www.mdpabel.com/malware-research/sc-403-self-healing-wordpress-malware/)
- [SC WordPress Malware: self-healing mesh of loaders, drop-ins, and a blockchain-controlled backdoor (Sucuri)](https://blog.sucuri.net/2026/09/sc-wordpress-malware-a-self-healing-mesh-of-loaders-drop-ins-and-a-blockchain-controlled-backdoor.html)

## Playbook
- Stop all traffic by block it in your .htaccess or so.
- Analyse the site via `wp am scan` and checkout the steps to take `wp am playbook`

## Start removal
- `wp am export` export found issues to .txt files.
- Then traverse out of the webroot and look into `ambulance-analysis` folder for found issues and adjust to which. Use one of the Bash script to cleanup witouth booting WordPress.

If you don't have the (SC) Self-Healing Hack, you might just can get away with `wp am fix` :).

## Destructive actions

This plugin is **mostly report-only**. Destructive exceptions:

- `purge-options` — deletes known `sc_*` / `_transient_sc_*` / `_wp_cg_%` option keys (and `content_sync_helper_footer_links`, `wp_helper_uid`)
- `purge-files` — deletes (or `--quarantine` moves) drop-ins, every `.php`/`.zip` at the wp-content root (incl. `index.php`), hex staging zips/PHP anywhere, `cron-helper*` / `db-helper*` / `maintenance-helper*` files, hidden files/dirs, known basenames, `.thumbnails`, `plugins/trace-wrapper-bit`, `plugins/content-sync-helper`, `plugins/advanced-linkflow-control`, `plugins/wp-security-helper`, `sc-loader.php`, `plugins/system-control`, `.sc-backup`, `plugins/mailpoet-652`, and confirmed `wp_helper_uid` samples (`admin-helper.php` / `boot-loader.php` by hash or markers)
- `sanitize` — marker-bounded strip of `SC_TH` / `SC_ADV` / `SC_DB` / `SC_WC` blocks and evidenced `auto_prepend_file` lines (backs up full files first)
- `fix` — **engine-first:** `purge-files` (reinfector/drop-ins → payload/decoys) → `purge-options` → clear all cron
- `export` — **analyse only:** writes manifests + offline `clean-*.sh` + `guard.sh` (run bash later; no WP on cleanup)

**It does not delete arbitrary PHP files** outside the fixed malicious basename list (except marker/hash-confirmed `wp_helper_uid` candidates).

## PHP class shape

```
DP_Ambulance_Command                 CLI plumbing (multisite, --format, --since, skip/relative path)
└── DP_Ambulance_Command_Files       Filesystem scan + content needles + path classifiers
    ├── DP_Ambulance_Command_Dropins       (needle scan on drop-ins / .user.ini)
    ├── DP_Ambulance_Command_Heuristics    (heuristic lists; reuses collect_file_findings)
    ├── DP_Ambulance_Command_Sanitize          Marker-bounded surgical cleaners
    └── DP_Ambulance_Command_Purge_Files   Destructive collectors / delete / quarantine
        └── DP_Ambulance_Command_Export   Manifests + offline bash + guard

Other commands (options, db, users, cron, integrity, fix, playbook, scan) extend DP_Ambulance_Command only.
```

Fingerprint lists (`$content_needles`, fake plugin names) live on **Files**. Purge basename/dir lists live on **Purge_Files**. Heuristic needles live on **Heuristics**.

## Commands

### `wp am scan`

Runs every read-only check, in this order: dropins → files (including heuristics) → integrity → options → db → users → cron.

Does **not** run `purge-options`.

| Flag | What it does |
|------|----------------|
| `--quick` | Passed to options: skip option_value / hex-name scans (faster). |
| `--since=<when>` | Passed to the file scan (ctime filter). |
| `--network` | On multisite, run per-site DB checks on every site. |

### `wp am dropins`

Checks usual persistence paths: `advanced-cache.php`, `db.php`, `object-cache.php`, `.user.ini`, `.htaccess` under `wp-content` and the site root.

Reports implant fingerprints, empty decoys, `auto_prepend_file`, and `#KH…YS` / Chrome UA-cloak rules. Present files with no known markers are still listed so you can review them.

### `wp am files`

Walks `wp-content` for:

- Implant fingerprints (Vista Connector Box / SC/SCOCV strings including `SC_WC`; Content Sync Helper / `PBN-LINKS` / `ticker/v1`; Advanced LinkFlow Control / `Advanced_LinkFlow_Control` / `?sp=` hide gate; WP Security Helper / `WP_Security_Helper`; `sc-loader.php` / `plugins/system-control` / `.sc-backup/system-control`; Compact Extension Vox / `menu-queue-bit.php` / `_ofdyhs`; `wp_helper_uid` pair — exact file hashes, gate digests, Widget-cache / Runtime-dependencies headers, cluster probes)
- Persistence paths scanners miss: `.sc_*` / `.sc-backup` dirs, empty mu-plugins, `echo-updater-x*`, `.off`/`.disabled` husks, state files, hex-named staging `.zip` / drop `.php` (e.g. `c76e59a3.zip`, `9dd16321.php`), `themes/custom-file-*` dirs, `plugins/security_<digits>` dirs, `sc-loader.php` / `plugins/system-control`, `admin-helper.php` / `boot-loader.php` candidates
- `#KH…YS` / “Block for Chrome” `.htaccess` cloaks
- PHP in `uploads/`, `cache/`, `upgrade/`
- PHP double extensions (`shell.php.jpg`)
- Timestamp-named PHP (`*_1771357352.php`)
- Generic webshell heuristics (same rules as `ambulance heuristics`)
- Fake mu-plugin headers (Vista Connector Box, Vapor Extension Tag)

Also reads `.htaccess`, `.user.ini`, HTML, JS, SVG, and `.off`/`.disabled` husks.

| Flag | What it does |
|------|----------------|
| `--since=<when>` | Only files whose **ctime** is newer than this. Examples: `24h`, `7d`, `2026-10-01`. Prefer ctime over mtime; mtime is easy to spoof. |
| `--fingerprint-only` | Skip generic heuristics and double-extension rows. |
| `--format=<format>` | `table` (default), `csv`, `json`, `json_pretty`, or `count`. |

### `wp am heuristics`

Same filesystem walk as `files`, but only generic malware heuristics:

- Cheap strings first (`eval(`, `base64_decode(`, `gzinflate(`, …)
- A file is flagged only if two cheap strings match, a known-shell marker hits (`FilesMan`, `c99shell`, …), or a high-signal regex matches (`eval` / `assert` on a superglobal, `preg_replace` `/e`)
- PHP double extensions

Review hits: many legitimate plugins use `base64_decode` / `eval`.

| Flag | What it does |
|------|----------------|
| `--since=<when>` | Ctime filter (same as `files`). |
| `--format=<format>` | `table`, `csv`, `json`, `json_pretty`, or `count`. |

### `wp am integrity`

Compares files to wordpress.org checksums:

- `wp core verify-checksums`
- `wp plugin verify-checksums --all`
- `wp theme verify-checksums --all` when this WP-CLI version supports it

Modified or unknown files (extra PHP in `wp-admin` / `wp-includes`, edited plugins) are the IR signal. Custom/premium plugins often fail checksums; that is expected.

Also lists installed file-manager class plugins (common foothold for this family).

| Flag | What it does |
|------|----------------|
| `--skip-plugins` | Skip plugin checksums. |
| `--skip-themes` | Skip theme checksums. |

### `wp am options`

Lists `wp_options` rows whose names are known implant keys or match `sc_%`, `_wp_cg_%`, `_transient_sc_%`, `_transient_timeout_sc_%`. **Deep by default:** also searches option values for implant/C2 markers, reports hex-named options when values match SC signatures, and lists options ≥100KB as triage-only (size ≠ malware). Pass `--quick` to skip value/hex/large scans. Hex / large options are **not** deleted by `purge-options` (but `_wp_cg_%` and `_transient_sc_*` are).

| Flag | What it does |
|------|----------------|
| `--quick` | Only known option names + LIKE patterns (faster on large databases). |
| `--format=<format>` | `table`, `csv`, `json`, `json_pretty`, or `count`. |
| `--network` | Run on every site (multisite). |

### `wp am db`

Scans `posts`, `postmeta`, `comments`, `commentmeta`, and `usermeta` for implant and webshell needles in content/meta values. Caps at 25 rows per needle per table. Also scans Code Snippets / WPCode tables when they exist.

Does not scan `wp_options` (use `ambulance options`). Does not delete rows.

| Flag | What it does |
|------|----------------|
| `--format=<format>` | `table`, `csv`, `json`, `json_pretty`, or `count`. |
| `--network` | Run on every site (multisite). |

### `wp am users`

Lists administrators and flags logins matching this family’s hex-suffix regex (`admin_c52e4d`, `content_*`, `w2s_*` / `wp2_*`, `mail_daemon*`) plus the looser prefixes (`admin_`, `adm_`, …). Also warns when the `wp_helper_uid` option is set and flags that user ID.

Flags are hints only. Verify every admin; rotate passwords and destroy sessions after cleanup.

| Flag | What it does |
|------|----------------|
| `--network` | Run on every site (multisite). |

### `wp am cron`

Lists cron hooks whose names look like this family (`sc_*`, `sc_cron`, `sc_admin`).

Does not unschedule events. After file cleanup: `wp cron event delete <hook>`.

| Flag | What it does |
|------|----------------|
| `--network` | Run on every site (multisite). |

### `wp am purge-options`

**Destructive.** Deletes known `sc_*` option keys (and `content_sync_helper_footer_links`) on the current site. Does not delete files, posts, users, or cron events.

Refuses to run without `--yes`.

| Flag | What it does |
|------|----------------|
| `--yes` | Confirm deletion. |
| `--network` | Run on every site (multisite). |

### `wp am purge-files`

**Destructive.** Deletes under `wp-content` (preview with `--dry-run`):

- drop-ins at wp-content root: `object-cache.php`, `advanced-cache.php`, `db.php`
- `.user.ini` / `user.ini` at the wp-content root
- known malicious basenames anywhere: `db-45.php`, `sunrise-45.php`, `maintenance-45.php`
- every `.php` and `.zip` directly in `wp-content/` (including `index.php` and drop-ins), plus hex-named staging zips (`[0-9a-f]{8}.zip`) and hex drop PHP (`[0-9a-f]{8}.php`) anywhere
- every **hidden file** (basename starts with `.`) under wp-content
- every **hidden directory** (basename starts with `.`) under wp-content (e.g. `.sc_*`, `.thumbnails`)
- `plugins/trace-wrapper-bit/` and `mu-plugins/trace-wrapper-bit/` (and `trace-wrapper-bit.php` anywhere under wp-content)
- decoy swarm: `echo-updater-x*` files/dirs, known three-word decoy mu-plugins (incl. `ridge-backup-mod.php`, `menu-queue-bit.php` / Compact Extension Vox), `mu-plugins/sc_*`, and **every 0-byte file under mu-plugins/** (allowlist: `autoloader.php`, `automation-by-installatron.php`, `0-loader.php`; `dp-ambulance` skipped)
- `plugins/wp-file-manager/` (common entry vector for this family)
- `plugins/link-factory/` — https://github.com/advisories/GHSA-p2hj-vx9x-4rh8
- `plugins/content-sync-helper/` (+ `mu-plugins/content-sync-helper.php`) — fake “Content Sync Helper” / PBN-LINKS injector
- `plugins/advanced-linkflow-control/` (+ `mu-plugins` / `.php` copies) — hide-self via `all_plugins` unset + `?sp=` gate
- `plugins/wp-security-helper/` (+ `mu-plugins` / `.php` copies) — fake “WP Security Helper”
- `sc-loader.php`; `plugins/system-control/` (destination); `.sc-backup/` (+ `.sc-backup/system-control` backup source)
- any filename containing `cron-helper`, `db-helper`, or `maintenance-helper`; `mu-plugins/custom-constants-652.php`; `plugins/mailpoet-652/`
- `themes/custom-file-*` directories (file-manager theme drops, e.g. `custom-file-4-1787062890`)
- `plugins/security_<digits>` directories (e.g. `security_1787155594`)
- every `uploads/.../.thumbnails` directory tree (also matched as hidden dirs)

Skips the ambulance plugin’s own files. Also removes legitimate cache/`db.php` drop-ins — reinstall those after cleanup if needed.

Refuses to run without `--yes` unless you pass `--dry-run`.

| Flag | What it does |
|------|----------------|
| `--yes` | Confirm deletion or quarantine. |
| `--dry-run` | List targets only; do not delete or move. |
| `--quarantine` | Move targets to `{ABSPATH}/../ambulance-quarantine/{stamp}/` (keeps durable `first/` + newest run copy) instead of deleting. |
| `--quarantine-dir=<path>` | Custom quarantine run directory. |

`admin-helper.php` / `boot-loader.php` are purged only when confirmed (filenames alone are not enough):

| Indicator | Type | Context |
|-----------|------|---------|
| `4bbeaed0845bcd965c92902a1dfb314d4afd79e48029dc22bf5fa7597a0d93cb` | SHA-256 | Exact recovered `admin-helper.php` |
| `0cbe6a757abcfe7c8968ae169929164d978f120847c05ca91f5e09c44293c4f3` | SHA-256 | Exact recovered `boot-loader.php` |
| `wp_helper_uid` | WP option + code | Shared by both files; also purged via `purge-options` |
| `Widget cache bootstrap, ver b2ccbcd25e` | Code marker | Fake header in `admin-helper.php` |
| `Runtime dependencies bootstrap 9b66554fd3` | Code marker | Fake header in `boot-loader.php` |
| `wp_179e4b` + `wp_4bb239` + `wp_4960ab` | Cluster probes | All three together in the direct endpoint |
| `8e753f173a5c428fe6c44646cddb0da04952628bcd098400d6fe9fcd3f3bb435` | Secret SHA-256 | Withheld direct-endpoint gate digest (literal in sample) |
| `b6efe58fb91fb0bb9d11fce3b6eb42bcc1b8822deacc39facc657d17cffb1bf5` | Secret SHA-256 | Withheld MU-plugin gate digest (literal in sample) |

Contextual paths: `wp-content/admin-helper.php`, `wp-content/mu-plugins/boot-loader.php`.

### `wp am sanitize`

**Destructive (surgical).** Removes only confirmed marker blocks:

- theme `functions.php`: unique `SC_TH_BEGIN`…`SC_TH_END`
- drop-ins: unique `SC_ADV_*` / `SC_DB_*` blocks
- `wp-config.php`: `SC_WC` lines / `SC_WC_BEGIN`…`SC_WC_END`
- `.user.ini` / `.htaccess`: `auto_prepend_file` lines only when SC evidence is also present

Ambiguous or repeated markers → `manual-review` (no write). Full infected copies are saved under quarantine `first/` + run dir.

| Flag | What it does |
|------|----------------|
| `--yes` | Confirm writes. |
| `--dry-run` | Report only. |
| `--quarantine-dir=<path>` | Backup location. |

### `wp am fix`

**Destructive.** Bundled remediation in [SC/SCOCV engine-first order](https://github.com/vapvarun/wp-malware-cleanup-mcp/blob/master/docs/case-studies/sc-scocv-dropin-backdoor-2026-09.md#remediation-engine-first-quarantine-first):

1. `purge-files` phase 1 — reinfector (`echo-updater-x*` / `trace-wrapper-bit*`) + drop-ins (`object-cache.php`, `advanced-cache.php`, `db.php`, `.user.ini`)
2. `purge-files` phase 2 — payload dirs, decoys, husks, zips, hidden files, etc.
3. `purge-options` — known `sc_*` option keys
4. Clear **all** scheduled WordPress cron events

Still manual (case-study steps 4–6): rogue admins, `wp am scan` verify, harden via `wp am playbook`.

Refuses to run without `--yes` unless you pass `--dry-run`.

| Flag | What it does |
|------|----------------|
| `--yes` | Confirm. |
| `--dry-run` | Preview only. |
| `--quarantine` | Pass through to purge-files. |
| `--quarantine-dir=<path>` | Pass through to purge-files. |
| `--network` | On multisite, purge options and clear cron on every site (file purge still once). |

### `wp am export` (alias: `wp am export`)

**Analyse only** (loads WordPress once). Writes a timestamped pack under `{ABSPATH}/../ambulance-analysis/{domain}/{Ymd-His}/` (outside `public_html`):

- `files.txt` / `dirs.txt` — purge-files targets (+ host `cron-helper` / `.wp-cache-*` / `/tmp` hits when found)
- `options.txt` — known implant options still present (`table\tcolumn\tname`)
- `cron.txt` — clear WP `cron` option + host `/etc/cron.d/php-cache-*` + crontab needles
- `users.txt` — regex-flagged rogue admins only (`ID\tlogin`)
- `watch-paths.txt` / `site.env` — inputs for live `guard.sh`
- `db.env` — DB credentials for mysql (chmod 600)
- `clean-files.sh`, `clean-dirs.sh`, `clean-options.sh`, `clean-cron.sh`, `clean-users.sh`, `clean-all.sh`, `guard.sh`

Cleanup is **offline bash** (no WP bootstrap):

```bash
cd …/ambulance-analysis/example.com/20261007-183015
DRY_RUN=1 ./clean-all.sh
QUARANTINE=1 ./clean-all.sh          # preferred: move instead of delete
INTERVAL=5 ./guard.sh                # short live containment; Ctrl+C to stop
```

`found=0` from the guard is **not** proof the site is clean. Prefer this when the implant reinfects on every WP load (`fix` still available for softer cases).

| Flag | What it does |
|------|----------------|
| `--dir=<path>` | Custom output directory. |

### `wp am playbook`

**Read-only.** Prints a copy/paste cheat sheet of helpful WP-CLI remediation commands (core force download, reinstall plugins/themes, shuffle salts, reset admin passwords, purge helpers, verify). Does not run any of them.

| Flag | What it does |
|------|----------------|
| `--section=<section>` | Only one block: `backup`, `scan`, `files`, `core`, `plugins`, `themes`, `database`, `users`, `harden`, `verify`. |

## Multisite

Use `--url=<site-url>` for one site, or `--network` on commands that support it (`scan`, `options`, `db`, `users`, `cron`, `purge-options`).

## Typical cleanup order

**When the implant reinfects on every WP request** (preferred):

1. `wp am export` (or `ambulance-export-all.sh` on the host)
2. Leave WordPress alone; run `DRY_RUN=1 ./clean-all.sh` then `./clean-all.sh` in the export dir
3. `wp am scan` verify, then playbook / rotate credentials

**When a one-shot WP cleanup is acceptable:**

1. `wp am scan` (deep options scan by default; use `--quick` for a faster triage)
2. `wp am fix --dry-run` then `wp am fix --yes`
3. `wp am playbook` (or `--section=core` / `plugins` / `users` / …) for remaining remediation
4. Review remaining file/heuristic/integrity hits; replace core/plugins/themes from clean packages
5. Remove leftover fake admins
6. Rotate all credentials (WP users, database, host, salts)

## Requirements

- WordPress 5.8+
- PHP 7.4+
- WP-CLI
