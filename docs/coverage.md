# What judged covers today

Everything listed here is written and tested. What is still open is in [todo.md](todo.md), what a miss costs in [costs.md](costs.md), and the long
explanation of each check in [reference.md](reference.md). judged only reads and reports; it never repairs, deletes, restores or renews on its own.

Every result is one of `pass`, `warn`, `fail`, `unknown` or (for a control with no machine evidence) `manual`. `fail` is for what is certain,
`warn` for what depends on your intent, `unknown` when the check could not look. Nothing is hidden: an option that accepts a finding keeps it
visible. The option tables below are generated from the code (a test fails when an option is missing from this file).

## 1. Coverage by area

| Area (`areas/`) | What it looks at | Platform |
|---|---|---|
| **expiry** (`tls`, `gpg`, `domain`, `date`, `licence`, `contract` lines) | TLS certificates, GPG keys, SSH keys, domains, bought licences, contracts and DPAs with a notice period; one alert per band (30, 14, 7, 1 days by default) | any |
| **renewal** (`renew` line) | runs your own ACME client or GPG extension when a certificate is due, then reads the served certificate again: unchanged is a failure whatever the exit code said | any |
| **obligations** (`company`, `obligation`, `duty`) | recurring and event deadlines for the regions you name: Cyber Essentials, ISO 27001, GDPR (72 h breach notice), NIS2 (24 h, 72 h, one month), Cyber Resilience Act. Catalog typed from memory, marked unreviewed | any |
| **feeds** | public lists cached as JSON: CISA known-exploited vulnerabilities | any |
| **host** and **hardening** | firewall, listening ports, SSH server and keys, sudoers, setuid and world-writable files, 13 kernel settings, logging, updates, disk encryption, extra uid-0 accounts, anti-malware service | Linux |
| **agents** | Claude Code permission settings, MCP server configs, hidden characters in instruction files, AI provider keys left in plain text or in a tracked `.env` | Linux, paths for Windows and macOS open |
| **secrets** | token shapes, secret-named files, `.env` files, high-entropy strings, your own names and paths, e-mail addresses (masked), git history | any |
| **github** | account hygiene through `gh api`, metadata only: the token judged uses (expiry, broad scopes), open secret-scanning alerts, read-write or old deploy keys, Actions secrets nobody rotated in a year | any with `gh` |
| **software** (`licences`, `deps`, `waive`) | Python environment licences; lockfile dependencies (npm, Cargo, Composer, Go, Python): vulnerabilities (OSV with CVSS), the CISA known-exploited list, licences; accepted risks with owner, reason and expiry | any |
| **sandboxes** (`flatpak`, `containers`) | Flatpak permissions and leftovers; podman or docker containers, images (trivy), Dockerfile and compose files | Linux |
| **malware** | ClamAV scan of chosen folders | Linux |
| **backup** | newest backup age, required folders, last restore test (restic, borg, plain folder); evidence only, backups are made by another tool | Linux |
| **integrity** | file baseline of chosen folders, compared on every audit | Linux |
| **links** | broken symlinks, links into `/tmp`, setuid files with several names | Linux |
| **endpoints** (`tls`, `site`) | TLS version, certificate lifetime, HSTS, CAA, security headers, page images that are not WebP | any |
| **mail** | SPF and DMARC of your mail domains | any |
| **paperwork** | contracts, suppliers, DPAs, insurance and trademarks: last day to give notice, auto-renew cost exposure per currency | any |
| **codestd** | MISRA C (cppcheck), CERT C (clang-tidy), shellcheck; findings are warnings; off by default | Linux |
| **custom checks** (`check` line) | your own command, mapped to controls | any |

Frameworks mapped: Cyber Essentials, ISO 27001 and GDPR (`judged audit --framework ce|iso27001|gdpr`). The control list is typed from memory and marked
unreviewed: this is evidence, not a certification.

## 2. Plug-in folders

One file per plug-in, found automatically; a plug-in that crashes becomes one `unknown` result and the rest still run.

| Folder | Files today |
|---|---|
| `judged/areas/` | one per area above |
| `judged/hardening/` | `logging_audit`, `ssh_keys`, `ssh_server`, `sudoers`, `suid`, `sysctl` |
| `judged/agentchecks/` | `claude_settings`, `envkeys`, `instructions`, `mcp` |
| `judged/codestd/` | `cert_c`, `misra_c`, `shell` |
| `judged/feeds/` | `kev` |
| `judged/inits/` | `dinit`, `openrc`, `runit`, `systemd` |
| `judged/pkgmgrs/` | `apt`, `dnf`, `pacman`, `xbps` |
| `judged/backups/` | `borg`, `folder`, `restic` |
| `judged/renewers/` | `gpg` |
| `judged/licsources/` | `depsdev`, `packagist` |
| `judged/sbom/` | `cyclonedx`, `spdx` |

## 3. What was run for real and what was not

Run for real on the development machine (Arch-based Linux, systemd, pacman): the expiry tracker, TLS and ACME against a local test server, the host
and hardening audits (except `sudoers`, which needs root), secrets, dependencies against OSV, folder backups, ClamAV with the EICAR test file,
CERT C through clang-tidy and shellcheck. Tested only against fake output written from the manuals: dinit, OpenRC, runit, xbps, apt, dnf, restic,
borg, rootful Docker, MISRA C through cppcheck (not installed here), and the `sudoers` parser. Not covered at all: Windows and macOS hosts, BSD.

## 4. Options

A **section** line is written as `name key=value ...` and every option must be stated, so nothing is implied (`judged config check` lists the
missing ones). An **item** line (`tls`, `contract`, ...) is one thing per line and its options are written on that line. `judged config template`
prints a file with all of them; `judged.example.conf` shows a filled one.

### Notifications

| Option | Type | Default | Meaning |
|---|---|---|---|
| `lead_days` | ints | 30,14,7,1 | days before an expiry on which one alert is sent (one alert per band, not one per run) |
| `urls` | list | empty | Apprise notification URLs; they hold tokens, so prefer `urls_file` |
| `urls_file` | str | empty | file with one Apprise URL per line, mode 600 (also `~/.config/judged/notify` or the `JUDGED_NOTIFY` variable) |
| `via` | str | auto | auto|notts|apprise |
| `notts` | str | notts | name or path of the notts program used when `via` is `notts` |

### Company

| Option | Type | Default | Meaning |
|---|---|---|---|
| `regions` | list | empty | regions whose legal duties are listed by `judged obligations` (UK, PL, EU, ...) |
| `mail_domains` | list | empty | domains checked for SPF and DMARC |

### Secrets and leaks

| Option | Type | Default | Meaning |
|---|---|---|---|
| `repos` | list | empty | folder globs searched for secret-named files, token shapes, `.gitignore` coverage and your own names |
| `history` | bool | 1 | also search git history (on by default |
| `scan_paths` | list | empty | extra folders searched as text (chat logs, notes) |
| `extra_terms` | list | empty | words that must never appear in a public repo (internal code names) |
| `entropy` | bool | 1 | also flag long random-looking strings with no keyword next to them (to review) |
| `max_file_mb` | int | 1 | text files are read up to this size, bigger ones and binary files are listed as not scanned |
| `emails` | bool | 1 | warn about e-mail addresses in files (personal data), shown masked |
| `email_accept` | list | empty | addresses or domains you publish on purpose |

### Licences you use

| Option | Type | Default | Meaning |
|---|---|---|---|
| `envs` | list | empty | Python environments (globs) to classify |
| `deny` | list | empty | licence labels that fail the audit |
| `reviewed_packages` | list | empty | ones a person approved |

### Dependencies

| Option | Type | Default | Meaning |
|---|---|---|---|
| `projects` | list | empty | folder globs with lockfiles; each gets a vulnerability result (OSV), an exploited-list result (CISA) and a licence result |
| `deny` | list | empty | licence labels that make the dependency licence result fail (falls back to `licences deny`) |
| `max_lookups` | int | 300 | most packages whose licence is looked up per project; the rest are said to be skipped |

### Flatpak

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 1 | audit Flatpak apps |
| `accept` | list | empty | `APP=KEY` pairs (or `*=KEY`) that stay visible but stop counting |
| `ignore` | list | empty | app ids left out |
| `leftovers` | bool | 1 | report orphaned data and unused runtimes |

### Containers

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 0 | audit podman/docker |
| `projects` | list | empty | folders with Dockerfiles/compose |
| `accept` | list | empty | `NAME=KEY` pairs (`privileged`, `cap:SYS_ADMIN`, `net:host`, `socket:PATH`, `unpinned`, ...) that stay visible but stop counting |
| `max_image_age_days` | int | 180 | images older than this are flagged |
| `scan` | bool | 1 | vulnerability scan of images with trivy |
| `max_scan_mb` | int | 1000 | images larger than this are not scanned by trivy (result `unknown`) |
| `max_images` | int | 10 | most images scanned per run |

### `tls HOST` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `port` | int | write it on the line | port to connect to (default 443) |
| `name` | str | write it on the line | label shown in the report instead of the host |

### `gpg` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `homedir` | str | write it on the line | GnuPG home folder to read keys from |

### `domain HOST` line

No options.

### `site HOST` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `images` | bool | write it on the line | also report page images that are not WebP (set to 0 to leave out) |

### `date NAME YYYY-MM-DD` line

No options.

### `waive ID YYYY-MM-DD` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `owner` | str | write it on the line | person who decided; a waiver without owner and reason is ignored |
| `reason` | str | write it on the line | why the vulnerability is accepted |
| `package` | str | write it on the line | limit the waiver to one package name |

### `licence NAME YYYY-MM-DD` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `cost` | float | write it on the line | price per term; an unknown cost counts as 0, so totals are a floor |
| `currency` | str | write it on the line | currency of `cost`; totals are per currency, never converted |
| `vendor` | str | write it on the line | who sold it |
| `owner` | str | write it on the line | who renews it |
| `auto_renews` | bool | write it on the line | 1 = renews by itself unless cancelled |

### `obligation ID` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `last_done` | date | write it on the line | date the periodic duty was last done; the next due date follows from the duty's cadence |

### `renew HOST` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `name` | str | write it on the line | label in the report |
| `cmd` | argv | write it on the line | your renewal command (certbot, lego, acme.sh, a script); judged does not speak ACME |
| `reload` | argv | write it on the line | command run after a successful renewal (reload the web server) |
| `when_days` | float | write it on the line | start renewing when fewer days than this are left |
| `min_interval_hours` | float | write it on the line | wait between retries (default 6) |
| `port` | int | write it on the line | port the served certificate is read from |
| `cafile` | str | write it on the line | CA file for hosts behind a private CA |
| `homedir` | str | write it on the line | GnuPG home folder (for `gpg:FINGERPRINT` entries) |
| `extend_by` | str | write it on the line | GPG only: new expiry as `2y`, `6m`, `30d` or a date |
| `timeout` | int | write it on the line | seconds the renewal command may run |

### `include PATH` line

No options.

### `check NAME` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `cmd` | argv | write it on the line | your command; exit 0 = pass, 1 = fail, `warn_exit` = warn, anything else, a timeout or a missing program = unknown |
| `maps` | maps | write it on the line | controls the result counts as evidence for, e.g. `ce:firewalls,iso27001:A.8.20` |
| `warn_exit` | int | write it on the line | exit code that means warn (default 2) |
| `timeout` | int | write it on the line | seconds the command may run |

### `framework ID NAME` line

No options.

### `control FRAMEWORK ID TITLE` line

No options.

### `duty ID` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `region` | list | write it on the line | regions the duty applies to |
| `framework` | str | write it on the line | framework the duty belongs to |
| `title` | str | write it on the line | what to do |
| `cadence_days` | int | write it on the line | repeat every this many days (periodic duties) |
| `deadline` | str | write it on the line | time allowed after an event, e.g. `72h` (event duties) |
| `verify` | str | write it on the line | what to check to know it was done |
| `reviewed` | date | write it on the line | date a person checked this entry against the official text; without it the entry stays marked unreviewed |

### Public lists

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 1 | use public lists (CISA known-exploited vulnerabilities, ...) in the checks |
| `online` | bool | 1 | download them when older than max_age_days (a plain GET, nothing about you is sent), off = use only the cached copy |
| `max_age_days` | int | 7 | a cached list younger than this is used without downloading |
| `skip` | list | empty | list names to leave out |

### Host hardening

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 1 | run the audits in judged/hardening |
| `skip` | list | empty | audit names to leave out |
| `accept_ports` | list | empty | listening ports you know about |
| `sysctl_accept` | list | empty | kernel settings you chose to leave |
| `suid_paths` | list | /usr,/etc | folders scanned for setuid and world-writable files |
| `suid_accept` | list | empty | path globs of setuid files you reviewed |
| `sudoers_accept` | list | empty | text of sudo rules you reviewed |
| `ssh_strict_forwarding` | bool | 0 | 1 = warn when sshd allows both agent and TCP forwarding |
| `ssh_dir` | str | ~/.ssh | folder with your SSH keys |
| `ssh_key_max_age_days` | int | 730 | key files older than this are flagged for rotation |
| `ssh_min_rsa_bits` | int | 3072 | smallest RSA key accepted |
| `ssh_keys_accept` | list | empty | private key file names allowed without a passphrase |

### AI agents

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 1 | run the audits in judged/agentchecks |
| `repos` | list | empty | folder globs whose project settings, .mcp.json, instruction files and .env files are read (your home files are always read) |
| `skip` | list | empty | audit names to leave out (claude, mcp, instructions, envkeys) |
| `mcp_accept` | list | empty | MCP server names you approved: when the list is not empty, any other server is a warning |

### GitHub account

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 0 | ask GitHub through `gh api` (needs `gh auth login` |
| `owner` | str | empty | user or organisation (empty = the logged-in user) |
| `skip` | list | empty | repository names or globs |
| `max_repos` | int | 100 | most repositories examined; the rest are counted as skipped |
| `token_warn_days` | int | 14 | limits |
| `deploy_key_max_age_days` | int | 365 | limits |
| `secret_max_age_days` | int | 365 | limits |
| `deploy_keys_accept` | list | empty | repo/title of keys that may stay read-write or old |

### Malware scan

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 0 | scan paths with ClamAV (slow) |
| `paths` | list | empty | folders scanned (one clamscan run for all) |
| `database` | str | empty | folder with ClamAV signatures |
| `max_db_age_days` | int | 3 | signatures older than this turn a clean result into a warning |
| `timeout` | int | 3600 | seconds the scan may run |
| `exclude` | list | empty | regular expressions of paths to skip |
| `max_filesize_mb` | int | 100 | files larger than this are not scanned |
| `accept` | list | empty | signature names a person reviewed |

### Backup evidence

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 0 | check the newest backup |
| `tool` | str | folder | folder/restic/borg (one file each in judged/backups) |
| `repo` | str | empty | path or URL |
| `password_file` | str | empty | restic password file (borg: set BORG_PASSCOMMAND in the environment) |
| `max_age_hours` | int | 36 | the newest backup must be younger than this |
| `must_include` | list | empty | folders the newest backup must hold (restic only) |
| `restore_tested` | str | empty | date of your last restore test YYYY-MM-DD |
| `restore_tested_file` | str | empty | a file whose first word is that date, written by the tool that did the restore test (the newer date counts) |
| `restore_max_age_days` | int | 365 | a restore test must be younger than this |

### File integrity

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 0 | compare paths with the baseline made by `judged integrity init` |
| `paths` | list | empty | folders in the baseline |
| `exclude` | list | empty | globs (names or paths) to skip |
| `max_filesize_mb` | int | 100 | bigger files are not hashed (the result says so) |
| `max_files` | int | 200000 | limit on files in the manifest; over it the result is `unknown` |
| `baseline` | str | empty | file for the manifest (empty = in judged's state folder) |

### Links

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 0 | scan paths for broken symlinks, links into /tmp and setuid files with several names |
| `paths` | list | empty | folders searched for symlinks and hardlinks |
| `exclude` | list | empty | globs to skip |
| `max_files` | int | 200000 | limit on files examined |

### `contract NAME YYYY-MM-DD` line

| Option | Type | Default | Meaning |
|---|---|---|---|
| `type` | str | write it on the line | `contract`, `supplier`, `dpa`, `insurance` or `trademark` |
| `notice_days` | int | write it on the line | the alert is placed on end date minus this many days (the last day to give notice) |
| `auto_renews` | bool | write it on the line | 1 = renews by a whole term if not cancelled in time |
| `term_months` | int | write it on the line | length of one term, used to roll an old end date forward |
| `cost` | float | write it on the line | price of one term; summed per currency in the exposure result |
| `currency` | str | write it on the line | currency of `cost` |
| `vendor` | str | write it on the line | who the contract is with |
| `owner` | str | write it on the line | who is responsible; a missing owner is a warning |

### Coding standards

| Option | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | 0 | run the standard checkers in judged/codestd on the folders in repos (slow on big trees) |
| `repos` | list | empty | folder globs of source trees to check |
| `skip` | list | empty | standard names to leave out (misra-c, cert-c, shell) |
| `misra_rules` | str | empty | your own copy of the MISRA rule-text file (the text is MISRA's, not shipped) |
| `max_files` | int | 300 | files per standard and folder |
| `timeout` | int | 300 | seconds one tool run may take |

