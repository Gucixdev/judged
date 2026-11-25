# judged reference

Every check, option and file format. The front page is the [README](../README.md); open work is in [todo.md](todo.md), finished work in [done.md](done.md).

## What `audit` checks

Host (Linux, read-only): firewall, listening services, SSH config, disk encryption, pending updates, extra uid-0
accounts, anti-malware. Per configured TLS host: protocol version, certificate expiry, certificate lifetime,
HSTS, CAA. GPG: key algorithm, size, expiry. Each result maps to controls in `judged/catalog.conf`; a control
with no machine evidence is reported as `manual`, never as passed. This is evidence, not certification.

## Renewal

judged does not speak ACME. For each `[[renew]]` entry it reads the served certificate, and when fewer than
`when_days` are left it runs your command (certbot, lego, acme.sh, a script), runs `reload`, then reads the served
certificate again: if it did not change, that is a failure and an alert, whatever the command's exit code said.
Retries are spaced by `min_interval_hours` (default 6). `cafile` lets it check hosts behind a private CA.

## Obligations by region

`judged/catalog.conf` lists periodic obligations (Cyber Essentials certificate, ISO 27001 surveillance and
recertification, GDPR record review) and event deadlines (GDPR 72 h breach notice, NIS2 24 h/72 h/1 month,
Cyber Resilience Act 24 h). Set `regions` and `last_done` in the config; periodic ones alert like any expiry.
**The catalog is typed from memory and unverified**; each entry names what to check.

## Licences

- **Bought** (`[[item]] kind = "licence"`, with `cost`, `currency`, `vendor`, `owner`, `auto_renews`): `judged licences`
  lists them per year of expiry with cost totals; `check` alerts before expiry like any item. An unknown cost counts as 0,
  so the total is a floor.
- **Used** (`[licences] envs`): every Python dependency is classified as permissive, weak copyleft, strong copyleft or
  unknown. `deny` fails the audit, strong copyleft and unknown only warn. The classifier is a keyword heuristic, not legal
  advice. Only Python environments so far; npm, Cargo and Go are TODO.

## Secrets hygiene

`[secrets]` in the config adds to `audit`:

- **repos** (globs): secret-named files tracked or untracked-but-not-ignored (`.env`, `id_*`, `*.pem`, `*.key`, ...),
  database files, token shapes inside files, whether `.gitignore` covers the usual secret names, your own
  identity in files (username, home path, git name and email, detected at run time, never typed), and with
  `history = true` (the default) token shapes in any commit. `entropy = yes` also lists long random-looking strings that
  have no keyword next to them (lines to review, never proof). Files it could not read as text are named in a coverage warning.
  `emails = yes` (the default) warns about e-mail addresses in files, shown masked (`a***@gmail.com`) because an address is personal data;
  ssh remotes (`git@host`), noreply and `example.*` addresses are skipped, role mailboxes you publish on purpose go in `email_accept`.
- **`[github]`** (off by default): `gh api` only, metadata only. Warns about a token with no expiry date or dangerous scopes,
  fails on open secret-scanning alerts, lists repositories with scanning off, read-write or old deploy keys and Actions secrets nobody
  rotated for a year. A request GitHub refuses is `unknown`, never clean.
- **scan_paths**: plain folders, for example `~/.claude/projects` (chat logs): token shapes only.

Findings print kind and `file:line`, never the value. A hit in history or a chat log means the secret is burnt:
revoke it at the provider first, cleaning comes after. Placeholders (one repeated character, `EXAMPLE`) and quoted
`BEGIN PRIVATE KEY` headers without a key body are ignored. Identity hits are a warning: fine in a private repo,
a leak in a public one. A path that is not a git repository is reported as `unknown`, not skipped silently.

## AI agents on this machine

`[agents]` reads what an AI coding agent is allowed to do here; one file per audit in `judged/agentchecks/`, found automatically. Your
home files are always read, `repos = ~/dev/*` adds the project files of every repo. Certain problems are `fail`, things that depend on
your intent are `warn`, so the warnings are yours to decide and the failures are not hidden. Secret values are never printed.

- **claude**: `settings.json` and `settings.local.json` (user and project). `defaultMode: bypassPermissions` and `enableAllProjectMcpServers` fail;
  `auto`, `dontAsk` and `skipDangerousModePermissionPrompt` warn; an allow rule `Bash(*)` fails, `Bash(curl *)`, `Bash(sudo *)` and similar warn;
  a hook that pipes a download into a shell fails, hooks that a repository brings along warn; a literal key in `env` fails.
- **mcp**: `~/.claude.json` (global and per project), `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`. An `npx`, `uvx` or `pnpm dlx`
  server with no fixed version warns, a plain `http://` server (not localhost), a secret in the URL, in `env` or in a header fails;
  with `mcp_accept = name,name` every other server warns.
- **instructions**: `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills and commands. Bidirectional controls and tag characters (text a person cannot see)
  fail, zero-width characters and soft hyphens warn, phrases like "ignore all previous instructions" warn. A joiner inside an emoji, a flag
  and a leading byte order mark are normal.
- **envkeys**: AI provider keys (`ANTHROPIC_`, `OPENAI_`, `GEMINI_`, `GROQ_`, `HF_` ...) written out in a shell start-up file warn (fail when
  other users can read the file); in a repo `.env` they fail when git tracks it or does not ignore it.

## One readable report

`judged audit --report` writes `raport.md` (or `--report FILE`): counts first, then "Fix first", "Look at these", "Could not be checked", the fine items, then the per-framework tables. Written for people who are not admins; unknown is never shown as fine. HTML is not built yet.

## One config, nothing implied

Every option of every section must be written in the config, as `1`/`0` or `true`/`false`, a path, a number or a list (empty after `=`
means nothing). A missing option is an error that prints the exact lines to add, with the default value:
`judged config template > ~/.config/judged/judged.conf` writes a complete file, `judged config check` validates yours.
Heavy checks (flatpak, containers, malware) have an `enabled` switch. Entries that repeat (`tls`, `site`, `domain`, `licence`, `waive`,
`obligation`, `renew`, `check`) are not options and stay optional. A test fails when an area adds a config key without a default.

## What changed since last time

`judged audit --report` also saves the results as `raport-STAMP.json`. `judged diff` compares the two newest (or `--old`/`--new`):
new problems, got worse, resolved, got better, text changed, and "no longer reported" (an area switched off is NOT shown as fixed).
Exit code 1 when something is new or worse, so a cron job can alert on changes only.

## Sending the report to your phone

`judged audit --notify` writes the report (see `judged report`) and sends a SHORT summary (counts, the worst items first) with the
FULL report attached. Two doors, set by `notify via=auto|notts|apprise` (default auto = `notts` when it is on PATH, else Apprise):
`notts` is an optional notification command (many services, flood control: an unchanged failing audit is not re-sent every
6 hours); Apprise URLs stay as a fallback door. judged calls `notts send --app judged --key judged-audit --state ok|warn|fail
--body-file - --attach raport.md`. A delivery that fails is printed as `NOT SENT: <why>` and the exit code is 3 (clean audit, message
did not leave); findings keep exit 1. judged does not retry on the other door after notts answered, because notts may have delivered part
of it. judged asks for `--json` and quotes notts's own answer (`sent`, `suppressed`, `grouped`, `held`, `queued`); exit 3 from notts (queued in its outbox) is reported as NOT delivered yet. Checked with a fake `notts` and with the real `notts` 0.1.0 against a local webhook server: first `fail` sent with the file, the same `fail` again suppressed, then `ok` sent as "Resolved" without the file. No real phone service has been contacted.

## Adding a new kind of check

One file in `judged/areas/`, found automatically (`NAME`, `ORDER`, optional `SPEC` = the config lines it understands, and
`run(cfg, ctx)` returning results). `audit()`, `conf.py` and the report do not change. An area that crashes becomes one `unknown`
result and the other areas still run. The built-in areas (host, endpoints, secrets, sandboxes, malware, custom checks, software,
mail) are the examples; the audit output was compared result by result before and after the move: identical.

## Software bill of materials

```
judged sbom --project ~/dev/app                          # CycloneDX 1.5 JSON on stdout, one line of counts on stderr
judged sbom --format spdx --out ~/sbom                   # SPDX 2.3, one file per project from `deps projects=...`
```

The list comes from the same lockfile parsers as the dependency audit, every component with a package URL (purl). It says what it does NOT contain: git, path and tarball dependencies, the dependency graph, hashes and licences. A project with no lockfile gives an EMPTY list and says so, a lockfile that cannot be read is a note, never a silently shorter list. The document id is derived from the content, so the same lockfiles give the same file.

Parts are separate: the components are `judged/sbom/__init__.py`, each format is one file in that folder (`cyclonedx.py`, `spdx.py`) found by itself. A new format is a file with `NAME`, `EXT` and `render(doc)`, nothing else changes (a test drops one in). Checked against the official CycloneDX 1.5 and SPDX 2.3 JSON schemas on a real project with 46 crates, with a broken document as a negative control; that check needs the schemas downloaded by hand and is skipped where they are not there.

## Init systems and package managers

Services go through `judged/inits/`, updates through `judged/pkgmgrs/`: one file per init system or package manager, found by itself, so a Void box with dinit or a Debian server needs no change in the checks. An init system is found from PID 1 (`/proc/1/comm`). A service name is looked up under every name it is known by (`clamav-daemon`, `clamd@scan`, `clamd`, ...). If the init system or package manager has no file, or cannot be asked (daemon unreachable, tool missing), the answer is `unknown` and the report says which init it saw; it is never "not running" and never a pass.

| Init system | File | Command | Checked |
|---|---|---|---|
| systemd | `systemd.py` | `systemctl is-active` | on this machine |
| dinit | `dinit.py` | `dinitctl list` (is the daemon reachable), then `dinitctl is-started` | no, from its manual |
| OpenRC | `openrc.py` | `rc-service NAME status` | no |
| runit (Void) | `runit.py` | `sv status NAME` | no |

| Package manager | File | Command | Checked |
|---|---|---|---|
| pacman | `pacman.py` | `pacman -Qu` | on this machine |
| xbps (Void) | `xbps.py` | `xbps-install -Mun` | no |
| apt | `apt.py` | `apt-get -s upgrade` (lines `Inst`) | no |
| dnf | `dnf.py` | `dnf -q check-update` (exit 100 = updates) | no |

The unchecked ones are tested with fake command output only. Before relying on them on a real Void/Debian/Fedora box, run `judged audit` there and compare with `sv status`, `xbps-install -Mun` and so on by hand.

## Host hardening

`judged/hardening/` holds one file per audit, found by itself (same idea as `areas/` and `sbom/`). A new audit is a file with `NAME`, `ORDER` and `check(cfg, env)`; `env` is everything it may touch on the machine, so tests give it exact fake inputs. An audit that crashes becomes one `unknown`, the others still run. What cannot be read (no root, no tool) is `unknown`, never `pass`. Switch audits off with `skip=` (a name that does not exist is a warning, so a typo cannot switch nothing off).

| Audit | Looks at | Needs root |
|---|---|---|
| `sysctl` | 13 kernel settings from /proc/sys (address randomisation, hidden kernel pointers, ptrace scope, redirects, syncookies ...); `sysctl_accept=KEY` for a deliberate difference | no |
| `ssh_server` | sshd_config: empty passwords, keys switched off, X11, host-based login, more than 6 tries (root login and passwords are `host.ssh`); settings after a `Match` line are not read as global | no |
| `suid` | setuid/setgid files under `suid_paths` (default /usr, /etc) that are not on the usual list and not in `suid_accept` (globs), world-writable files and directories without the sticky bit; places it could not read are reported, so a short list is never mistaken for a clean one | partly |
| `sudoers` | `NOPASSWD` and `!authenticate` in /etc/sudoers and /etc/sudoers.d; `sudoers_accept=TEXT` for reviewed rules | yes |
| `logging` | journald/auditd/rsyslog/socklog active on any known init, journal kept across reboots (ISO A.8.15) | no |
| `ssh_keys` | private keys in `ssh_dir`: type and size (DSA and RSA under `ssh_min_rsa_bits`), no passphrase (`ssh_keys_accept=NAME` for a deliberate CI key), file mode, file age over `ssh_key_max_age_days` (the file's modified time, a rough age); `authorized_keys`: same key twice, weak keys, group/world-writable file. Comments of keys (often e-mail addresses) are never printed | no |

`accept_ports=22,8080` lists the ports `host.ports` should not report. The lists (which settings, which setuid names are "usual") are my judgement from common hardening guides, not a standard. On this machine: sysctl, ssh and the scan run for real (10 s for /usr and /etc); `sudoers` answers `unknown` because /etc/sudoers is root-only, so its parser is checked against made-up samples only.

## File integrity baseline

```
judged integrity init       # make the baseline of the folders in the `integrity` section (refuses if one exists)
judged integrity show       # what was added, changed, removed or got another mode since
judged integrity accept     # replace the baseline, after you looked at `show`
```

A manifest of path, size, mode and SHA-256 (symlinks by their target, never followed). The audit only compares: it never makes or replaces the baseline, because otherwise the first run after a break-in would approve the break-in. Files are always re-hashed, not skipped by modified time, because an attacker can put the time back. A file over `max_filesize_mb`, a folder that cannot be read or the `max_files` limit make the result `unknown` and say which, so a short list is never taken for a clean one. Changing `paths` in the config without a new baseline is a warning. The baseline file does not protect itself: keep it on another disk or give `baseline=` a path that only root can write.

## Backup evidence

`backup enabled=1 tool=restic repo=/mnt/backup/restic password_file=~/.config/restic/pw max_age_hours=36 must_include=/home/user,/etc restore_tested=2026-10-01 restore_tested_file=~/.local/state/judged/restore.stamp`

Three results: the newest backup is not older than `max_age_hours`; the newest backup holds every folder in `must_include` (only when the tool can say, which restic can and borg and a plain folder cannot: then it is `unknown`, not a pass); and a restore test no older than `restore_max_age_days`. `restore_tested_file` is a file whose first word is a date, written by the tool that restored a file and compared its hash (judged never restores anything itself); the newer of the two dates counts, a missing or empty file is said. Without any date it is a warning: a backup that was never restored is a hope, not evidence (ISO 27001 A.8.13). judged only reads the list of snapshots. One file per tool in `judged/backups/` (`folder`, `restic`, `borg`); only `folder` was run for real here, restic and borg are tested with output written from their manuals. Borg prints local times without a zone; judged reads them as this machine's local time.

## Links

`[links]` lists what the links in chosen folders really are. `judged links` prints every symlink with its state (`OK`, `BROKEN`, `LOOP`) and every file that has several names; the audit reports:

- **broken symlinks and loops** (warn, with the target they point at),
- **symlinks into `/tmp`, `/var/tmp`, `/dev/shm`** from a folder outside them (anyone can replace the target there),
- **files with several names (hardlinks)**: a plain count is fine, a setuid or setgid file with a second name is a warning (an update of one name leaves the old program reachable under the other). A hardlink cannot "break": it is just another name, so there is nothing to report as dead.

A link that cannot be followed for permission is `unknown`, never "broken" and never "fine". **judged only reports.** It never repairs, replaces or deletes a link: fixing is the job of a tool that is allowed to change things (a separate tool; such a tool may call judged, never the other way round).

## Contracts and notice periods

`contract "Hosting" 2027-03-31 type=supplier notice_days=90 auto_renews=1 term_months=12 cost=24000 currency=EUR owner=anna`

The date that costs money is the last day to give notice, not the end of the term. The alert (same bands as every other item) is placed on `end - notice_days`. After that day an auto-renewing contract is locked in for another term: the result fails and says what that term costs. With `auto_renews=1` an end date in the past is rolled forward by whole terms (and the result says so, because the real date should be written down). A contract that ended and does not auto-renew fails. `type` is `contract`, `supplier`, `dpa`, `insurance` or `trademark`; the first three map to GDPR Art. 28 and ISO 27001 A.5.19/A.5.20 (typed from memory, UNVERIFIED like the rest of the catalog). A missing owner or a cost without a currency is a warning; `paperwork.exposure` adds up the cost of auto-renewing contracts that are past or near their deadline, one total per currency, never converted.

## Malware scan

Opt in, because scanning is slow: `malware paths=~/work,/srv/uploads database=~/.local/state/judged/clamav` in `judged.conf`
(more keys: `max_db_age_days` 3, `timeout` 3600 s, `exclude` regexes, `max_filesize_mb` 100, `accept` = signature names you reviewed).
judged runs `clamscan` ONCE for all folders (it loads 3.6 million signatures each start, about 10 s) and reads the answer carefully:
a detection is `fail` and names file and signature (nothing is moved or deleted); an unreadable or missing folder, an empty folder, a
timeout, a scanner error and "0 files scanned" are all `unknown`, never `pass`; signatures older than `max_db_age_days` turn a clean
result into `warn`. Without a database judged says how to get one (`freshclam` as root fills `/var/lib/clamav`; as a user point
`database=` at a folder you fill with `freshclam --datadir`). Checked on this machine with the real EICAR test file, a clean, an empty
and a missing folder, and with a unit test that runs real clamscan when it is installed (EICAR is built at run time, never stored).
The host check `Anti-malware` (is a ClamAV service running) stays as it was.

## Flatpak and containers

Opt in with a `flatpak` and/or a `containers` line in `judged.conf`. Both only read; nothing is changed.

    flatpak accept=*=socket:session-bus ignore=org.some.App
    containers projects=~/dev/*,~/work/* accept=web=cap:SYS_ADMIN,*=unpinned max_image_age_days=180

- **Flatpak**: for every installed app it reads `flatpak info --show-permissions`, merges the global and the per-app
  override over it (a `!x` removes `x`; conditional `if:` entries are not counted), and judges the result. Wide
  permissions are `fail` or `warn`: full session bus, talking to `org.freedesktop.Flatpak` or systemd (can start
  commands on the host), the whole host or home file system, credential directories (`~/.ssh`, `~/.gnupg`, `~/.aws`,
  ...), ssh-agent and gpg-agent, `devices=all`, `features=devel`, X11 without Wayland, the keyring. It also checks that
  no remote has signature checks off and counts pending updates (unknown when offline). A finding that your global
  override grants to every app says so in the evidence. `accept=APP=KEY` (or `*=KEY`) keeps a finding visible but
  stops it counting.
- **Containers** (`podman`, else `docker`): rootless or not; per container (running or stopped) privileged, added
  capabilities, host network/PID/IPC, mounted runtime socket or host directories, unconfined security options, root
  inside a rootful runtime, ports published on every interface, images not pinned to a version; image age. Image
  vulnerabilities go through `trivy` (`podman save` to a temp tar, `trivy image --input`, HIGH and CRITICAL): critical
  is `fail`, high is `warn`, an image trivy cannot read (scratch, distroless, too big, scan error, no trivy) is `unknown`,
  never `pass`. Keys: `scan=no`, `max_scan_mb` (default 1000), `max_images` (default 10); `accept=NAME=vulns`.
  Only trivy's own database download touches the network.
  `accept=NAME=KEY` takes one finding: `privileged`, `cap:SYS_ADMIN`, `net:host`, `pid:host`, `ipc:host`, `socket:PATH`,
  `mount:PATH`, `secopt:seccomp=unconfined`, `root`, `port:80/tcp`, `unpinned`; `*` matches any name or any key.
- **Files** in the `projects` paths: Dockerfile, Containerfile and compose files, checked line by line (no YAML or
  Dockerfile parser): unpinned `FROM`, no `USER`, `ADD` of a URL, download piped into a shell, literal secrets in
  `ENV`/`ARG`/environment (the value is never printed), `chmod 777`, `privileged`, `network_mode: host`, the runtime
  socket, ports on every interface, risky capabilities.

The fail/warn thresholds are my judgement from `flatpak-metadata(5)` and common container hardening advice, not a
standard and not reviewed; accepted risk is the intended way to say "known and fine".
