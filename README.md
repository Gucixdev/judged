# judged

A command-line daemon that watches what a small company cannot afford to miss and reports it: certificates, keys, domains,
licences and contracts about to expire, and machine evidence for Cyber Essentials, ISO 27001 and GDPR. It reads and
reports; it never repairs, deletes or restores anything. Python 3.13, one optional dependency
([Apprise](https://github.com/caronc/apprise)) for notifications.

    python3 -m venv .venv && .venv/bin/pip install apprise
    .venv/bin/python -m judged config template > judged.conf     # every option, with its default
    .venv/bin/python -m judged -c judged.conf audit --framework ce

Real output on a laptop with a fresh template config (trimmed to two rows; the full table has one row per control):

    _Report as of 2026-11-25._

    ## Cyber Essentials [UNREVIEWED control list]

    1 pass, 3 warn, 1 fail

    | Control | Status | Evidence |
    |---|---|---|
    | firewalls Firewalls | pass | Host firewall: ufw is active (systemd); Listening services: only loopback |
    | malware Malware protection | warn | Anti-malware: no ClamAV service active (other products are not detected) (systemd) |

    _Automated machine evidence only. Not a certification; policy and process controls need people._

A control with no machine evidence is shown as `manual`, never as passed. Exit code 1 when something fails.

## Commands

| Command | What it does |
|---|---|
| `audit --framework ce\|iso27001\|gdpr` | evidence per control, markdown or `--json`; `--notify` sends it |
| `check --dry-run` | expiry list (certificates, keys, domains, licences, contracts), what would be sent |
| `renew --dry-run` | certificates due for renewal; runs your own ACME client |
| `obligations` | recurring and event deadlines for the regions in your config |
| `sbom`, `licences` | software bill of materials (CycloneDX, SPDX) and licence audit from lockfiles |
| `integrity`, `links` | file baseline and symlink audit |
| `diff` | what changed between two reports |
| `run --every 6` | the daemon: expiry and renewal pass every 6 hours |

## What it checks

- **Expiry:** TLS certificates, SSH and GPG keys, domains, licences, contracts with notice periods. One alert per band
  (30, 14, 7, 1 days by default), not one per run.
- **Host:** firewall, listening ports, SSH server and keys, sudoers, setuid files, kernel settings, updates, disk encryption,
  Flatpak and container sandboxes, backups (reads the evidence, does not make backups).
- **Code and secrets:** token shapes, `.env` files, high-entropy strings, e-mail addresses in files (shown masked),
  dependency vulnerabilities with CVSS severity, licences, malware scan through ClamAV.
- **Web:** certificate, headers, mail authentication (SPF, DMARC), page images that are not WebP.
- **AI agents:** Claude Code permission settings, MCP server configs, hidden characters in instruction files, provider keys
  left in plain text.
- **Public lists:** CISA known-exploited CVEs (a vulnerable dependency on it is a fail), downloaded as a plain GET, cached as JSON.
- **Code standards:** MISRA C, CERT C, shellcheck on your repos, off by default; a miss is a warning.
- **Obligations:** GDPR and other deadlines from a catalog you can edit.

Every plug-in is one file in a folder that is found automatically (`areas/`, `hardening/`, `agentchecks/`, `sbom/`,
`pkgmgrs/`, `inits/`, `renewers/`, `backups/`); a plug-in that crashes becomes one `unknown` result and the rest still run.
Every check and option: [docs/reference.md](docs/reference.md).

## Findings: fail, warn, unknown

`fail` is for what is certain (a literal key in a config, permission checks switched off). `warn` is for what depends on
your intent (an unpinned server, an e-mail address that may be public on purpose), so you decide. `unknown` means the check
could not look (no permission, tool missing); it is never reported as a pass. Secret values are never printed, only the
name and `file:line`.

## Config

One file, one line per thing: `directive args key=value`. A typo is an error with its line number, and every option must
be stated (`judged config check` lists the missing ones), so nothing is implied. `judged.example.conf` shows all of them.
Notification URLs hold tokens: keep them in `~/.config/judged/notify` (mode 600) or `JUDGED_NOTIFY`, never in the repo.

## What it can save

There is no measured saving (judged has no customer data); this is arithmetic on published figures ([docs/costs.md](docs/costs.md), and `notebooks/costs.ipynb` to type your own numbers),
to be replaced with your own. A certificate that expires unnoticed and takes 4 hours to fix costs a small firm USD 33,000 to 102,000
(USD 137 to 427 a minute, Ponemon). A contract that renews by a missed notice date costs one full term. A dependency on the CISA
list is the kind of hole behind Equifax (USD 1.38 billion settlement). Expected saving is the yearly chance of a miss times the cost: one
such outage in ten years is USD 3,300 a year, against EUR 0 for the tool and an afternoon of setup.
## Tests

    .venv/bin/pip install pytest
    .venv/bin/python -m pytest -q tests --ignore=tests/e2e

398 tests, most of them against fake command output with exact inputs; the newer modules were also mutation-tested.
`tests/e2e/` builds a clean Debian container with Python 3.13 and a local ACME test server (needs podman or docker).
A few tests read schema data from `$JUDGED_TEST_DATA` and skip when it is missing.

## Limits

The host audits are Linux only; Windows and macOS are not covered yet (planned, see todo), BSD is untested. Fake output stands in for tools that were not installed on the
development machine (restic, borg, dinit, OpenRC, runit, xbps, apt, dnf, rootful Docker), so those paths are checked against
documented formats, not real runs. The control catalog is typed from memory and marked unreviewed: this is evidence, not
certification. Scanning this repository reports its own test fixtures; that is expected.

What a miss costs, with numbers and sources: [docs/costs.md](docs/costs.md). Open work: [docs/todo.md](docs/todo.md). Finished work and how each piece was checked: [docs/done.md](docs/done.md).

Licence: MIT, see `LICENSE`.
