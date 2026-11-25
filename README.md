# judged

A command-line daemon that watches what a company cannot afford to miss: dates about to run out, machine evidence for
Cyber Essentials, ISO 27001 and GDPR, what is still open before a certification audit, and changes to the official texts
behind it. Every result is pass, warn or fail, and what cannot wait goes out as an alert. It reads and reports; it never
repairs, deletes or restores anything. Python 3.13; [Apprise](https://github.com/caronc/apprise) is optional, for alerts.

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

    _`pass (statements only)` rests on what people stated, with owner and proof; nothing was measured. This report is not a certificate._

Exit code 1 when something fails.

## Commands

| Command | What it does |
|---|---|
| `audit --framework ce\|iso27001\|gdpr` | evidence per control, markdown or `--json`; `--notify` sends it |
| `audit --soa` | statement of applicability: per control, what proves it, and what is open before an audit |
| `check --dry-run` | every dated item (certificates, keys, domains, licences, contracts, reviews, certifications) and the alerts that would go out, changed official texts included |
| `renew --dry-run` | certificates due for renewal; runs your own ACME client |
| `obligations` | recurring and event deadlines for the regions in your config |
| `sbom`, `licences` | software bill of materials (CycloneDX, SPDX) and licence audit from lockfiles |
| `integrity`, `links` | file baseline and symlink audit |
| `diff` | what changed between two reports |
| `run --every 6` | the daemon: expiry and renewal pass every 6 hours |

## What it checks

- **Expiry:** TLS certificates, SSH and GPG keys, domains, licences, contracts with notice periods.
- **Host:** firewall, ports, SSH, sudoers, setuid files, kernel settings, updates, disk encryption, sandboxes, backup evidence.
- **Code:** secrets and e-mail addresses (shown masked), vulnerable dependencies (CISA exploited list included), licences,
  ClamAV malware scan, MISRA C, CERT C and shellcheck (off by default).
- **Web and AI agents:** headers, SPF, DMARC, images not in WebP; Claude Code permissions, MCP configs, hidden characters.
- **People's part:** `review`, `certification` and `notapplicable` lines with owner, proof or reason; legal deadlines.
- **Official texts:** GDPR, NIS2, DORA and CRA amendments (EUR-Lex), Cyber Essentials pages, the Polish data protection
  act. A change stays `warn` until a person has read it. Your own sources are one line each.

One plug-in is one file, found automatically; one that crashes is one `unknown` result. All options:
[docs/coverage.md](docs/coverage.md); how each check works: [docs/reference.md](docs/reference.md).

## Pass, warn, fail and alerts

They live in [judged/statement.py](judged/statement.py). `fail` is certain, `warn` is for you to decide, `unknown` means it
could not look and is never a pass. A control with no evidence is `manual`; one resting on people's statements alone is
`pass (statements only)`. `check` and `run` alert once per band as a date gets close (30, 14, 7, 1 days) and once when a
watched text changes; a failed delivery is tried again. Secret values are never printed, only the name and `file:line`.

## Certification

judged measures what a machine can, records what people did, lists what is open (`audit --framework ce --soa`) and alerts
before reviews and certificates run out. It issues no certificate: a certification body does (for Cyber Essentials,
[licensed by IASME](https://iasme.co.uk/articles/what-is-the-role-of-certification-bodies-when-certifying-to-cyber-essentials/)).
The control lists are short and unreviewed, so nothing open does not mean you will pass. A changed legal text does not
become a new check by itself: a person reads it and updates the controls.

## For bigger companies: planned, not built

By impact, as an opinion rather than market research (details in [docs/todo.md](docs/todo.md)):
1. Windows and macOS host checks. 2. One view of many machines. 3. SOC 2, more ISO 27001, NIS2 Art. 21, DORA.
4. Cloud accounts, access reviews, offboarding, MFA. 5. Days open per finding, incident deadlines, supplier questionnaires.

## Config

One file, one line per thing: `directive args key=value`. A typo is an error with its line number, and every option must be
stated (`judged config check` lists the missing ones). Notification URLs hold tokens: keep them in
`~/.config/judged/notify` (mode 600) or `JUDGED_NOTIFY`, never in the repo.

## Costs

What judged saves is unknown: it has no customer data. What misses and breaches cost, with sources:
[docs/costs.md](docs/costs.md). `notebooks/run` builds a short presentation (`notebooks/out/costs.pdf`) and adds up your
own past misses, each with proof.

## Tests and limits

    .venv/bin/pip install pytest
    .venv/bin/python -m pytest -q tests --ignore=tests/e2e

440 tests, mostly against fake command output; newer modules were also mutation-tested. `tests/e2e/` needs podman or docker;
a few tests skip without `$JUDGED_TEST_DATA`. Host audits are Linux only, BSD is untested, and restic, borg, dinit, OpenRC,
runit, xbps, apt, dnf and rootful Docker were checked against documented formats, not real runs. The control catalog is
typed from memory. Scanning this repository reports its own test fixtures. Finished work: [docs/done.md](docs/done.md).

Licence: MIT, see `LICENSE`.
