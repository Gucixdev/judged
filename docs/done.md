# judged done

## Status

| Done | Not done |
|---|---|
| expiry tracker with once-per-band alerts; audit engine, 3 frameworks, host/TLS/GPG/SPF/DMARC checks; renewal supervisor verified end to end against a local TLS server; obligations calendar; 398 unit tests; `./e2e` runs a clean Debian + Python 3.13 container with no network: real TLS server, Pebble ACME, certbot, GPG, leaky repo, 25 claims, Lean proofs for bands and renewal window, AMPL optimum for the window; SPF/DMARC, site, domain expiry and Cargo dependency audit run live | real CA issuance (only Pebble); real notification delivery; everything unchecked under TODO |

## Done

Finished and checked, newest groups last. Each line says how it was checked.

- [x] AI agent audit (`[agents]`): Claude Code settings, MCP servers, instruction files with hidden characters, provider keys in rc and .env files; fail for the certain, warn for the intent-dependent; 16 tests, mutation-tested (every survivor closed). Run on this machine: 3 warnings (auto mode, broad allow rules, unpinned MCP servers), 0 failures
**Paperwork**
- [x] Contracts, DPAs, suppliers, insurance, trademarks as one item kind (`contract`): notice deadline as the alert date, auto-renewal rolled forward, cost of the next term in the failure, owner and currency required to pass, money locked in per currency. Checked live on a scratch config of four contracts; mutation-tested (22 mutants)

**Expiry and renewal**
- [x] GPG key expiry extension: `renew gpg:<full fingerprint> when_days=30 extend_by=2y [homedir=...]` (a plug-in in `judged/renewers/`, one file per kind). Only keys you name; primary key and subkeys in two gpg calls (found with a real key: `*` alone leaves the primary unchanged); reads the key back and fails when the date did not move; passphrase stays with gpg-agent; does NOT publish the key (said in the message). Verified on a throwaway key in a scratch GnuPG home, and a real-gpg test runs when gpg is installed
- [x] Expiry tracker for TLS, GPG, dates and licences, alert once per band (Lean: `lean4/Bands.lean`)
- [x] Renewal supervisor against a local TLS server; `when_days` checked against the retry cadence (Lean `Window.lean`, AMPL `ampl/window.py`)
- [x] Real ACME issuance: certbot against Pebble (the Let's Encrypt test server) inside `./e2e`, the renewed certificate is served and judged says so. Lego/acme.sh and a real CA are not tried
- [x] Domain expiry (RDAP, `[[item]] kind = "domain"`) and DNSSEC (DS record present; chain not validated)

**Secrets**
- [x] Repo scan: secret-named files, token shapes, `.gitignore` coverage, owner identity, optional history
- [x] GitHub through `gh api` (metadata only, `[github]` in the config): the token judged uses (no expiry, broad scopes such as `delete_repo`), open secret-scanning alerts (fail), repositories with scanning off (warn, private ones counted separately), read-write or old deploy keys, Actions secrets not rotated for a year (names and dates only), refused requests as `unknown`; forks and archived repos skipped and counted. Run on the real account: token without expiry and with `delete_repo`, 14 of 31 repositories without scanning, no open alerts
- [x] Links audit (`[links]`, `judged links`): broken symlinks and loops, symlinks into temp folders, setuid files with several names; report only, never repairs (decision: judged reports, a separate tool repairs). Real run on this machine: 24 of 86 symlinks in ~/.local/bin point at repositories that moved
- [x] Chat-log scan for token shapes; skipped identity terms reported as warnings
- [x] Passwords without a keyword (`entropy = yes`): long random-looking strings are listed as lines to review; hashes, UUIDs, alphabet tables, identifiers made of words, URL query ids, SRI hashes and key fingerprints are not. Measured on this machine's 20 repos: 1 uncertain line left, no false alarms in source code. Honest limit: about 10% of random 32-64 character strings lack a digit or a capital and are not flagged
- [x] Coverage is reported, never silently skipped: binary files, files over `max_file_mb` (default 1), files past the file limit and unreadable paths are one `warn` that names them (images, fonts, bytecode and links are not a gap); a history search that fails or takes over 60 s is `unknown`, history search is on by default

**Licences and SBOM**
- [x] Bought licences per year with cost totals; Python dependency licences classified against a deny list
- [x] Lockfile parsers: package-lock.json, Cargo.lock, composer.lock, go.mod, poetry.lock, uv.lock, Pipfile.lock, requirements.txt (registry packages only)
- [x] Licences for Packagist (PHP) through the Packagist API (`judged/licsources/`, one file per licence source; deps.dev is one of them). The `p2` metadata is minified (older versions inherit `license`, `__unset` removes it), checked live on monolog and symfony; a package that is not on Packagist or a version that is not listed is `unknown`, never guessed
- [x] Page images (`site HOST images=1`, on by default): front page only, same-host files only (other hosts are counted, not fetched, the limit is 40 files, the first 200 KB of each is read). `web.HOST.images` warns for every PNG, JPEG, GIF, BMP or TIFF (WebP, AVIF and SVG pass) with format and size, the size from Content-Length when the body was cut; `web.HOST.animations` warns for a GIF with more than one frame or an APNG, and says "maybe" for a big GIF whose first 200 KB show one frame. Animated WebP and `<video>` pass. No saving is promised, it depends on the picture. Unreadable files are listed and make the result `unknown`, never `pass`
- [x] Vulnerability severity and fixed-version hint (one OSV request per id, first 40 ids): the database's own label (GitHub: low, moderate, high, critical), else the CVSS v3 base score computed from the vector, else `unrated` (CVSS v4 vectors are not scored, said so). A package with a high or critical vulnerability makes the result `fail`, medium and low `warn` (my judgement of the thresholds). Fix hint = lowest fixed version above yours for exactly that package, loose number comparison. Checked: the formula against 11 published vectors and against 321 real GitHub advisories (288 agree; in the other 33 GitHub's reviewers overrode the vector's band, which is why their label wins); live on lodash 4.17.20 and minimist 1.2.0
- [x] Known vulnerabilities per package from OSV (any ecosystem OSV covers); licences from deps.dev for npm, Cargo, Go, PyPI
- [x] `pnpm-lock.yaml` (v5 to v9), `yarn.lock` (classic and Berry) and `Gemfile.lock`: parsers checked against real files on this machine (pnpm: 2337 of 2337, 4201 of 4201 entries; git and tarball sources skipped on purpose)
- [x] Vulnerability waivers: `waive GHSA-xxxx 2026-12-31 owner=anna reason="not reachable" [package=lodash]` in `judged.conf`. A waiver without owner or reason is ignored, an expired one stops counting (the finding is back), one ending within 14 days is marked, one that matches nothing any more is reported so the list cannot rot. Waived findings stay visible in the evidence (who, until when). Matches the OSV id shown in the report (not CVE aliases yet)
- [x] Licence classifier: SPDX expressions are parsed (brackets, AND binds tighter than OR, `WITH` exceptions, `+`), words go through a keyword list; a new class `restricted` (non-commercial, no-derivatives, BUSL, Elastic, proprietary) is flagged and can be denied by label (`non-commercial`, `no-derivatives`, `BUSL`, `proprietary`). Checked against all 100 ids of the local SPDX list (Arch package `licenses`) in a test. The class of a licence is still my reading, not legal advice: share-alike (CC-BY-SA, GFDL) counts as strong copyleft, a `WITH` exception softens only the linking ones we list
- [x] File integrity baseline (`judged integrity init|show|accept`) and backup evidence (newest backup, coverage, restore test; folder checked here, restic and borg from their manuals) (2026-11-24)
- [x] SSH keys audit (type, size, passphrase, mode, age, authorized_keys); init systems and package managers as plug-in files (systemd and pacman checked here; dinit, OpenRC, runit, xbps, apt, dnf from their manuals, fake output only) (2026-11-24)
- [x] Host hardening as plug-in audits: sysctl, sshd settings, setuid and world-writable files, sudoers, logging, accepted ports (2026-11-24)
- [x] SBOM export: `judged sbom` writes CycloneDX 1.5 and SPDX 2.3 from the lockfiles; formats are plug-in files (2026-11-24)
- [x] Obligations grouped by year like bought licences (`judged obligations`: overdue first, then one block per year of the due date, then no-date and event-driven ones; unknown ids in the config are named, not ignored)

**Websites and servers** (own hosts only)
- [x] `[[item]] kind = "site"`: http to https redirect, security headers, cookie flags, version disclosure, security.txt (RFC 9116)
- [x] Flatpak sandbox audit (permissions with overrides merged, remotes, updates), checked on this machine's 10 apps and with fake `flatpak` output in tests
- [x] Renewal hardened after a review: a missing or hung command, a damaged state file and a missing `apprise` no longer stop the pass for the other hosts; attempts are saved right after each host; a `renew` line without `cmd` is a config error
- [x] Flatpak leftovers, read only: data folders of apps that are no longer installed, and base runtime versions no installed app uses (candidates only; `leftovers=no` in `[flatpak]` switches it off). Never deletes
- [x] Containers: podman inspect and images, Containerfile/compose lint; checked against this machine's rootless podman and in tests
- [x] Image vulnerabilities through trivy (installed from the Arch `extra` repo; run on 3 of this machine's podman images, 4 over the size limit are listed as not scanned). grype is not packaged here and is not supported

**Delivery and platforms**
- [x] Your own rules without code: `check "name" cmd=... maps=ce:x,iso27001:A.8.13` in `judged.conf` or in a file pulled in by `include rules/*.rules`; exit 0 pass, 1 fail, 2 warn, else unknown

**Certification and official texts (2026-11-25)**
- [x] Cyber Essentials requirement by requirement: 31 lines in own words from NCSC v3.3 (April 2026, whole document read; no reuse licence found, so no text copied); `confirm=yes` so a measurement never passes a requirement alone; checks re-mapped to single requirements, and Cyber Essentials removed from what the NCSC text does not ask for (backups, disk encryption, TLS and web headers, logging, secrets, file integrity, dependency licences, agent configs, ClamAV on Linux); `judged config reviews` prints the review list. Not reviewed by a person or assessor
- [x] `review`, `certification`, `notapplicable` lines (`areas/assurance_area.py`): a statement passes only with owner and proof, overdue or never done is a fail, unknown control ids are a warning; a control resting on statements alone reads `pass (statements only)`; their dates alert like any expiry. `audit --soa`: what applies, what proves it, what is open. Tests with exact dates on the boundaries; real run on this laptop with a scratch config (SoA and `check --dry-run`)
- [x] Watched official texts (`source` lines): a short marker of what `match=` finds, `warn` until `seen=` matches, `unknown` when nothing was downloaded or the pattern finds nothing, one alert per new marker from `check`/`run`. All 7 shipped sources downloaded for real on 2026-11-25 (EUR-Lex 4 to 16 s each, the rest under 1 s); the EUR-Lex query was checked against eIDAS, which has known amendments, and it showed 32025R0327 amending the Cyber Resilience Act. A real change has not been observed yet, so the alert is tested with fakes only
- [x] `judged/statement.py`: pass, warn, fail (unknown, na), the result, the roll-up into a control, and the alert with one `deliver` used for both dates and changed sources (not for renewal messages); `controls.py` re-exports the old names. Tests for the order of the statuses and for a failed delivery being retried
- [x] Tests no longer reach the internet (`tests/conftest.py`); two end-to-end tests had been downloading from public sites

**Feeds, code standards, costs (2026-11-25)**
- Public lists cached as JSON (`judged/feeds/`, area `feeds`): CISA known-exploited CVEs; fresh, stale (warn) and none (unknown) states, atomic cache write, 30 MB limit, offline option. Tests use an injected fetch, no network.
- `deps.<name>.exploited`: a vulnerable dependency whose CVE (own id or alias) is on the CISA list is a fail, waived ones included (a waiver never hides it). Tested with fakes; not run against the live list in the suite.
- Code standards (`judged/codestd/`, area `codestd`, off by default): CERT C (clang-tidy) and shellcheck were run for real on a sample; MISRA C through cppcheck is only tested with fake output, cppcheck is not installed here. A miss is a warning.
- `docs/costs.md` (sourced figures, read from search results, not the full reports) and `notebooks/costs.ipynb`. The notebook is a 16:9 presentation: what judged does, one log-scale chart of published single-miss costs (legal maximums hatched, each row with its sample and what judged really does for it, no total), what Cyber Essentials certification brings (PPN 014, IASME insurance, the NCSC 92%, attributed to the certificate), why judged, straight answers, sources, and the user's own recorded misses (proof per entry, no figure without records). Every figure sits in `notebooks/costdata.json` with a text the notebook looks for on the source page: run 2026-11-25 in real Jupyter through `notebooks/run`, 10 of 11 confirmed, the Sophos page cannot be loaded by script (read separately). All six PDF pages, a records page with sample rows and inline slide images read by eye; all five slides show inside Jupyter (a figure without axes is silently not shown there); the PDF test run with matplotlib. The earlier guessed savings estimate and the Windows 10 rows are gone.

**Audit core (2026-11-24)**
- [x] Malware scan with ClamAV (`malware` section): detection = fail with file and signature, nothing scanned = unknown, old signatures = warn; real EICAR run, 6 mutations caught
- [x] Vulnerability waivers (`waive ID DATE owner= reason=`): invalid or expired ones do not count, unused ones are reported; 6 mutations caught
- [x] Obligations grouped by year, unknown obligation ids named instead of ignored
- [x] Audit areas: one file per kind of check in `judged/areas/`, found automatically, a crashing area becomes one `unknown`; audit output identical before and after (37 of 37 results)
- [x] Report delivery: `audit --notify` sends a summary and the full report through notts or Apprise, exit 3 when not delivered (checked with a fake notts and with the real notts 0.1.0 against a local webhook; no real phone service contacted)
- [x] Strict config: every option must be stated, `judged config template|check`, `enabled` switches for flatpak, containers, malware
- [x] `judged diff` between saved reports with a regression exit code
