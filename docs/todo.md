# judged TODO

Open work only, in the order it will be done. When something is finished it is not ticked here: it moves to [done.md](done.md). Anything typed from memory stays UNVERIFIED until checked against the official text.

What each item costs when missed, and the order by money: [costs.md](costs.md). Online public lists (CISA KEV, EPSS, endoflife.date, SPDX licences, Certificate Transparency) cached as JSON under `<state>/feeds/`: first one (KEV) is written, wiring into deps and the rest are below.

**For bigger companies** (order of impact, same as in the README; the details are in the sections below)
- [ ] Windows and macOS host checks (see Windows and macOS)
- [ ] One view of many machines: collect the `audit` reports of a fleet, group by owner, show what got worse
- [ ] SOC 2, more ISO 27001 Annex A ids, NIS2 Art. 21, DORA (see Inspirations)
- [ ] Cloud accounts, access reviews, offboarding, MFA evidence
- [ ] Days open per finding, `judged incident start TIME`, supplier questionnaire (see Inspirations)

**Certification and official texts**
- [ ] Cyber Essentials requirement by requirement from the NCSC document (v3.3, April 2026) instead of five coarse controls: each requirement mapped to a check or a `review`; check the document's reuse terms first (it says Crown Copyright, no licence found yet)
- [ ] More watched sources: UK acts (no stable marker found yet in the legislation.gov.uk feed), authority guidance (EDPB, UODO), EUR-Lex corrigenda, the Polish NIS2 act
- [ ] SPDX licence list, endoflife.date (both answered on 2026-11-25): wire into the checks (listed under Online feeds)

**Expiry and renewal**
- [ ] Built-in ACME backend through the `acme` library (RFC 8555, HTTP-01 and DNS-01); Pebble is already in `./e2e`, so only the code is missing
- [ ] DNSSEC chain validation and DS/DNSKEY expiry (RRSIG validity)
- [ ] Certificate Transparency watch (crt.sh): certificates issued for your domains that you did not request

**AI agents**
- [ ] Agents, next: inventory of AI providers a project uses (lockfiles and endpoint hosts) against an `approved` list, cross-checked with a DPA contract (Art. 28); EU AI Act duties as `unverified` catalog entries; Codex, Gemini CLI, Windsurf and Claude Desktop config paths (formats assumed, files not on this machine); MCP tool descriptions with hidden instructions need the servers running, so they are not read

**Secrets**
- [ ] GitHub: organisation-wide personal access token listing (needs org admin), Dependabot alerts, branch protection
- [ ] Lean/AMPL for the placeholder heuristic (distinct-character threshold is a guess, not measured)

**Licences and SBOM**
- [ ] More lockfiles: Maven pom.xml and gradle.lockfile (Java), packages.lock.json (NuGet), pubspec.lock (Dart), Package.resolved (Swift), mix.lock (Elixir), conan/vcpkg (C and C++). No real sample of these on this machine yet, so none is typed from memory
- [ ] Containers and OS packages (images, apt/rpm lists): needs syft or trivy, not installed here

**Compliance content**
- [ ] Verify `catalog.conf` control ids and titles against official texts (Cyber Essentials and GDPR are public; ISO is paid, ids only)
- [ ] Verify the duties in `catalog.conf` and set `reviewed` dates; add more regions (UK, US states) and frameworks (DORA, SOC 2, HIPAA, PCI DSS)
- [ ] GDPR records of processing (Art. 30) and breach notification (Art. 33) as checklists with owners and dates
- [ ] Access reviews: accounts, keys, offboarding
- [ ] Logging, sudoers and MFA evidence (backup restore tests: see Backup and integrity)
- [ ] Consume OSCAL catalogs where an official one exists

**Websites and servers** (own hosts only)
- [ ] More page checks in the same pass (ideas, none started): images without `alt`, mixed content (http assets on an https page), missing compression (gzip/br) and cache headers on assets, total page weight, internal links that return 404, `robots.txt` and `sitemap.xml` present, favicon present, images much larger than shown (needs a browser, so probably out)
- [ ] Page assets only look at the front page and at images (img, picture, video poster, CSS `url()` in style attributes); images set from external stylesheets or by script are not seen, and the result says nothing about them
- [ ] TLS protocol versions and cipher suites, mixed content, certificate chain problems (use testssl.sh or sslyze, not our own)
- [ ] Docker (rootful) is untested: this machine has only podman, the `docker info` and `docker inspect` JSON shapes are assumed to match podman's; also the docker group (root-equivalent) is not checked
- [ ] Per-app Flatpak overrides and `--system` installations are untested here (no per-app override exists, every app is a user install); whether `flatpak info --show-permissions` already includes overrides is not verified, merging twice is harmless
- [ ] Flatpak: end-of-life runtimes and apps, known vulnerabilities of the runtime (no source wired in), Flathub verification status
- [ ] SBOM of images, signature checks (cosign), registry credentials in `~/.docker/config.json` and `auth.json`, trivy misconfiguration and secret scanning of images, `--ignore-unfixed` option
- [ ] A real Dockerfile and compose parser (multi-line `RUN`, `include`, extends, env files) instead of the line-based lint; hadolint as an optional backend
- [ ] Kubernetes manifests and Helm charts, Snap, AppImage, systemd-nspawn, LXC
- [ ] Open ports and exposed services of your own servers (nmap is installed; scope must be written in the config)
- [ ] CMS and plugin versions (WordPress, Drupal, Joomla) against known vulnerabilities
- [ ] Privacy paperwork on the page: privacy policy, cookie banner, imprint where the law asks for one (region dependent)
- [ ] Server patch level over SSH (kernel, packages) and reboot-needed flag
- [ ] Cloud accounts: access key age, public buckets, unused users (AWS, GCP, Azure)
- [ ] Uptime of the checked hosts (a check that cannot connect is reported, but there is no history)

**Paperwork**
- [ ] Licence cost currency and a yearly budget view across currencies
- [ ] Reminders to a named owner instead of one global channel

**One combined file**
- [ ] `judged bundle`: ONE separate JSON file that holds everything machine-readable together (SBOM components, audit results, waivers, diff against last time, scan evidence), for now they stay separate files. Each part is contributed by its own module (like `areas/` and `sbom/`), so a new kind of data adds a section and changes nothing else

**Backup and integrity**
- [ ] Backup: restic and borg are tested with fake output only (neither is installed here); run against a real repository, add more tools (rclone, duplicity, kopia, btrfs/zfs snapshots) as files in `judged/backups/`; read the stamp file that a restore-test tool writes after a verified restore (`restore_tested_file=`, instead of a hand-written date): judged does not restore anything itself
- [ ] Integrity: watch a changing folder without noise (rules by path), compare against the package manager's own file hashes (`pacman -Qkk`, `debsums`)

**More host audits**
- [ ] Run `judged audit` on a real Void (runit/dinit, xbps), Debian and Fedora machine and compare with the manual commands; more init systems (s6) and package managers (zypper, apk, emerge): each one a file
- [ ] SSH client config and `authorized_keys`, firewall rules (listing needs root), unattended-upgrade state, mount options (noexec/nosuid), core dumps, password policy, sudoers checked as root
- [ ] Diff of the config itself (`judged config diff` against the template, to see which options still have their default)

**Mail**
- [ ] Antispam and mail hygiene of YOUR mail server: Rspamd/SpamAssassin running and their rules fresh, your sending IP on public blocklists (DNSBL), open relay test, greylisting, ClamAV in the mail path
- [ ] Malware: rkhunter (its log is root-only here, so judged would read it as root), a second engine (YARA rules), scan of containers and Flatpak data folders, scheduling and a daily summary
- [ ] DKIM (needs selectors), MTA-STS, TLS-RPT, BIMI; SPF lookup-count limit

**Online feeds** (plain GET of public lists, nothing about you is sent; cached JSON, stale cache used with a warning when offline)
- [ ] Wire KEV into `deps.project` and `areas/software.py`: `deps.<name>.exploited` fails when a vulnerable package's CVE is in KEV
- [ ] EPSS scores (exploit probability) next to CVSS
- [ ] endoflife.date: product and version past or near end of life, for the OS, runtimes and containers found on the host
- [ ] SPDX licence list: licence ids and OSI/deprecated flags instead of the hand-typed table
- [ ] Certificate Transparency (crt.sh): certificates issued for your domains that you did not request; new subdomains
- [ ] Tests for the feeds package (injected fetch: fresh, stale, none, corrupt cache, atomic write, 30 MB limit) and mutation run

**Windows and macOS** (most staff machines at a company run these, so this is high priority)
- [ ] Find out what already works off Linux: expiry (certificates, domains, contracts), web checks, secrets and e-mail scan, dependency and licence audit, notifications are plain Python and should run; list what breaks (paths such as `/proc`, `/etc`, `~/.config`, file modes, `which`)
- [ ] An `Env` for each OS so the hardening plug-ins stay one file each and tests keep using fakes
- [ ] Windows checks, read-only through PowerShell: Defender state and signature age (`Get-MpComputerStatus`), firewall profiles (`Get-NetFirewallProfile`), BitLocker (`manage-bde -status`), Windows Update pending and last install, SMBv1 off, local administrators, RDP enabled and NLA, guest account, PowerShell logging, end-of-life Windows build (Windows 10 support ended 2025-10-14, extended updates cost per device, see docs/costs.md)
- [ ] macOS checks: FileVault (`fdesetup status`), firewall (`socketfilterfw --getglobalstate`), Gatekeeper (`spctl --status`), SIP (`csrutil status`), pending updates (`softwareupdate -l`), supported macOS version, XProtect age, remote login
- [ ] Windows and macOS config paths for the AI-agent audit (Claude Desktop, Cursor, VS Code MCP files)
- [ ] Cannot be verified on the development machine (Linux only): fakes with documented command output first, then a real run by someone with the machine, marked as such in done.md

**Notebook** (Jupyter; optional, nothing in judged depends on it)
- [ ] `notebooks/audit.ipynb`: read `judged audit --json` and show status per control with filters
- [ ] A static `costs.html` twin that opens from a file manager without Jupyter (needs rates typed in or a CORS-enabled rate API; decide)

**Code standards** (first three are written in `judged/codestd/`: MISRA C through cppcheck, CERT C through clang-tidy, shellcheck; a miss is always a warning; there will be far more standards than these, so each stays one file in that folder). Names and numbers below are typed from memory: UNVERIFIED until checked against the owner's text.
- [ ] Verify the MISRA path on a machine with cppcheck (not installed here): `--addon` JSON with `--rule-texts`, rule ids `misra-c2012-N.N`; MISRA C:2023 and MISRA C++:2023 ids
- [ ] **C**: ISO/IEC 9899 conformance (`-std=c89|c99|c11|c17 -pedantic-errors`, what people call ANSI C is C89/C90, ANSI X3.159-1989 adopted as ISO/IEC 9899:1990), ISO/IEC TS 17961 (secure C), CWE Top 25 patterns, compiler warnings as a standard (`-Wall -Wextra -Wconversion`), sanitizer build result as evidence
- [ ] **C++**: MISRA C++:2023, AUTOSAR C++14, SEI CERT C++, C++ Core Guidelines (clang-tidy `cppcoreguidelines-*`), ISO C++ conformance flags
- [ ] **Python**: PEP 8 and PEP 257 (ruff or flake8), PEP 484 typing (mypy or pyright strict), bandit (security), pylint; **JS/TS**: ESLint, `tsc --strict`; **Rust**: clippy, `cargo audit` and `cargo deny`, count of `unsafe`; **Go**: `go vet`, staticcheck, gosec; **Java**: SEI CERT Java, SpotBugs; **Shell**: POSIX sh conformance (checkbashisms); **Dockerfile**: hadolint; **SQL**, **Terraform and other infrastructure code**: tflint, checkov
- [ ] **General rules, not tied to a language**: function length, nesting depth, cyclomatic complexity, file size, duplicated blocks, commented-out code, TODO age, public functions without a doc comment. Design principles (composition over inheritance, YAGNI, DRY, abstraction level) are judgement, so only measurable proxies are checked and every one is a warning the team can answer
- [ ] **Profiles**: a standard set per language and a global one, as plain files (`standards/*.rules`) the team edits; a rule can be switched off for the whole tree, for one language or for one folder, and the switch is listed in the report (nothing is hidden)
- [ ] **Deviations**: a rule broken on purpose is recorded like a waiver (rule, place, reason, owner, expiry), as MISRA asks for formal deviations; expired ones count again
- [ ] **Baseline** for an old code base: findings that existed at the start are shown as their own count next to the new ones, never dropped
- [ ] **Safety and quality standards that require a coding standard** (evidence mapping only): ISO 26262 (road vehicles), IEC 61508 (functional safety), IEC 62304 (medical device software), DO-178C (airborne), ISO/IEC 25010 and ISO/IEC 5055 (source code quality measures), ISO/IEC 27034 and OWASP ASVS (application security), NIST SP 800-218 SSDF, SLSA, OpenSSF Scorecard
- [ ] Rule texts: MISRA is a paid document (never shipped, user points at their copy); CERT and C++ Core Guidelines are free to read; record the licence of each rule source in its file header
rust go python php java javascript typescript im wiecej jezykow pokryc tym lepiej 


**Delivery and platforms**
- [ ] A real notification delivery test through any channel (needs a URL in `~/.config/judged/notify`, mode 600)
- [ ] Let `judged.conf` add or override controls and duties (the parser reads `framework`, `control`, `duty` lines and `include rules/*.rules` works; the merge with the shipped catalog is covered for `control` only, `duty` and `framework` overrides are not tested)
- [ ] Other Linux package managers and BSD (apt, dnf are written against documented formats; BSD untested)
- [ ] Put the code in a git repo and push (not done, waiting for the go-ahead)


# containers 

podman docker flatpak proxmox distrobox
judged powinien ogarniac kryptografie czy komunikacja jest bezpieczna czy jest p2p czy jakiejs zabezpieczenia 
czy nie sa wystawione na atak czy podsluch szyfrowanie stron internetowych jest zgodne nie jest przestarzale i zgodne z standardem 
i bazy danych rowniez XD w pelni skan czy wszystko gra audyty papierkowe etc XD 










**Inspirations (2026-11-25)** (from [inspirations.md](inspirations.md); matches for cairn, compAI, trustwatch and expiryradar are guesses, see there; AGPL sources are technique only, MIT sources may be copied with the notice)
- [ ] First-seen date per finding kept in the state folder, and "days open" in the report; a high or critical finding open more than 14 days is a `fail` for Cyber Essentials (security-controls-metrics, e8mate). Mean time to fix and overdue count per owner come after that
- [ ] Controls added to `catalog.conf` with ids from the official texts and a map from the checks that already exist: SOC 2 trust criteria (CC6 access, CC7 operations, A1 backup), more ISO 27001 Annex A ids, NIS2 Art. 21 measures, DORA; mark all `unverified` (probo)
- [ ] NIST CSF 2.0 and CIS Controls v8 as extra mapping targets for `maps=` (security-controls-metrics)
- [ ] ASD Essential Eight as a framework (`--framework e8`): the eight strategies with maturity level 1 checks; maturity per strategy = highest level whose checks all pass, overall = lowest; ASD outcome names mapped to judged statuses; text typed from the ASD maturity model, `unverified` until read (e8mate)
- [ ] Essential Eight gaps on Linux: allowlisting state (fapolicyd, AppArmor or SELinux enforcing), patch age in days after a fix exists, backup copy stored apart from the machine and not writable by normal accounts, age limit tied to a stated recovery point, GitHub 2FA for the account and organisation members as the first MFA evidence (e8mate)
- [ ] Device checks missing next to the existing host audit: screen lock timeout (GNOME, KDE, sway, i3), time sync (chrony, systemd-timesyncd), password policy (`PASS_MAX_DAYS`, pam_pwquality), `/etc/shadow` permissions, unattended updates switched on (probo device agent, security-controls-metrics)
- [ ] A starter list of `review` lines to copy: risk assessment, internal audit, management review, disaster recovery test, penetration test, security training, access review, policy review, offboarding checklist, mapped to the right controls (probo, compAI)
- [ ] Supplier questionnaire: weighted questions, must-have answers that block approval, answers file per supplier, score and decision in `paperwork`; questions mapped to ISO 27001 A.5.19 to A.5.23 and GDPR Art. 28 (security-controls-metrics)
- [ ] `judged incident start TIME`: prints every statutory deadline from the catalog (GDPR 72 h, NIS2 24 h, 72 h, one month, DORA) as clock times; a duty with no numeric limit prints "without undue delay" and no invented hours (cairn)
- [ ] `certification ... replaces=`: the certificate this one takes over from (cairn)
- [ ] CA trust stores: system bundle and each certifi copy of the listed Python environments checked against the Mozilla CCADB removed-roots report (feed under `feeds/`) and for age of the bundle (trustwatch, Naveen-Sai-Ganadi)
- [ ] Maintainer count next to each npm and PyPI dependency result, limited by `max_lookups`; a single publisher is a warning (trustwatch, Dovakyr, no licence: idea only, nothing copied)
- [ ] Export of all dated items (expiry, paperwork, `review`) as one CSV or iCalendar file (expiryradar)
- [ ] Per-result record keeps the command that produced the evidence and the time it ran, not only the evidence text (e8mate)
