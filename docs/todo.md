# judged TODO

Open work only, in the order it will be done. When something is finished it is not ticked here: it moves to [done.md](done.md). Anything typed from memory stays UNVERIFIED until checked against the official text.

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

**Delivery and platforms**
- [ ] A real notification delivery test through any channel (needs a URL in `~/.config/judged/notify`, mode 600)
- [ ] Let `judged.conf` add or override controls and duties (the parser reads `framework`, `control`, `duty` lines and `include rules/*.rules` works; the merge with the shipped catalog is covered for `control` only, `duty` and `framework` overrides are not tested)
- [ ] Hosts other than Linux with pacman (apt, dnf, BSD, macOS, Windows); BSD and macOS are untested
- [ ] Put the code in a git repo and push (not done, waiting for the go-ahead)


# containers 

podman docker flatpak proxmox distrobox
