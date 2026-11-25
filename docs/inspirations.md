# Inspirations

The user listed seven names under `##inspiracje` in [reference.md](reference.md): cairn, compAI, probo, expiryradar, trustwatch, e8mate, security-controls-metrics. This file says what each one is, what judged lacks compared to it and what to take. Read on 2026-11-25 from shallow read-only clones (README and file structure; none of their code was run). Concrete items are in [todo.md](todo.md) under "Inspirations (2026-11-25)".

Licence rule: MIT and Apache code may be copied with the notice kept; GPL and AGPL code is never copied, only the technique is used.

## How sure each match is

| Name | Repository | Match |
|---|---|---|
| probo | getprobo/probo | confident |
| e8mate | boonchuan/e8mate | confident |
| security-controls-metrics | suhaibkhan916/security-controls-metrics | confident (only repo with this exact name; it maps to Cyber Essentials and ISO 27001, which fits judged) |
| compAI | trycompai/comp (Comp AI Community Edition) | probable guess |
| cairn | frousselet/cairn | guess: several other projects are called Cairn (a pentest search engine, a knowledge graph, firmware); this is the only GRC one |
| trustwatch | Naveen-Sai-Ganadi/trustwatch | guess: several repos have this name; this one is about certificate trust and fits the expiry theme. Dovakyr/trustwatch (supply chain) is the other candidate and is covered below |
| expiryradar | poudelsamip/expiryradar | weak guess: two repos have this name and neither says much. This one is a mobile app, so little follows from it |

## probo (MIT, Go and TypeScript, self-hosted GRC platform)

What it does: a risk register, a control library, vendor risk, data privacy records, access reviews, audit programs, evidence files and links, versioned documents with signatures, a public compliance page, a CLI (`prb`) and an MCP server. Frameworks ship as JSON in `apps/console/public/data/frameworks/`: SOC 2 (61 criteria), ISO 27001:2022 (123 entries), GDPR (62), DORA (65), NIS2 (17), HIPAA, PCI DSS, ISO 27701, ISO 42001, CCPA, FERPA, HDS, 21 CFR Part 11. `data/mitigations.json` holds 81 practical measures in 11 categories, each with an importance (62 mandatory, 13 preferred, 6 advanced) and a `standards` string such as `ISO27001:2022-A.5.16;SOC2-CC6.1`. A device agent (`pkg/deviceagent/checks`) runs per OS: disk encryption, screen lock, firewall, time sync, OS version, auto update, password policy, remote login, malware protection (Linux, macOS, Windows, FreeBSD).

What judged lacks:
- Frameworks: judged has 14 ISO 27001 controls, 6 GDPR articles, 31 Cyber Essentials requirement lines (5 themes when this was compared) and no SOC 2, DORA, NIS2 controls (NIS2 only as deadlines), HIPAA or PCI DSS.
- Measures that have no machine evidence and need a dated human answer: risk assessment, internal audit, management review, disaster recovery test, penetration test, security training, background checks, offboarding, policy approval. judged has only `manual` as a status and no recurring "last done" date for them.
- Device checks judged does not have: screen lock timeout, time sync, password policy, automatic updates switched on, one verdict per device.
- A Statement of Applicability (which control applies, why, and how it is met).
- Evidence as a file or link attached to a control with an owner.
- Access review campaigns (judged todo has one line for it).

Take (MIT, copy with notice allowed): the shape of `mitigations.json` (id, category, importance, standards string) and the standards mapping for the measures judged can already prove (updates, 2FA, backups, logging, clock sync, encryption, DMARC). Check every id against the official text before it enters `catalog.conf`; Probo's mapping is a third party's claim, not the standard. The SOC 2 criteria list is a list of public ids and titles; ISO titles are paid text, so only ids are kept (same rule as today).

## e8mate (MIT, Python, Essential Eight scanner for Windows)

What it does: 30 checks at maturity level 1 for the eight ASD Essential Eight strategies, collected through local PowerShell, WinRM or a mock transport. Each check has an id such as `PA-ML1-001`, a severity, raw evidence (source, command, raw output, time) and one of the ASD outcomes (effective, alternate control, ineffective, no visibility, not implemented, not applicable). Maturity per control is the highest level whose checks all pass, and overall maturity is the lowest of the eight. It lists fixes sorted by level then severity, compares two scans (`diff.py`: regressed, improved, new, removed), and maps each check to Essential Eight, Singapore Cyber Essentials and CIS Controls v8. A separate web scanner and Nuclei templates exist; they are not part of this review. ML2 and ML3 are listed as not written. Only the README, rules file and structure were read; the collectors were not checked line by line.

Mapping to judged (judged is Linux only today):

| Essential Eight strategy | What judged covers | Gap |
|---|---|---|
| 1 Application control | nothing | allowlisting state: fapolicyd, AppArmor or SELinux enforcing on Linux; AppLocker and WDAC on Windows |
| 2 Patch applications | lockfile vulnerabilities (OSV, CISA KEV), Flatpak runtimes | patch within 2 weeks or 1 month after a fix exists; unsupported applications (endoflife.date is in todo); proof that a scanner runs at least every fortnight |
| 3 Office macros | nothing | Windows and Office only; out of scope until the Windows work starts |
| 4 User application hardening | page headers and TLS of your own sites | browser policy (ads, Java, Flash), PowerShell logging; Linux has little equivalent |
| 5 Restrict admin privileges | `sudoers`, extra uid-0 accounts, SSH root and keys, GitHub token scopes | list of privileged accounts with an owner, inactive privileged accounts, admin used for mail and web (access reviews are in todo) |
| 6 Patch operating systems | pending updates through four package managers, OS end of life is in todo | patch age (days since a fix was available), automatic updates on, Windows Update |
| 7 MFA | nothing | no evidence of MFA anywhere (todo has one line); GitHub 2FA for the account and for organisation members is the first machine-checkable source |
| 8 Regular backups | newest backup age, required folders, last restore test | backup stored apart from the machine, backup not writable by normal accounts, age limit tied to a stated recovery point |

Take (MIT): the maturity rule (a level counts only when all its checks pass; overall is the minimum) as an optional view for the Essential Eight frameworks; the six outcome names mapped onto judged's statuses (no visibility = `unknown`, alternate control = a waiver with a reason, not applicable = a stated skip); the priority list sorted by level then severity; storing the command and time with each piece of evidence. judged's own `diff` already covers the scan comparison, so only the vocabulary (regressed, improved) is worth checking against it.

## compAI, Comp AI Community Edition (AGPL-3.0, TypeScript, technique only)

What it does: a self-hosted compliance platform for SOC 2, ISO 27001, HIPAA and GDPR: tasks and evidence per control, policies, vendors, people, training, offboarding checklist, background checks, risk register, statement of applicability, questionnaire answering, a trust portal, penetration test findings, cloud scans (AWS, GCP, Azure) with suggested fixes, 590 integration definitions under `integrations-catalog/`, an Electron device agent and an MCP server. A paid cloud edition exists with extra features.

What judged lacks: the same non-machine records as Probo (training, offboarding, people), cloud account scans, a questionnaire from customers that the evidence answers, and a trust page built from results.

Take as technique only: findings can be accepted with an expiry date and the expiry is a calendar day, not a timestamp (judged `waive` already does the first; its date parsing rejects 2026-02-30, which is the same trap Comp AI's code guards against). The device agent split (one check per key per OS, one verdict) matches judged's plug-in folders. Do not copy its files, schemas or the integrations catalog.

## cairn (AGPL-3.0-or-later, Python and Django, technique only; a guess)

What it does: a GRC application built around ISO 27001 clause 4 context, assets with confidentiality, integrity and availability values, ISO 27005 and EBIOS risk assessment, frameworks and audits, a nonconformity register, incident handling with statutory notification clocks (GDPR 24 h or 72 h, NIS2 24 h, 72 h and one month, DORA), documents with one version in force, controls whose effectiveness comes from validated test runs, a certificate model with expiry and a renewal chain (a new certificate supersedes the old one), and single-point-of-failure detection in the asset dependency graph.

What judged lacks: a record of your own certifications (ISO, Cyber Essentials) with expiry and the chain of renewals; an incident clock that starts from a stated time and prints each deadline; a dependency map of what depends on what.

Take as technique only: the certificate chain (judged already tracks the dates in `obligations`, but not "the certificate you hold"); the incident clock as a command (`judged incident start TIME` prints GDPR, NIS2 and DORA deadlines; the durations are already in the catalog); control effectiveness from a test run with a date, not from a status someone typed. Cairn also states that a duty with no numeric limit ("without undue delay") must not get an invented hour count; judged's catalog should say the same.

## trustwatch (MIT, Python; a guess, Naveen-Sai-Ganadi/trustwatch)

What it does: finds every trust store (system bundle, Python certifi, Node, Java cacerts, container images, programs with compiled-in roots) that still trusts a distrusted or compromised certificate authority, using Mozilla CCADB lists and a fingerprint match, and says how to fix each store.

What judged lacks: judged checks the certificates of your own hosts and their expiry; it does not look at which authorities your machine trusts, or at roots removed by Mozilla.

Take (MIT, copying with notice allowed, but small enough to rewrite): a check for the system bundle and for each certifi copy found in the Python environments judged already lists: roots removed by Mozilla (CCADB report) and a stale bundle (age of the file). Needs a feed in `feeds/`.

The other trustwatch, Dovakyr/trustwatch, has no licence file, so it is all rights reserved and nothing may be copied. Its idea is a score for how many humans must be compromised for a malicious release (maintainer count, recent publishers) per npm or PyPI dependency. judged could show the maintainer count next to the dependency results; it needs registry calls per package and a limit like `max_lookups`.

## expiryradar (MIT, Expo mobile app; weak guess)

What it does: a phone app that stores one dated item (document, warranty, subscription, insurance, vehicle), with five bands (expired, 3 days, 7 days, 30 days, later) and reminders at chosen day offsets, attachments and data export. The MIT licence file is the Expo template's.

What judged lacks: attachments and a category for personal or non-company items; judged has bands and reminders already. Little to take. One idea: a data export of all dated items as one file (judged `paperwork` has no export).

## security-controls-metrics (MIT, Python, Docker)

What it does: 12 shell checks run inside a Debian image before and after hardening, each mapped to Cyber Essentials, CIS Controls v8, NIST CSF 2.0 and ISO 27001 Annex A; Lynis and Trivy results; a remediation tracker with time to fix and SLA by severity (14 days for critical and high, as Cyber Essentials requires); a weighted supplier questionnaire (10 questions, must-have answers that block approval) mapped to ISO 27001 5.19 to 5.23 and UK GDPR Art. 28. The tracker and the supplier are synthetic, the README says so.

What judged lacks compared to it:
- Time to fix: judged reports a finding is open but not for how many days. Cyber Essentials asks for high-risk fixes within 14 days; judged has no first-seen date per finding.
- The supplier questionnaire with weights and must-have answers (judged `paperwork` records suppliers and DPAs but does not rate them).
- NIST CSF 2.0 and CIS Controls v8 as extra mappings (judged maps Cyber Essentials, ISO 27001, GDPR).
- A before and after comparison of controls passed (judged `diff` compares two reports but shows no pass rate).
- Its checks overlap with what judged has: root SSH login, empty passwords, uid 0, shadow permissions, world-writable files, sudo group, password age, telnet, pending updates, firewall default deny, audit logging. Password maximum age and shadow file permissions are not clearly in judged; check before adding.

Take (MIT): the SLA table, the weighted score, the supplier questions after rewording, and the YAML 1.1 lesson (an unquoted `yes` becomes true; judged's own config is not YAML, so only the answers file for a questionnaire would be exposed).

## What it adds up to

Order by value for judged: first-seen date and days open per finding (security-controls-metrics, e8mate), then the SOC 2 and extra ISO controls with a mapping for the checks that already exist (probo), then dated manual evidence lines for the measures that have no machine check (probo, comp), then the supplier questionnaire, then device checks that are missing (screen lock, time sync, password policy), then CA trust stores (trustwatch), then the incident clock and certification record (cairn).
