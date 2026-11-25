# What a miss costs

Real numbers for each thing judged watches, so you can see where the money is. Written 2026-11-25.

How to read it:

- Every figure is a published number with its source at the bottom, or it says **estimate** (mine) or **computed** (arithmetic on a published number, shown).
- Currencies are the ones the source used. Nothing is converted.
- Averages are not your case. A 10-person firm and a bank sit under the same average. Many sources are vendors who sell the fix, so
  they have a reason to round up; those are marked **vendor**.
- Units: *per incident* happens once and hurts, *per year* repeats, *per device* scales with your size.

## 1. What one bad incident costs

**Start here if the firm is small.** UK government, [Cyber Security Breaches Survey 2025/2026](https://www.gov.uk/government/statistics/cyber-security-breaches-survey-20252026/cyber-security-breaches-survey-20252026),
published 2026-04-30, read from the page itself. Cost of the single most disruptive breach or attack of the last 12 months,
estimated by the business, among those that noticed one (43% of all businesses), zero answers included (Table 4.1a):

| Businesses | Median | 75th percentile | 90th percentile | 95th percentile |
|---|---|---|---|---|
| all | GBP 0 | GBP 200 | GBP 1,500 | GBP 4,000 |
| micro and small | GBP 0 | GBP 190 | GBP 1,140 | GBP 4,000 |
| medium and large | GBP 30 | GBP 500 | GBP 2,330 | GBP 10,000 |

The survey stopped publishing averages this year. The figures below are averages and ceilings from other samples; they
are far larger and are not what a typical small firm should expect. None of this says how much judged saves.


| What | Figure | Unit | Source |
|---|---|---|---|
| Data breach, global average | USD 4.44 million (down 9% from 4.88 million in 2024) | per incident | IBM 2025 |
| Data breach, United States | USD 10.22 million | per incident | IBM 2025 |
| Data breach, healthcare | USD 7.42 million | per incident | IBM 2025 |
| Time to find and contain a breach | 241 days | per incident | IBM 2025 |
| Breach with a lot of shadow AI (staff using unapproved AI tools) | +USD 670,000 compared with little or none | per incident | IBM 2025 |
| Ransomware or extortion incident | USD 5.08 million (when the attacker disclosed it) | per incident | IBM 2025 |
| Ransomware recovery, not counting the ransom | USD 1.53 million mean (UK: USD 2.58 million), firms of 100 to 5,000 staff | per incident | Sophos 2025 |
| Ransom paid, median | USD 1 million; 53% negotiated below the first demand | per incident | Sophos 2025 |
| Recovered fully within a week | 53% of ransomware victims (35% the year before) | share | Sophos 2025 |
| Business e-mail compromise (fake invoice, fake boss) | USD 2.77 billion lost over 21,442 reports, so about USD 129,000 each | per report, **computed** | FBI IC3 2024 |
| All reported cybercrime | USD 16.6 billion, 33% more than 2023 | per year, US | FBI IC3 2024 |

## 2. Area by area: what a miss costs and what judged does about it

| Area | What goes wrong | What it costs | Unit | Status in judged |
|---|---|---|---|---|
| **TLS certificate or key expires** | Site, API or mail stops working until someone renews and deploys | Small firms lose USD 137 to 427 per minute of downtime, so USD 8,200 to 25,600 per hour (**computed** from per-minute). Certificate-outage figures of USD 500,000 to 5 million per event and over 5 hours to fix are **vendor** claims for enterprises | per hour of outage | done: `check`, once-per-band alerts |
| **Free certificate** | The fix itself | Let's Encrypt issues certificates at no charge; judged runs your own ACME client | per year: 0 | done: `renew` |
| **Domain expires or is hijacked** | Site and mail gone; someone else registers the name | No published figure found. **Estimate:** your outage cost per hour (see section 4) times the days to get the name back, plus buying it back at the new owner's price | per incident | done: expiry; transfer lock and dangling DNS open |
| **Known-exploited vulnerability left unpatched** | An attacker uses a hole that already has a fix | Equifax 2017, unpatched Apache Struts with a patch available: at least USD 1.38 billion consumer settlement, plus USD 575 to 700 million to regulators | per incident, large firm | done: OSV + CVSS; CISA KEV list open (first in the queue) |
| **Software past end of life** | No security fixes, fails Cyber Essentials, insurers ask | Windows 10 extended updates: USD 61, then 122, then 244 per device per year; USD 45 per device with cloud management. For 100 devices that is USD 6,100, then 12,200, then 24,400, USD 42,700 over three years (**computed**) | per device per year | open: EOL data feed |
| **Ransomware, no usable backup** | You pay or you rebuild | See section 1: USD 1.53 million recovery mean, USD 1 million median ransom | per incident | done: backup evidence (restore tests live in a separate tool) |
| **Personal data rules (GDPR)** | Regulator fine | Up to EUR 20 million or 4% of worldwide yearly turnover, whichever is higher, for the serious tier; EUR 10 million or 2% for the lower tier. Largest so far: EUR 1.2 billion (Meta, 2023). Ceilings are not typical fines | per decision | done: obligations calendar, Art. 28 contract check; Art. 30 and 33 open |
| **UK GDPR** | Same, UK regulator | Up to GBP 17.5 million or 4% of turnover (from the statute, not re-checked in this pass) | per decision | same |
| **NIS2 (EU, essential and important sectors)** | Late or missing incident report, weak controls | Up to EUR 10 million or 2% (essential), EUR 7 million or 1.4% (important). Clock: warning within 24 hours, report within 72 hours, final report in one month | per decision | open: breach-readiness check |
| **Cyber Essentials (UK)** | Lost contracts that require it | GBP 300 to 600 plus VAT a year by size; the Plus audit GBP 1,350 to 1,600 plus VAT a year at one certifier for 1 to 49 users, with estimates up to GBP 1,500 to 8,000; fixing what the audit finds GBP 500 to 3,000 (**estimate** by a vendor). All **vendor** prices, get quotes | per year | done: evidence per control |
| **ISO 27001** | Lost contracts, failed audit | First year for 10 to 25 staff USD 10,500 to 21,000; yearly surveillance audit USD 3,000 to 10,000; internal audit USD 5,000 to 15,000 or GBP 3,500 to 10,000; UK audit fees GBP 5,000 to 8,000 for 1 to 10 staff. All **vendor** | first year and per year | done: evidence per control |
| **Cyber insurance** | A claim refused, or no cover to buy | A USD 1 million policy for a small firm is about USD 1,000 to 3,000 a year (reported range USD 1,000 to 7,500); typical deductible USD 2,500; premiums fell about 5% so far in 2026. Insurers ask about MFA, backups and patching; a wrong answer can give them grounds to refuse a claim (**not verified here**, read your policy) | per year | open: insurer view of existing evidence |
| **Software licence audit** | Vendor audit finds you short | Average true-up USD 263,000 at a USD 50 million firm and USD 1.6 million at a USD 4 billion firm (Flexera, 2013 to 14, **dated**); over a quarter of firms spend USD 100,000 to 500,000 a year settling licence issues (Azul and ITAM Forum survey). BSA cases reportedly settle at 40 to 60% of the demand (secondary source, **unverified**) | per audit and per year | done: licence expiry and dependency licences |
| **Mail spoofing (SPF, DKIM, DMARC)** | Fake invoices in your name | The FBI figure in section 1: about USD 129,000 per business e-mail compromise report | per incident | done: SPF, DMARC; DKIM, MTA-STS open |
| **AI agents with too much access** | An agent with bypassed permissions or a leaked key does the damage | No separate figure. Shadow AI adds USD 670,000 per breach (IBM). Your own cost is the breach row plus the time to rotate keys (**estimate:** 1 to 3 hours per leaked key) | per incident | done: `[agents]` |
| **Secrets in repositories** | A key in git history | No separate figure; it becomes the breach row. Revoking at the provider comes first, cleaning later | per incident | done: secrets scan, e-mail warning |
| **Contract auto-renews unnoticed** | A year of a service you meant to drop | Price of one term, e.g. a EUR 12,000 a year hosting contract missed by a day costs EUR 12,000 (illustration, not a statistic). judged sums the exposure per currency | per renewal | done: contracts |

## 3. Where to spend effort first, by money

The order below puts a large, common cost with a small piece of work first. It is also the order of [todo.md](todo.md).

| Rank | Work | Money anchor | Effort | State |
|---|---|---|---|---|
| 1 | Known-exploited list (CISA KEV) against dependencies and host | Equifax, ransomware rows | small, free public data | in progress |
| 2 | Windows and macOS machines (where most staff work): disk encryption, Defender or XProtect, updates, end-of-life builds | Windows 10 ESU per device; a lost unencrypted laptop can be a reportable breach (depends on the data held) | medium, needs a per-OS `Env` | open |
| 3 | End-of-life software | Windows 10 ESU per device; Cyber Essentials fail | small, free public data | open |
| 4 | Certificate and domain expiry, extended to SAML, code signing, DKIM keys, service keys | USD 8,200 to 25,600 per hour of outage | small, the tracker already handles any dated item | partly done |
| 5 | Insurer questionnaire view | USD 1,000 to 3,000 a year premium and the refused claim | small, the evidence exists | open |
| 6 | Domain transfer lock and dangling DNS (subdomain takeover) | domain row above | medium | open |
| 7 | Offboarding: keys and accounts of people who left | breach row | medium | open |
| 8 | Mail authentication complete (DKIM, MTA-STS) | about USD 129,000 per fraud report | medium | open |
| 9 | Breach-readiness (who is told within 24 and 72 hours) | NIS2 and GDPR ceilings | small | open |
| 10 | Third-party scripts on checkout pages | breach row | small | open |

Cloud misconfiguration is left out on purpose: it needs cloud credentials, and judged would then hold them.

## 4. Working out your own number

An hour of outage for your firm: revenue per hour, plus the people who cannot work times their loaded hourly cost, plus any
penalty in your contracts. Example (**illustration**): EUR 600,000 revenue a year over 2,000 trading hours is EUR 300 an hour; 5 staff idle
at EUR 40 an hour is EUR 200; together EUR 500 an hour, so a certificate that takes a morning (4 hours) to fix costs about EUR 2,000.

## 5. What judged itself costs

Licence MIT, so EUR 0. It runs on a machine you already have; the only optional dependency (Apprise, for notifications) is free. The public
lists it downloads (CISA KEV and the like) are free and the download sends nothing about you. Setup is **estimated** at an afternoon for the
config file, and each warning you decide on takes you the minutes it takes to read it. It reports and never changes anything, so it has no
way to break production.

## Sources

- IBM, Cost of a Data Breach Report 2025: [IBM newsroom](https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls), [Help Net Security](https://helpnetsecurity.com/2025/08/04/ibm-cost-data-breach-report-2025), [SecurityWeek (US figure)](https://www.securityweek.com/cost-of-data-breach-in-us-rises-to-10-22-million-says-latest-ibm-report/)
- Sophos, State of Ransomware 2025: [report](https://www.sophos.com/en-us/blog/the-state-of-ransomware-2025), [press release](https://www.sophos.com/en-us/press/press-releases/2025/06/nearly-half-companies-opt-pay-ransom-sophos-report-finds)
- FBI IC3 2024: [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/fbi-staggering-lost-cybercrime-2024/), [CyberScoop](https://cyberscoop.com/fbi-ic3-cybercrime-report-2024-key-statistics-trends/)
- Downtime per minute (Ponemon, quoted by Atlassian): [Atlassian](https://www.atlassian.com/incident-management/kpis/cost-of-downtime); certificate outage claims (vendors): [Red Sift](https://blog.redsift.com/asm/a-real-world-view-how-expired-certificates-can-cause-service-downtime-and-financial-losses), [Sectigo](https://www.sectigo.com/blog/the-cost-of-certificate-expiration-for-smb)
- Equifax: [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/2017-data-breach-will-cost-equifax-at-least-1-38-billion), [PortSwigger](https://portswigger.net/daily-swig/equifax-finalizes-data-breach-settlement-with-us-regulators)
- Windows 10 extended updates: [Computerworld](https://www.computerworld.com/article/2081793/heres-how-much-microsoft-will-charge-for-win10-security-updates-once-support-ends.html), [Petri](https://petri.com/windows-10-extended-security-updates-price/)
- GDPR fines: [gdpr-info.eu](https://gdpr-info.eu/issues/fines-penalties/), [iubenda list of largest fines](https://www.iubenda.com/en/blog/the-biggest-gdpr-fines-to-date/), [GDPR Enforcement Tracker report](https://cms.law/en/media/international/files/publications/publications/gdpr-enforcement-tracker-report-may-2025)
- NIS2 (vendor and law-firm summaries; the authority is Directive (EU) 2022/2555 articles 23 and 34): [Mofo](https://www.mofo.com/resources/insights/250708-ns-2-strengthening-europes-cyber-defenses), [Freshfields](https://freshfields.com/en/our-thinking/campaigns/tech-data-and-ai-the-digital-frontier/eu-digital-strategy/nis2-directive)
- Cyber Essentials prices (vendors): [Forensic Control](https://forensiccontrol.com/guides/how-much-does-cyber-essentials-plus-cost/), [ISMS.online](https://isms.online/cyber-essentials/cost/)
- ISO 27001 prices (vendors): [Drata](https://drata.com/blog/iso-27001-certification-cost), [IT Governance](https://www.itgovernance.co.uk/iso27001-certification-costs), [Secureframe](https://secureframe.com/blog/iso-27001-certification-cost)
- Cyber insurance (brokers): [Insureon](https://www.insureon.com/small-business-insurance/cyber-liability/cost), [MoneyGeek](https://www.moneygeek.com/insurance/business/cyber/cost/), [Insurance Journal](https://www.insurancejournal.com/news/national/2026/10/16/889133.htm)
- Licence audits: [CIO Dive on the Azul and ITAM Forum survey](https://www.ciodive.com/news/software-audit-costs-java-open-source-itam-azul/753598/), [InfoWorld](https://www.infoworld.com/article/2245170/got-enterprise-software-youre-probably-due-for-an-audit-3.html)

Apart from the UK survey table, figures were read from search results on 2026-11-25, not from the full reports. Before quoting one in a contract or a budget, open the source.
