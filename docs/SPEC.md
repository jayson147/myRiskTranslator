# risk-translator: project brief

> Draft written for you to edit. Rewrite it in your own words before you start: the brief is what you'll talk through in interviews, so it has to sound like you. Anything marked **DECIDE** is your call.

## The problem

Vulnerability scanners produce long lists of CVEs ranked by CVSS severity. A board can't act on that list, and CVSS alone is the wrong ranking: it measures how bad a flaw *could* be, not how likely it is to be exploited, or how much the affected system matters to the business.

A risk analyst closes that gap by hand: checking whether each flaw is being exploited, judging how critical each asset is, scoring likelihood and impact, mapping the risk to the organisation's control framework, and writing it up for leadership. risk-translator automates the first pass so the analyst can spend their time on judgement.

## Who it's for

A GRC or risk analyst, or the IT lead at a small organisation, who has scan results and needs a prioritised risk register and a summary leadership can read.

## What it does (v1)

1. **Reads input:**
   - a CSV of `asset,cve` pairs (simplest case); and
   - an Nmap XML file produced with `nmap -sV --script vulners -oX scan.xml <target>`.
2. **Reads an assets file** (`assets.yaml`): each asset's name, IP, owner, a short description and a criticality rating. **DECIDE:** the criticality scale (1 to 5?) and what each level means.
3. **Enriches each CVE** from three free public sources:
   - **NVD (CVE API 2.0):** CVSS base score and severity, description, CWE weakness IDs.
   - **FIRST EPSS API:** probability of exploitation in the next 30 days, and its percentile.
   - **CISA KEV catalogue (JSON feed):** whether it's known to be exploited in the wild, and the date it was added.
4. **Scores risk** as likelihood x impact on a 5 x 5 matrix (see the scoring model).
5. **Maps each risk** to ISO/IEC 27001:2022 Annex A controls (see the mapping).
6. **Writes three outputs** to the output folder:
   - `register.csv` and `register.xlsx`: one row per asset and CVE, with ID, asset, owner, description, CVSS, EPSS, KEV, likelihood, impact, score, band, ISO controls and a suggested treatment.
   - `heatmap.png`: the 5 x 5 matrix with a count of risks in each cell.
   - `summary.md`: a one-page summary for leadership (headline numbers, top five risks in plain English, everything on KEV, recommended actions, a short "how this was scored" note and data credits).

## Scoring model (starting point: DECIDE every number)

**Likelihood (1 to 5)**

| Rule | Likelihood |
|---|---|
| On the CISA KEV list | 5 |
| EPSS percentile 95 or above | 4 |
| EPSS percentile 80 to 95 | 3 |
| EPSS percentile 50 to 80 | 2 |
| Below 50, or no EPSS score | 1 |

**Impact (1 to 5):** start from the CVSS severity band (low 1, medium 2, high 3, critical 4), then adjust for the asset's criticality (for example +1 for a critical asset, -1 for a low one), kept within 1 to 5.

**Risk score:** likelihood x impact, from 1 to 25.

| Score | Band |
|---|---|
| 1 to 4 | Low |
| 5 to 9 | Medium |
| 10 to 16 | High |
| 20 to 25 | Critical |

Questions to settle and log in `docs/decisions.md`: Should KEV override everything? Should an internet-facing asset raise likelihood? How should the tool treat a CVE with no CVSS score yet?

## ISO 27001 mapping (starting point: DECIDE and check against your Information Risk Management notes)

Every finding maps to **8.8 Management of technical vulnerabilities**. A second control comes from the CWE weakness type NVD gives, using a small mapping file you write (`mappings/iso27001.yaml`), for example:

| Weakness type (examples) | Extra control |
|---|---|
| Authentication flaws (CWE-287, 306, 798) | 8.5 Secure authentication |
| Weak or missing cryptography (CWE-319, 326, 327) | 8.24 Use of cryptography |
| Injection and input validation (CWE-20, 78, 79, 89) | 8.28 Secure coding |
| Misconfiguration (CWE-16, 1188) | 8.9 Configuration management |
| Information exposure (CWE-200) | 8.12 Data leakage prevention |

Use control numbers and short names in your own words only. The standard's text is copyrighted.

## Not in v1

OpenVAS input, PDF output, NIST CSF 2.0 mapping, risk owners and treatment tracking over time, a web interface. These are the v2 list.

## Done means

- `risk-translator --input samples/cves.csv --assets samples/assets.yaml --out out/` produces all three outputs.
- It also works on a real Nmap XML scan of your own lab VM.
- Tests pass with no network access; the linter is clean.
- The README (in your words) explains the problem, the scoring model and why, how to run it, a sample output, and the data credits.
- `docs/decisions.md` records at least five design decisions and why you made them.

## Data sources and credits

- NVD CVE API 2.0 (request a free API key from the NVD developers page; it raises the rate limit a lot). The NVD asks products using its API to say they use it but are not endorsed or certified by the NVD: check the exact wording on its terms of use page.
- FIRST EPSS: `https://api.first.org/data/v1/epss?cve=CVE-2021-44228` (accepts several CVEs, comma-separated).
- CISA Known Exploited Vulnerabilities catalogue: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## Legal

Only scan machines you own or have written permission to test. Scanning anything else can breach the Computer Misuse Act 1990.
