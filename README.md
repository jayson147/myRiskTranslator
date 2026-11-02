# risk-translator

A command-line tool that turns vulnerability scan results into a risk register a board can act on.

You give it a list of known flaws (CVEs) on your systems, either from an Nmap scan or a simple CSV, plus a short file describing how important each system is. It looks each flaw up in three free public sources, scores it as **likelihood x impact** on a 5 x 5 risk matrix, maps it to **ISO/IEC 27001:2022 Annex A** controls, and writes:

- `register.csv` and `register.xlsx`: the full risk register, highest risk first
- `heatmap.png`: the 5 x 5 risk matrix with the number of risks in each cell
- `summary.md`: a one-page summary in plain English for leadership

## The problem

Vulnerability scanners produce long lists of CVEs sorted by CVSS severity. A board can't act on that list, and CVSS on its own ranks risk badly:

- **CVSS measures how bad a flaw *could* be, not how likely it is to be used.** Most CVEs are never exploited, while a few are used by criminals within days of being published.
- **CVSS knows nothing about your business.** A "critical" flaw on a test machine with no data matters far less than a "high" flaw on the website that takes customer payments.

A risk analyst closes that gap by hand: checking whether each flaw is being exploited, judging how important each system is, scoring likelihood and impact, mapping the risk to the organisation's control framework and writing it up for leadership. risk-translator automates that first pass, so the analyst can spend their time on judgement rather than lookups.

## How it works

```
Nmap XML or CSV ──► findings (system + CVE)
assets.yaml     ──►        │
                           ▼
              enrich from NVD, EPSS and CISA KEV  (cached in .cache/)
                           │
                           ▼
              score: likelihood x impact = 1 to 25, then a band
                           │
                           ▼
              map to ISO 27001 Annex A (8.8 plus one control from the CWE)
                           │
                           ▼
          register.csv / register.xlsx / heatmap.png / summary.md
```

1. **Read the inputs.** A CSV of `asset,cve` pairs, or an Nmap XML file from `nmap -sV --script vulners`. Each finding is matched to a system in `assets.yaml`, by name or IP address.
2. **Enrich each CVE** from public data:
   - **NVD** (National Vulnerability Database): CVSS score and severity, a description and the CWE weakness type.
   - **EPSS** (Exploit Prediction Scoring System, from FIRST): the probability that the flaw will be attacked in the next 30 days, and how it ranks against all other CVEs.
   - **CISA KEV** (Known Exploited Vulnerabilities): whether the flaw is confirmed as being exploited in the wild, and whether it has been used in ransomware.
3. **Score the risk** on a 5 x 5 matrix (see below).
4. **Map it to ISO 27001** controls (see below).
5. **Write the outputs.**

## The scoring model, and why

Every rule lives in one place, the `DECISIONS` block at the top of [`src/risk_translator/scoring.py`](src/risk_translator/scoring.py), with the reason for each one written next to it.

### Likelihood (1 to 5): how likely is an attack?

| Rule | Likelihood |
|---|---|
| On the CISA KEV list | 5 |
| EPSS percentile 95 or above (top 5% of all CVEs) | 4 |
| EPSS percentile 80 to 95 | 3 |
| EPSS percentile 50 to 80 | 2 |
| Below 50, or no EPSS score | 1 |
| System is internet-facing | +1 (up to 5) |

- **KEV overrides EPSS.** Confirmed exploitation is stronger evidence than any forecast.
- **The EPSS percentile, not the raw score.** Raw EPSS scores are mostly tiny numbers. The percentile says how a flaw ranks against all the others, which is easier to defend and explain.
- **Internet-facing systems get +1.** Anyone in the world can reach them, not just someone already inside the network. Exposure changes how *likely* an attack is, not how much damage it does, so it adjusts likelihood rather than impact.

### Impact (1 to 5): how much damage could it do?

| CVSS severity | Starting impact |
|---|---|
| None or Low | 1 |
| Medium | 2 |
| High | 3 |
| Critical | 4 |
| No CVSS score yet | 3 (assumed high, and flagged) |

Then adjust for how important the system is to the business:

| Asset criticality | Adjustment |
|---|---|
| 1 Negligible, 2 Low | -1 |
| 3 Moderate | 0 |
| 4 High, 5 Critical | +1 |

- **CVSS alone tops out at 4.** Only the asset's importance can push impact to 5, so technical severity on its own never decides that a risk is as bad as it gets for the business.
- **Missing CVSS scores are assumed high.** Brand-new CVEs are often waiting for NVD to analyse them, and they can be the most urgent ones. Skipping them or scoring them low would hide risk. The register notes every estimate.

### Score, band and treatment

**Risk score = likelihood x impact**, from 1 to 25.

| Score | Band | Suggested treatment |
|---|---|---|
| 20 to 25 | Critical | Fix or put a workaround in place within 7 days, and tell the owner today |
| 10 to 16 | High | Fix within 14 days |
| 5 to 9 | Medium | Fix within 30 days, in the monthly patch cycle |
| 1 to 4 | Low | Fix at the next scheduled update, or accept the risk with the owner's sign-off |

Critical can only be reached when likelihood and impact are both near the top (5 x 4, 4 x 5 or 5 x 5), so the label is kept for flaws that are both likely to be used and damaging if they are. The 14-day target for High matches the UK Cyber Essentials rule for applying high and critical security updates.

### Asset criticality scale

| Level | Meaning |
|---|---|
| 1 Negligible | Test or lab system with no business data. An outage goes unnoticed. |
| 2 Low | Internal convenience tool with no sensitive data. An outage is an annoyance. |
| 3 Moderate | Supports day-to-day work or holds internal data. An outage disrupts teams for a day or so. |
| 4 High | Runs an important business process or holds personal or financial data. A breach could mean financial loss or a report to the regulator. |
| 5 Critical | Customer-facing or core to revenue, or holds payment or special category data. A breach would cause serious financial, legal or reputational harm. |

## ISO/IEC 27001:2022 mapping

Every finding maps to **8.8 Management of technical vulnerabilities**, because finding and fixing known flaws is exactly what that control covers. A second control comes from the CVE's CWE weakness type, using [`mappings/iso27001.yaml`](mappings/iso27001.yaml). It points at the defence that would have limited this kind of weakness, so that control's owner knows the risk is theirs too.

| Weakness group | Example CWEs | Second control |
|---|---|---|
| Injection and code execution | CWE-20, 78, 79, 89, 502, 917 | 8.28 Secure coding |
| Memory-handling flaws | CWE-119, 125, 416, 787 | 8.28 Secure coding |
| Access control flaws | CWE-22, 284, 862, 863 | 8.3 Information access restriction |
| Authentication flaws | CWE-287, 306, 798 | 8.5 Secure authentication |
| Weak or missing cryptography | CWE-319, 326, 327, 295 | 8.24 Use of cryptography |
| Misconfiguration | CWE-16, 276, 1188 | 8.9 Configuration management |
| Information exposure | CWE-200, 209, 532 | 8.12 Data leakage prevention |
| Denial of service | CWE-400, 770, 835 | 8.6 Capacity management |

When a CVE has several CWEs, the first one that appears in the mapping wins, with NVD's own analysis checked before other sources. That keeps every risk to exactly "8.8 plus one", which keeps the register readable and gives each risk one clear control owner. CWEs that aren't in the file get 8.8 only.

Controls are referred to by number and a short name in my own words. The text of the standard is copyrighted and is not reproduced here.

## Quick start

You need Python 3.12 or later.

```bash
git clone https://github.com/jayson147/myRiskTranslator.git
cd myRiskTranslator
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Optionally, request a free NVD API key from the NVD developers page and add it to `.env`:

```bash
cp .env.example .env
# then edit .env:  NVD_API_KEY=your-key-here
```

Without a key the tool still works, but NVD only allows about one request every six seconds, so the first run is slow. With a key it is roughly ten times faster.

Run it on the sample data:

```bash
risk-translator --input samples/cves.csv --assets samples/assets.yaml --out out/
```

Or on an Nmap scan of a machine you own:

```bash
nmap -sV --script vulners -oX scan.xml <your-lab-vm-ip>
risk-translator --input scan.xml --assets samples/assets.yaml --out out/
```

### Options

| Option | What it does |
|---|---|
| `--input FILE` | The CVE list (`.csv`) or Nmap scan (`.xml`) |
| `--assets FILE` | The assets file |
| `--out DIR` | Folder for the four output files (created if needed) |
| `--input-type csv\|nmap` | Override the input type if the file extension is unusual |
| `--mapping FILE` | ISO 27001 mapping file (default `mappings/iso27001.yaml`) |
| `--cache-dir DIR` | Where API responses are cached (default `.cache`) |
| `--offline` | Use cached data only and make no network calls |
| `--refresh` | Ignore the cache and fetch everything again |
| `-v`, `--verbose` | Show debug messages |

### Input formats

`assets.yaml`:

```yaml
assets:
  - name: booking-web
    ip: 10.0.10.5
    owner: Head of Digital
    description: the customer booking website, which takes card payments
    criticality: 5
    internet_facing: true
```

`cves.csv` (the `asset` column can hold a system's name or its IP address):

```csv
asset,cve
booking-web,CVE-2021-44228
finance-db,CVE-2019-0708
```

## The outputs

- **`register.csv` / `register.xlsx`:** one row per system and CVE, sorted by score. Columns include the risk ID, system, owner, service, CVE, description, CVSS, EPSS, KEV status, likelihood, impact, score, band, ISO controls, suggested treatment, and notes on how the score was reached and what data was missing. The Excel version has a frozen header row, filters and colour-coded bands.
- **`heatmap.png`:** likelihood up the side, impact along the bottom, with the number of risks in each cell. Each band has its own colour, hatching pattern and letter, so it still reads when printed in black and white.
- **`summary.md`:** one page for leadership. It covers the headline numbers, the top five risks in plain English (what it is, which system, why it matters, what to do), every flaw on the known exploited list, three recommended actions, a short note on how the scores work, any gaps in the data, and the data credits.

## Design notes

- **Polite to the APIs.** Every response is cached on disk: KEV and EPSS for a day, because they change daily, and NVD for a week. A second run on the same data makes no network calls. EPSS lookups are batched (up to 50 CVEs per request), the KEV catalogue is downloaded at most once per run, and NVD requests are paced to stay under its rate limit, with exponential backoff on HTTP 403 and 429.
- **Fails clearly.** A malformed CVE ID, a system missing from the assets file or a broken config file gives a plain error message listing every problem, not a stack trace. If a data source is down, the run carries on, the affected fields are left blank, and the summary opens with a warning that some scores may understate the real risk.
- **Unknown hosts are never dropped silently.** Hosts in an Nmap scan that aren't in `assets.yaml` are reported on the terminal and in the summary's "Gaps in this report" section.
- **Secure by default.** Scan files are parsed with `defusedxml`, which blocks XML attacks such as entity expansion. The NVD key is read from the environment, sent in a request header and never printed or logged. Cache keys are checked so they can't point outside the cache folder. Text written to the register is protected against spreadsheet formula injection.

## Testing

```bash
pytest
ruff check . && ruff format --check .
```

The tests never touch the network: a fixture in `tests/conftest.py` blocks network connections, and the API clients are tested against stored responses in `tests/fixtures/`. To check the parsers against real, current API responses, run `python scripts/record_fixtures.py` once with internet access. It saves real responses to `tests/fixtures/recorded/`, and `tests/test_recorded_fixtures.py` picks them up automatically.

## Project layout

```
src/risk_translator/
  cli.py            command-line entry point
  readers.py        assets.yaml and CSV readers
  nmap_reader.py    Nmap XML parser (defusedxml)
  sources/          KEV, EPSS and NVD clients, plus fetch-with-retry
  cache.py          on-disk JSON cache
  enrich.py         combines the three sources per CVE
  scoring.py        likelihood, impact, bands and treatments (all the rules)
  iso_mapping.py    ISO 27001 mapping loader and lookup
  pipeline.py       scores, maps and sorts the risks
  outputs/          register, heat map and summary writers
mappings/iso27001.yaml   CWE to Annex A control mapping
samples/                 example assets and CVE list (made-up systems)
docs/                    project brief, build plan and design decisions
```

## Limitations

- **Only as good as the scan.** Nmap's vulners script matches software versions to known CVEs, so it can report flaws that have been patched by a backport, and miss flaws in software it can't fingerprint.
- **CVSS is a base score.** It ignores your own mitigations, such as a firewall rule or a disabled feature, so impact may be overstated for well-defended systems.
- **EPSS is a forecast, and KEV is a US government list.** Neither covers every exploited flaw, so a likelihood of 1 means "no evidence of attacks", not "safe".
- **Asset criticality is a judgement.** The scores are only as good as the ratings in `assets.yaml`, so they should be agreed with each system's owner.
- **Risk IDs are per run.** R-001 is simply the top risk in this report. Tracking a risk across runs is on the v2 list.

## What's next

- OpenVAS and other scanner inputs
- PDF output of the summary
- Mapping to NIST CSF 2.0 alongside ISO 27001
- Risk owners, treatment decisions and tracking over time
- A simple web interface

## Data credits

- **NVD:** CVSS scores, descriptions and CWE weakness types come from the NIST National Vulnerability Database. This product uses the NVD API but is not endorsed or certified by the NVD.
- **EPSS:** exploit prediction scores from the Exploit Prediction Scoring System by FIRST, https://www.first.org/epss.
- **CISA KEV:** known exploited status from the Cybersecurity and Infrastructure Security Agency's Known Exploited Vulnerabilities catalogue.
- **ISO/IEC 27001:2022:** controls are cited by number and short name only. The standard is published by ISO and IEC.

## Legal and ethical use

Only scan systems you own or have written permission to test. In the UK, scanning other people's systems without permission can be an offence under the Computer Misuse Act 1990. The sample files in this repository describe made-up systems. Any real scan added to `samples/` must come only from a lab machine you own.
