# risk-translator

A Python command-line tool that turns vulnerability scan output into a board-ready risk register. It enriches each CVE with public data (NVD severity, FIRST EPSS exploit likelihood, CISA KEV known-exploited status), scores risk as likelihood x impact using the asset criticality the user sets, maps each risk to ISO/IEC 27001:2022 Annex A controls, and writes a risk register, a heat map and a one-page summary.

Full brief: `docs/SPEC.md`. Build plan: `docs/BUILD-PROMPTS.md`. Design decisions: `docs/decisions.md`.

## Who owns this

This is Jayson's portfolio project for graduate cyber risk and GRC roles. He has to be able to explain every line and every design choice in an interview. So:

- Work one phase at a time, as set out in `docs/BUILD-PROMPTS.md`. Stop at the end of each phase so he can review, test and commit.
- Before writing code, explain the plan in plain English: which files change, how data flows, and what the tests will check.
- **Design decisions are his, not yours.** Scoring thresholds, likelihood and impact rules, risk bands, asset criticality scales and the ISO 27001 mapping are his calls. Offer 2 or 3 options with trade-offs, then wait. In Learning output style, leave a `TODO(human)` at these points.
- When he makes a decision, remind him to log it in `docs/decisions.md` in his own words. Don't write those entries for him.
- Don't write README prose. You can suggest an outline; he writes the words.
- Prefer simple, readable code over clever code. Short functions, clear names, type hints, a docstring on every public function.

## Stack

- Python 3.12, `src/` layout, package `risk_translator`, installed with `pip install -e .`
- Allowed dependencies: `requests`, `pyyaml`, `openpyxl`, `matplotlib`, `python-dotenv`, `defusedxml` (for parsing scan files safely), plus `pytest` and `ruff` for development. **Ask before adding anything else**, and say why the standard library isn't enough.
- CLI with `argparse` (no framework).

## Commands

- Set up: `python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"`
- Test: `pytest`
- Lint and format: `ruff check . && ruff format .`
- Run: `risk-translator --input samples/cves.csv --assets samples/assets.yaml --out out/`

Run the tests and the linter at the end of every phase and report the results.

## Rules for the code

- **Tests never touch the network.** Use recorded JSON fixtures in `tests/fixtures/`. Every module gets tests.
- **Be polite to the APIs.** Cache every response on disk in `.cache/` and reuse it. Respect NVD rate limits (back off and retry on HTTP 403 or 429). Batch EPSS lookups. Download the KEV catalogue once per run.
- **Secrets:** the NVD API key comes from the `NVD_API_KEY` environment variable, loaded from `.env`. Never hardcode it, print it or log it. Keep `.env.example` up to date and `.env` out of git.
- **Fail clearly:** a malformed CVE ID, a host missing from the assets file or an API outage should produce a readable message, not a stack trace. Partial results are fine if the summary says what's missing.

## Legal and ethical limits

- Sample scans come only from machines Jayson owns or is authorised to test (his own lab VM). Never suggest scanning third-party systems: in the UK that can breach the Computer Misuse Act 1990.
- Don't commit real scan data other than the files in `samples/`.
- ISO/IEC 27001 is copyrighted. Refer to controls by number and a short name in our own words (for example "8.8 Management of technical vulnerabilities"). Never paste text from the standard.
- Credit the data sources in the README and the summary output, including the NVD notice that the product uses the NVD API but is not endorsed or certified by the NVD.

## Writing style for docs and generated reports

- British English. No em dashes; use a comma, colon or full stop instead.
- The one-page summary is for a board, not engineers: plain English, business impact first, no jargon without a one-line explanation.

## Git

Don't commit or push. Jayson reviews the diff and commits himself with his own messages.
