"""Record real API responses into tests/fixtures/recorded/ (run once, with internet).

    python scripts/record_fixtures.py

Saves one NVD response per sample CVE, one EPSS batch response and a trimmed
copy of the KEV catalogue (only the sample CVEs, to keep the repo small).
tests/test_recorded_fixtures.py then checks the parsers against them.
Uses NVD_API_KEY from .env if set; the key is never written to the files.
"""

import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from risk_translator.sources.epss import EPSS_URL
from risk_translator.sources.fetch import fetch_json, new_session
from risk_translator.sources.kev import KEV_URL
from risk_translator.sources.nvd import NVD_URL

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "recorded"
SAMPLE = ROOT / "samples" / "cves.csv"


def save(name: str, data: object) -> None:
    """Write one fixture file as pretty-printed JSON."""
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"saved {name}")


def main() -> int:
    """Fetch and save the fixtures. Returns the exit code."""
    load_dotenv(ROOT / ".env")
    api_key = os.environ.get("NVD_API_KEY") or None
    cves = sorted(
        {line.split(",")[1].strip() for line in SAMPLE.read_text().splitlines()[1:] if line}
    )
    OUT.mkdir(parents=True, exist_ok=True)
    session = new_session()

    kev = fetch_json(session, KEV_URL)
    kev["vulnerabilities"] = [v for v in kev["vulnerabilities"] if v["cveID"] in cves]
    kev["count"] = len(kev["vulnerabilities"])
    save("kev_trimmed.json", kev)

    save("epss_batch.json", fetch_json(session, EPSS_URL, params={"cve": ",".join(cves)}))

    headers = {"apiKey": api_key} if api_key else None
    for index, cve_id in enumerate(cves):
        if index:
            time.sleep(0.7 if api_key else 6.5)
        data = fetch_json(session, NVD_URL, params={"cveId": cve_id}, headers=headers)
        save(f"nvd_{cve_id}.json", data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
