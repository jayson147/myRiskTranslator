"""Check the parsers against real API responses, once they have been recorded.

Skipped until you run scripts/record_fixtures.py on a machine with internet.
"""

import json
from pathlib import Path

import pytest

from fakes import FIXTURES
from risk_translator.sources.kev import parse_kev
from risk_translator.sources.nvd import parse_nvd_cve

RECORDED = FIXTURES / "recorded"
NVD_FILES = sorted(RECORDED.glob("nvd_*.json")) if RECORDED.exists() else []


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.skipif(not NVD_FILES, reason="no recorded fixtures yet")
@pytest.mark.parametrize("path", NVD_FILES, ids=[p.stem for p in NVD_FILES])
def test_real_nvd_response_parses(path):
    vulnerabilities = load(path)["vulnerabilities"]
    assert vulnerabilities, "NVD returned no record"
    record = parse_nvd_cve(vulnerabilities[0]["cve"])
    assert record.description
    assert record.cvss_score is None or 0 <= record.cvss_score <= 10
    assert record.cvss_severity in {None, "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert all(cwe.startswith("CWE-") for cwe in record.cwe_ids)


@pytest.mark.skipif(not (RECORDED / "kev_trimmed.json").exists(), reason="no recorded KEV")
def test_real_kev_parses():
    catalogue = parse_kev(load(RECORDED / "kev_trimmed.json"))
    assert catalogue.version != "unknown"
    assert all(entry.date_added for entry in catalogue.entries.values())


@pytest.mark.skipif(not (RECORDED / "epss_batch.json").exists(), reason="no recorded EPSS")
def test_real_epss_parses():
    rows = load(RECORDED / "epss_batch.json")["data"]
    assert rows
    for row in rows:
        assert 0 <= float(row["epss"]) <= 1 and 0 <= float(row["percentile"]) <= 1
