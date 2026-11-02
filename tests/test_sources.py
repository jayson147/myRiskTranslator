"""Tests for the KEV, EPSS and NVD clients and the enrichment step, using fixtures only."""

import pytest

from fakes import FakeResponse, FakeSession, load_fixture, no_sleep
from risk_translator.cache import DiskCache
from risk_translator.enrich import enrich_cves
from risk_translator.errors import SourceUnavailable
from risk_translator.sources.epss import EPSS_URL, fetch_epss
from risk_translator.sources.kev import KEV_URL, load_kev
from risk_translator.sources.nvd import NVD_URL, fetch_nvd, parse_nvd_cve, severity_from_score


def nvd_cve(name: str) -> dict:
    return load_fixture(name)["vulnerabilities"][0]["cve"]


# --- KEV -----------------------------------------------------------------


def test_kev_download_and_lookup(tmp_path):
    session = FakeSession({KEV_URL: [FakeResponse(200, load_fixture("kev_catalogue.json"))]})
    kev = load_kev(session, DiskCache(tmp_path))
    assert kev.version == "2026.01.01"
    log4shell = kev.lookup("cve-2021-44228")
    assert log4shell.date_added == "2021-12-10" and log4shell.ransomware is True
    assert kev.lookup("CVE-2014-0160").ransomware is False
    assert kev.lookup("CVE-2099-0001") is None


def test_kev_second_load_uses_cache(tmp_path):
    session = FakeSession({KEV_URL: [FakeResponse(200, load_fixture("kev_catalogue.json"))]})
    cache = DiskCache(tmp_path)
    load_kev(session, cache)
    load_kev(session, cache)
    assert len(session.calls) == 1


def test_kev_offline_without_cache(tmp_path):
    with pytest.raises(SourceUnavailable, match="offline"):
        load_kev(FakeSession(), DiskCache(tmp_path), offline=True)


def test_kev_malformed(tmp_path):
    session = FakeSession({KEV_URL: [FakeResponse(200, {"oops": []})]})
    with pytest.raises(SourceUnavailable, match="expected format"):
        load_kev(session, DiskCache(tmp_path))
    assert not (tmp_path / "kev").exists()  # bad data is never cached


# --- EPSS ----------------------------------------------------------------

CVES = ["CVE-2021-44228", "CVE-2014-0160", "CVE-2023-48795", "CVE-2099-0001"]


def test_epss_batches_one_request(tmp_path):
    session = FakeSession({EPSS_URL: [FakeResponse(200, load_fixture("epss_batch.json"))]})
    results, warnings = fetch_epss(CVES, session, DiskCache(tmp_path))
    assert len(session.calls) == 1
    assert session.calls[0]["params"]["cve"] == ",".join(CVES)
    assert results["CVE-2021-44228"].percentile == pytest.approx(0.999)
    assert results["CVE-2023-48795"].score == pytest.approx(0.4)
    assert results["CVE-2099-0001"] is None  # looked up, but EPSS has no score
    assert warnings == []


def test_epss_second_run_makes_no_calls(tmp_path):
    cache = DiskCache(tmp_path)
    session = FakeSession({EPSS_URL: [FakeResponse(200, load_fixture("epss_batch.json"))]})
    fetch_epss(CVES, session, cache)
    results, _ = fetch_epss(CVES, session, cache)
    assert len(session.calls) == 1
    assert results["CVE-2099-0001"] is None


def test_epss_splits_large_batches(tmp_path, monkeypatch):
    monkeypatch.setattr("risk_translator.sources.epss.BATCH_SIZE", 2)
    session = FakeSession({EPSS_URL: [FakeResponse(200, load_fixture("epss_batch.json"))]})
    fetch_epss(CVES, session, DiskCache(tmp_path))
    assert len(session.calls) == 2


def test_epss_outage_carries_on(tmp_path):
    session = FakeSession({EPSS_URL: [FakeResponse(503)]})
    results, warnings = fetch_epss(CVES, session, DiskCache(tmp_path), sleep=no_sleep)
    assert results == {}
    assert "EPSS unavailable" in warnings[0]


# --- NVD parsing ---------------------------------------------------------


def test_parse_prefers_v31_primary_score():
    record = parse_nvd_cve(nvd_cve("nvd_v31.json"))
    assert (record.cvss_score, record.cvss_severity, record.cvss_version) == (
        10.0,
        "CRITICAL",
        "3.1",
    )
    assert record.description.startswith("Illustrative")
    assert record.cwe_ids == ["CWE-917", "CWE-20"]  # NVD-CWE-Other dropped


def test_parse_falls_back_to_v2_severity_on_metric():
    record = parse_nvd_cve(nvd_cve("nvd_v2_only.json"))
    assert (record.cvss_score, record.cvss_severity, record.cvss_version) == (5.0, "MEDIUM", "2.0")


def test_parse_v40_derives_missing_severity():
    record = parse_nvd_cve(nvd_cve("nvd_v40_only.json"))
    assert (record.cvss_score, record.cvss_severity, record.cvss_version) == (8.7, "HIGH", "4.0")
    assert record.cwe_ids == []


def test_parse_no_metrics():
    record = parse_nvd_cve(nvd_cve("nvd_no_metrics.json"))
    assert record.cvss_score is None and record.cvss_severity is None
    assert record.cwe_ids == []


@pytest.mark.parametrize(
    "score, severity",
    [
        (0.0, "NONE"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (9.0, "CRITICAL"),
    ],
)
def test_severity_from_score(score, severity):
    assert severity_from_score(score) == severity


# --- NVD client ----------------------------------------------------------


def nvd_session(*responses):
    return FakeSession({NVD_URL: list(responses)})


def test_nvd_sends_key_in_header_and_paces_requests(tmp_path):
    waits: list[float] = []
    session = nvd_session(FakeResponse(200, load_fixture("nvd_v31.json")))
    results, warnings = fetch_nvd(
        ["CVE-2021-44228", "CVE-2014-0160"], session, DiskCache(tmp_path), "k3y", sleep=waits.append
    )
    assert session.calls[0]["headers"] == {"apiKey": "k3y"}
    assert "k3y" not in session.calls[0]["url"]
    assert session.calls[0]["params"] == {"cveId": "CVE-2021-44228"}
    assert waits == [0.7]  # one pause between two requests, with a key
    assert warnings == []


def test_nvd_without_key_waits_longer(tmp_path):
    waits: list[float] = []
    session = nvd_session(FakeResponse(200, load_fixture("nvd_v31.json")))
    fetch_nvd(["CVE-1111-0001", "CVE-1111-0002"], session, DiskCache(tmp_path), sleep=waits.append)
    assert session.calls[0]["headers"] is None
    assert waits == [6.5]


def test_nvd_retries_on_403_then_succeeds(tmp_path):
    waits: list[float] = []
    session = nvd_session(FakeResponse(403), FakeResponse(200, load_fixture("nvd_v31.json")))
    results, warnings = fetch_nvd(
        ["CVE-2021-44228"], session, DiskCache(tmp_path), "k", sleep=waits.append
    )
    assert results["CVE-2021-44228"].cvss_score == 10.0
    assert waits == [6.0] and warnings == []


def test_nvd_not_found_is_cached_as_none(tmp_path):
    cache = DiskCache(tmp_path)
    session = nvd_session(FakeResponse(200, load_fixture("nvd_not_found.json")))
    results, _ = fetch_nvd(["CVE-2099-0001"], session, cache, sleep=no_sleep)
    assert results == {"CVE-2099-0001": None}
    results, _ = fetch_nvd(["CVE-2099-0001"], session, cache, sleep=no_sleep)
    assert results == {"CVE-2099-0001": None} and len(session.calls) == 1


def test_nvd_outage_stops_after_three_failures(tmp_path):
    session = nvd_session(FakeResponse(503))
    cves = [f"CVE-2020-000{n}" for n in range(1, 6)]
    results, warnings = fetch_nvd(cves, session, DiskCache(tmp_path), sleep=no_sleep)
    assert results == {}
    assert len(session.calls) == 3 * 4  # three CVEs, four attempts each
    assert "skipped the remaining 2" in warnings[-1]


def test_nvd_offline_uses_cache_only(tmp_path):
    results, warnings = fetch_nvd(
        ["CVE-2021-44228"], FakeSession(), DiskCache(tmp_path), offline=True
    )
    assert results == {} and "offline" in warnings[0]


# --- enrichment ----------------------------------------------------------


def full_session():
    return FakeSession(
        {
            KEV_URL: [FakeResponse(200, load_fixture("kev_catalogue.json"))],
            EPSS_URL: [FakeResponse(200, load_fixture("epss_batch.json"))],
            NVD_URL: [
                FakeResponse(200, load_fixture("nvd_v31.json")),
                FakeResponse(200, load_fixture("nvd_v2_only.json")),
            ],
        }
    )


def test_enrich_combines_all_three_sources(tmp_path):
    enrichments, warnings, version = enrich_cves(
        ["CVE-2021-44228", "CVE-2014-0160", "CVE-2021-44228"],
        cache_dir=tmp_path,
        session=full_session(),
        sleep=no_sleep,
    )
    assert list(enrichments) == ["CVE-2021-44228", "CVE-2014-0160"]  # de-duplicated
    log4shell = enrichments["CVE-2021-44228"]
    assert log4shell.on_kev is True and log4shell.kev_ransomware is True
    assert log4shell.epss_percentile == pytest.approx(0.999)
    assert log4shell.cvss_score == 10.0 and log4shell.cwe_ids == ["CWE-917", "CWE-20"]
    assert log4shell.gaps == []
    assert warnings == [] and version == "2026.01.01"


def test_enrich_second_run_makes_no_network_calls(tmp_path):
    cves = ["CVE-2021-44228", "CVE-2014-0160"]
    enrich_cves(cves, cache_dir=tmp_path, session=full_session(), sleep=no_sleep)
    second = FakeSession()  # any call would raise
    enrichments, warnings, _ = enrich_cves(cves, cache_dir=tmp_path, session=second, sleep=no_sleep)
    assert second.calls == []
    assert enrichments["CVE-2014-0160"].cvss_version == "2.0"


def test_enrich_marks_missing_fields_when_everything_is_down(tmp_path):
    down = FakeSession({"https://": [FakeResponse(503)]})
    enrichments, warnings, version = enrich_cves(
        ["CVE-2021-44228"], cache_dir=tmp_path, session=down, sleep=no_sleep
    )
    item = enrichments["CVE-2021-44228"]
    assert item.on_kev is None and item.epss_score is None and item.cvss_score is None
    assert item.gaps == ["KEV status unknown", "EPSS unavailable", "NVD unavailable"]
    assert len(warnings) == 3 and version is None
