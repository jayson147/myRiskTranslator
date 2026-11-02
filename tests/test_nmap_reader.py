"""Tests for the Nmap XML parser, using a hand-made scan with edge cases."""

from pathlib import Path

import pytest

from fakes import FIXTURES
from risk_translator.errors import InputError
from risk_translator.models import Asset
from risk_translator.nmap_reader import read_nmap_xml
from risk_translator.readers import AssetRegistry

SCAN = FIXTURES / "nmap_edge_cases.xml"


@pytest.fixture
def assets():
    return AssetRegistry(
        [
            Asset("booking-web", "10.0.10.5", "Head of Digital", "the website", 5),
            Asset("finance-db", "10.0.20.12", "Finance Director", "the finance server", 4),
            Asset("staff-wiki", "10.0.30.8", "IT Manager", "the wiki", 2),
        ]
    )


def test_findings_per_host_and_service(assets):
    result = read_nmap_xml(SCAN, assets)
    pairs = [(f.asset.name, f.service, f.cve_id) for f in result.findings]
    assert pairs == [
        ("booking-web", "tcp/22 ssh OpenSSH 8.9p1", "CVE-2023-38408"),
        ("booking-web", "tcp/22 ssh OpenSSH 8.9p1", "CVE-2023-48795"),
        ("booking-web", "tcp/80 http Apache httpd 2.4.49", "CVE-2021-41773"),
        ("finance-db", "tcp/3389 ms-wbt-server", "CVE-2019-0708"),
    ]


def test_non_cve_entries_and_duplicates_are_skipped(assets):
    cves = [f.cve_id for f in read_nmap_xml(SCAN, assets).findings]
    assert not any(c.startswith("PACKETSTORM") for c in cves)
    assert cves.count("CVE-2023-38408") == 1


def test_host_with_no_cves_gives_no_findings(assets):
    result = read_nmap_xml(SCAN, assets)
    assert "staff-wiki" not in {f.asset.name for f in result.findings}


def test_unknown_host_is_reported_not_dropped_silently(assets):
    result = read_nmap_xml(SCAN, assets)
    assert len(result.warnings) == 1
    assert "192.168.99.99" in result.warnings[0]
    assert "1 CVE(s)" in result.warnings[0]
    assert "192.168.99.99" not in {f.asset.ip for f in result.findings}


def test_lab_scan_if_present(samples_dir):
    """Runs against Jayson's own lab scan once he has added it (phase 4)."""
    scan = samples_dir / "lab-scan.xml"
    if not scan.exists():
        pytest.skip("samples/lab-scan.xml not created yet")
    from risk_translator.readers import load_assets

    result = read_nmap_xml(scan, load_assets(samples_dir / "assets.yaml"))
    assert result.findings or result.warnings


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "scan.xml"
    path.write_text(text, encoding="utf-8")
    return path


def test_empty_scan_warns(tmp_path, assets):
    result = read_nmap_xml(write(tmp_path, "<nmaprun></nmaprun>"), assets)
    assert result.findings == []
    assert "no hosts" in result.warnings[0]


def test_rejects_entity_expansion_attack(tmp_path, assets):
    bomb = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>\n'
        "<nmaprun>&lol2;</nmaprun>"
    )
    with pytest.raises(InputError, match="unsafe XML"):
        read_nmap_xml(write(tmp_path, bomb), assets)


@pytest.mark.parametrize("text, message", [("<nmaprun>", "not valid XML"), ("<x/>", "nmaprun")])
def test_rejects_bad_files(tmp_path, assets, text, message):
    with pytest.raises(InputError, match=message):
        read_nmap_xml(write(tmp_path, text), assets)


def test_missing_file(tmp_path, assets):
    with pytest.raises(InputError, match="not found"):
        read_nmap_xml(tmp_path / "missing.xml", assets)
