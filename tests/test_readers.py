"""Tests for the assets file and CVE list readers, including the error cases."""

from pathlib import Path

import pytest

from risk_translator.errors import InputError
from risk_translator.readers import (
    detect_input_type,
    load_assets,
    normalise_cve_id,
    read_cve_csv,
)

ASSETS_YAML = """
assets:
  - name: web
    ip: 10.0.0.1
    owner: Head of Digital
    description: the website
    criticality: 5
    internet_facing: true
  - name: wiki
    owner: IT Manager
    criticality: 2
"""


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def assets(tmp_path):
    return load_assets(write(tmp_path, "assets.yaml", ASSETS_YAML))


# --- assets.yaml ---------------------------------------------------------


def test_load_assets_reads_every_field(assets):
    web = assets.find("web")
    assert web.ip == "10.0.0.1"
    assert web.owner == "Head of Digital"
    assert web.criticality == 5
    assert web.internet_facing is True
    wiki = assets.find("WIKI")  # names match case-insensitively
    assert wiki.ip is None and wiki.internet_facing is False
    assert len(assets) == 2


def test_find_matches_ip(assets):
    assert assets.find("10.0.0.1").name == "web"
    assert assets.find_by_ip("10.0.0.1").name == "web"
    assert assets.find("nope") is None


def test_sample_assets_file_is_valid(samples_dir):
    assert len(load_assets(samples_dir / "assets.yaml")) == 3


@pytest.mark.parametrize(
    "entry, message",
    [
        ("- {name: a, owner: o, criticality: 7}", "'criticality' must be one of"),
        ("- {name: a, owner: o, criticality: true}", "'criticality' must be one of"),
        ("- {name: a, criticality: 3}", "'owner' is required"),
        ("- {owner: o, criticality: 3}", "'name' is required"),
        ("- {name: a, owner: o, criticality: 3, ip: 999.1.1.1}", "not a valid IP"),
        ("- {name: a, owner: o, criticality: 3, internet_facing: maybe}", "true or false"),
        (
            "- {name: a, owner: o, criticality: 3}\n  - {name: A, owner: o, criticality: 3}",
            "used more than once",
        ),
        ("- just a string", "expected a mapping"),
    ],
)
def test_load_assets_rejects_bad_entries(tmp_path, entry, message):
    path = write(tmp_path, "assets.yaml", f"assets:\n  {entry}\n")
    with pytest.raises(InputError, match=message):
        load_assets(path)


def test_load_assets_reports_all_problems_at_once(tmp_path):
    text = "assets:\n  - {name: a, criticality: 9}\n  - {name: b, owner: o, criticality: 0}\n"
    with pytest.raises(InputError) as error:
        load_assets(write(tmp_path, "assets.yaml", text))
    assert "3 problem(s)" in str(error.value)


@pytest.mark.parametrize("text", ["", "assets: []", "- a\n- b", "assets: [unclosed"])
def test_load_assets_rejects_bad_files(tmp_path, text):
    with pytest.raises(InputError):
        load_assets(write(tmp_path, "assets.yaml", text))


def test_load_assets_missing_file(tmp_path):
    with pytest.raises(InputError, match="not found"):
        load_assets(tmp_path / "missing.yaml")


# --- CVE list ------------------------------------------------------------


def test_read_csv_builds_findings(tmp_path, assets):
    path = write(tmp_path, "cves.csv", "asset,cve\nweb,cve-2021-44228\n\n10.0.0.1,CVE-2014-0160\n")
    result = read_cve_csv(path, assets)
    assert [(f.asset.name, f.cve_id) for f in result.findings] == [
        ("web", "CVE-2021-44228"),
        ("web", "CVE-2014-0160"),
    ]
    assert result.findings[0].source == "cves.csv row 2"
    assert result.warnings == []


def test_read_csv_accepts_excel_bom_and_header_case(tmp_path, assets):
    path = tmp_path / "cves.csv"
    path.write_bytes("﻿Asset , CVE\nweb,CVE-2021-44228\n".encode())
    assert len(read_cve_csv(path, assets).findings) == 1


def test_sample_csv_reads_cleanly(samples_dir):
    assets = load_assets(samples_dir / "assets.yaml")
    result = read_cve_csv(samples_dir / "cves.csv", assets)
    assert len(result.findings) == 8
    assert {f.asset.name for f in result.findings} == {"booking-web", "finance-db", "staff-wiki"}


@pytest.mark.parametrize(
    "rows, message",
    [
        ("web,CVE-21-44228", "not a valid CVE ID"),
        ("web,log4shell", "not a valid CVE ID"),
        ("web,", "not a valid CVE ID"),
        ("unknown-host,CVE-2021-44228", "not in the assets file"),
        ("web,CVE-2021-44228\nweb,cve-2021-44228", "duplicate of an earlier row"),
    ],
)
def test_read_csv_errors(tmp_path, assets, rows, message):
    path = write(tmp_path, "cves.csv", f"asset,cve\n{rows}\n")
    with pytest.raises(InputError, match=message):
        read_cve_csv(path, assets)


def test_read_csv_error_names_the_row(tmp_path, assets):
    path = write(tmp_path, "cves.csv", "asset,cve\nweb,CVE-2021-44228\nweb,BAD\n")
    with pytest.raises(InputError, match="row 3"):
        read_cve_csv(path, assets)


def test_read_csv_needs_header(tmp_path, assets):
    path = write(tmp_path, "cves.csv", "host,vuln\nweb,CVE-2021-44228\n")
    with pytest.raises(InputError, match="'asset' and 'cve' columns"):
        read_cve_csv(path, assets)


def test_normalise_cve_id():
    assert normalise_cve_id(" cve-2021-44228 ") == "CVE-2021-44228"
    assert normalise_cve_id("CVE-2024-123456") == "CVE-2024-123456"
    assert normalise_cve_id("CVE-2024-123") is None
    assert normalise_cve_id("CVE-2024-1234; DROP") is None


@pytest.mark.parametrize(
    "name, override, expected",
    [("a.csv", None, "csv"), ("a.XML", None, "nmap"), ("a.txt", "csv", "csv")],
)
def test_detect_input_type(name, override, expected):
    assert detect_input_type(Path(name), override) == expected


def test_detect_input_type_unknown_extension():
    with pytest.raises(InputError, match="--input-type"):
        detect_input_type(Path("scan.txt"))
