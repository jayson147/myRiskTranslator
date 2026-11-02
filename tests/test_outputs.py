"""Tests for the register, heat map and summary outputs."""

import csv
from datetime import date

import pytest
from openpyxl import load_workbook

from risk_translator.iso_mapping import load_mapping
from risk_translator.models import Asset, Enrichment, Finding
from risk_translator.outputs.heatmap import count_cells, write_heatmap
from risk_translator.outputs.register import (
    COLUMNS,
    safe_text,
    write_register_csv,
    write_register_xlsx,
)
from risk_translator.outputs.summary import (
    NVD_NOTICE,
    REQUIRED_SECTIONS,
    SummaryContext,
    build_summary,
)
from risk_translator.pipeline import build_risks

WEB = Asset("booking-web", "10.0.10.5", "Head of Digital", "the booking website", 5, True)
WIKI = Asset("staff-wiki", "10.0.30.8", "IT Manager", "the staff wiki", 2)


@pytest.fixture
def risks(mapping_path):
    findings = [
        Finding(WIKI, "CVE-2023-48795", "test"),
        Finding(WEB, "CVE-2021-44228", "test", "tcp/443 https"),
        Finding(WEB, "CVE-2014-0160", "test"),
    ]
    enrichments = {
        "CVE-2021-44228": Enrichment(
            "CVE-2021-44228",
            10.0,
            "CRITICAL",
            "3.1",
            '=HYPERLINK("evil")',
            ["CWE-20"],
            0.94,
            0.999,
            True,
            "2021-12-10",
            True,
        ),
        "CVE-2014-0160": Enrichment(
            "CVE-2014-0160",
            7.5,
            "HIGH",
            "3.1",
            "Memory disclosure",
            ["CWE-200"],
            0.88,
            0.98,
            True,
            "2022-05-04",
        ),
        "CVE-2023-48795": Enrichment(
            "CVE-2023-48795",
            5.9,
            "MEDIUM",
            "3.1",
            "SSH prefix truncation",
            [],
            0.4,
            0.85,
            False,
            gaps=["Example gap"],
        ),
    }
    return build_risks(findings, enrichments, load_mapping(mapping_path))


def test_risks_sorted_and_numbered(risks):
    assert [(r.risk_id, r.finding.cve_id, r.score) for r in risks] == [
        ("R-001", "CVE-2021-44228", 25),
        ("R-002", "CVE-2014-0160", 20),
        ("R-003", "CVE-2023-48795", 3),
    ]
    assert [c.id for c in risks[0].controls] == ["8.8", "8.28"]
    assert risks[0].weakness == "Injection and code execution"


def test_register_csv(risks, tmp_path):
    path = tmp_path / "register.csv"
    write_register_csv(risks, path)
    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == COLUMNS
    assert len(rows) == 3
    assert [row["Score"] for row in rows] == ["25", "20", "3"]
    assert rows[0]["On KEV"] == "Yes" and rows[2]["On KEV"] == "No"
    assert rows[0]["ISO 27001 controls"].startswith("8.8 Management of technical vulnerabilities")
    assert rows[0]["Vulnerability description"].startswith("'=")  # formula defused


def test_register_xlsx(risks, tmp_path):
    path = tmp_path / "register.xlsx"
    write_register_xlsx(risks, path)
    sheet = load_workbook(path).active
    assert [cell.value for cell in sheet[1]] == COLUMNS
    assert sheet.max_row == 4
    assert sheet.freeze_panes == "A2"
    assert sheet.auto_filter.ref == sheet.dimensions
    band = sheet.cell(row=2, column=COLUMNS.index("Band") + 1)
    assert band.value == "Critical" and band.fill.fgColor.rgb.endswith("D7191C")
    description = sheet.cell(row=2, column=COLUMNS.index("Vulnerability description") + 1)
    assert description.data_type == "s"  # stored as text, not a formula


@pytest.mark.parametrize(
    "text, expected", [("=1+1", "'=1+1"), ("@SUM", "'@SUM"), ("-2", "'-2"), ("ok", "ok")]
)
def test_safe_text(text, expected):
    assert safe_text(text) == expected


def test_heatmap(risks, tmp_path):
    path = tmp_path / "heatmap.png"
    write_heatmap(risks, path)
    assert path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert count_cells(risks) == {(5, 5): 1, (5, 4): 1, (3, 1): 1}


def test_heatmap_with_no_risks(tmp_path):
    write_heatmap([], tmp_path / "heatmap.png")
    assert (tmp_path / "heatmap.png").exists()


def context(**extra) -> SummaryContext:
    return SummaryContext(
        input_name="cves.csv",
        asset_count=2,
        generated_on=date(2026, 1, 5),
        kev_version="2026.01.01",
        **extra,
    )


def test_summary_has_required_sections(risks):
    text = build_summary(risks, context())
    for section in REQUIRED_SECTIONS:
        assert section in text
    assert NVD_NOTICE in text
    assert "Prepared 5 January 2026" in text


def test_summary_content(risks):
    text = build_summary(risks, context())
    assert "**2 risks need action soon**" in text
    assert "**2 flaws are being actively exploited**" in text
    assert "Most exposed system: booking-web" in text
    assert "| booking-web | CVE-2021-44228 | 2021-12-10 | Yes | R-001 |" in text
    assert "ransomware" in text
    assert text.count("\n1. ") == 2  # top risks list and actions list


def test_summary_style_rules(risks):
    text = build_summary(risks, context(warnings=["NVD unavailable for CVE-1"]))
    assert "—" not in text  # no em dashes
    for american in ["prioritize", "organization", "analyze"]:
        assert american not in text.lower()


def test_summary_flags_incomplete_data(risks):
    text = build_summary(risks, context(warnings=["EPSS unavailable for 3 CVE(s)"]))
    assert "Warning: incomplete data" in text
    assert "- EPSS unavailable for 3 CVE(s)" in text


def test_summary_with_no_risks():
    text = build_summary([], context())
    assert "No vulnerabilities were found" in text
    assert "Warning: incomplete data" not in text
    for section in REQUIRED_SECTIONS:
        assert section in text


def test_summary_says_when_kev_is_unknown(risks):
    risks[0].enrichment.on_kev = None
    text = build_summary(risks, context())
    assert "could not check which flaws are being actively exploited" in text


def test_summary_singular_grammar(risks):
    text = build_summary(risks[2:], context())
    assert "**0 risks need action soon**" in text
    risks[0].band = "High"
    assert "**1 risk needs action soon**" in build_summary(risks[:1], context())


def actions_section(text: str) -> str:
    return text.split("## Recommended actions")[1].split("## How this was scored")[0]


def test_actions_put_actively_exploited_flaws_first(risks):
    actions = actions_section(build_summary(risks, context()))
    assert actions.count("\n1. ") == 1 and "\n3. " in actions and "\n4. " not in actions
    first = actions.split("\n2. ")[0]
    assert (
        "**Fix the 2 flaws that criminals are already using** on booking-web within 7 days."
        in first
    )


def test_actions_when_nothing_urgent(risks):
    actions = actions_section(build_summary(risks[2:], context()))
    assert "Keep the current patching routine" in actions
    assert "Close the gaps in this report" in actions  # risks[2] has a data gap
    assert "Repeat this assessment every month" in actions


def test_actions_ask_owners_for_fix_dates(risks):
    for risk in risks:
        risk.enrichment.on_kev = False
    risks[0].band = "Critical"
    actions = actions_section(build_summary(risks, context()))
    assert "Ask Head of Digital to commit to fix dates" in actions
    assert "Check whether booking-web needs" in actions or "Close the gaps" in actions


def test_actions_with_no_risks_still_three():
    actions = actions_section(build_summary([], context()))
    assert "\n3. " in actions


def test_top_risk_heading_names_the_weakness(risks):
    text = build_summary(risks, context())
    assert (
        "1. **booking-web: Injection and code execution** (Critical, score 25 of 25, R-001)" in text
    )
    assert "**staff-wiki: known software flaw**" in text
