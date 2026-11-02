"""Scoring table: example inputs with the expected likelihood, impact, score and band.

These expectations encode the decisions in scoring.py. When you change a
decision there, update the matching rows here.
"""

import pytest

from risk_translator.models import Asset, Enrichment
from risk_translator.scoring import band_for, score_impact, score_likelihood, treatment_for

CRITICAL = Asset("crit", None, "o", "", criticality=5)
HIGH = Asset("high", None, "o", "", criticality=4)
MODERATE = Asset("mod", None, "o", "", criticality=3)
MINOR = Asset("minor", None, "o", "", criticality=2)
LOW = Asset("low", None, "o", "", criticality=1)
EXPOSED = Asset("web", None, "o", "", criticality=3, internet_facing=True)


def data(**fields) -> Enrichment:
    return Enrichment(cve_id="CVE-2000-0001", **fields)


CASES = [
    # (description, enrichment, asset, likelihood, impact, score, band)
    (
        "on KEV overrides low EPSS",
        data(on_kev=True, epss_percentile=0.1, cvss_severity="CRITICAL"),
        MODERATE,
        5,
        4,
        20,
        "Critical",
    ),
    (
        "on KEV, critical asset",
        data(on_kev=True, cvss_severity="CRITICAL"),
        CRITICAL,
        5,
        5,
        25,
        "Critical",
    ),
    (
        "EPSS 95th percentile",
        data(on_kev=False, epss_percentile=0.95, cvss_severity="HIGH"),
        MODERATE,
        4,
        3,
        12,
        "High",
    ),
    (
        "EPSS 80th percentile",
        data(epss_percentile=0.80, cvss_severity="HIGH"),
        MODERATE,
        3,
        3,
        9,
        "Medium",
    ),
    (
        "EPSS just under 80th",
        data(epss_percentile=0.7999, cvss_severity="MEDIUM"),
        MODERATE,
        2,
        2,
        4,
        "Low",
    ),
    (
        "EPSS 50th percentile",
        data(epss_percentile=0.50, cvss_severity="CRITICAL"),
        MODERATE,
        2,
        4,
        8,
        "Medium",
    ),
    (
        "EPSS below 50th",
        data(epss_percentile=0.49, cvss_severity="CRITICAL"),
        MODERATE,
        1,
        4,
        4,
        "Low",
    ),
    ("no EPSS score", data(cvss_severity="CRITICAL"), MODERATE, 1, 4, 4, "Low"),
    ("no CVSS score", data(epss_percentile=0.96), MODERATE, 4, 3, 12, "High"),
    ("no data at all", data(), MODERATE, 1, 3, 3, "Low"),
    (
        "critical asset lifts impact",
        data(epss_percentile=0.85, cvss_severity="HIGH"),
        CRITICAL,
        3,
        4,
        12,
        "High",
    ),
    (
        "critical asset capped at 5",
        data(on_kev=True, cvss_severity="CRITICAL"),
        CRITICAL,
        5,
        5,
        25,
        "Critical",
    ),
    (
        "low-criticality asset lowers impact",
        data(epss_percentile=0.97, cvss_severity="HIGH"),
        LOW,
        4,
        2,
        8,
        "Medium",
    ),
    ("low asset floored at 1", data(cvss_severity="LOW"), LOW, 1, 1, 1, "Low"),
    ("CVSS none counts as 1", data(cvss_severity="NONE"), MODERATE, 1, 1, 1, "Low"),
    ("lower-case severity accepted", data(cvss_severity="high"), MODERATE, 1, 3, 3, "Low"),
    (
        "high asset lifts impact",
        data(on_kev=True, cvss_severity="HIGH"),
        HIGH,
        5,
        4,
        20,
        "Critical",
    ),
    (
        "minor asset lowers impact",
        data(epss_percentile=0.9, cvss_severity="HIGH"),
        MINOR,
        3,
        2,
        6,
        "Medium",
    ),
    (
        "internet-facing adds 1",
        data(epss_percentile=0.96, cvss_severity="HIGH"),
        EXPOSED,
        5,
        3,
        15,
        "High",
    ),
    ("internet-facing, no EPSS", data(cvss_severity="MEDIUM"), EXPOSED, 2, 2, 4, "Low"),
    (
        "internet-facing on KEV capped at 5",
        data(on_kev=True, cvss_severity="CRITICAL"),
        EXPOSED,
        5,
        4,
        20,
        "Critical",
    ),
]


@pytest.mark.parametrize(
    "enrichment, asset, likelihood, impact, score, band",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_scoring_table(enrichment, asset, likelihood, impact, score, band):
    got_likelihood, _ = score_likelihood(enrichment, asset)
    got_impact, _ = score_impact(enrichment, asset)
    assert (got_likelihood, got_impact) == (likelihood, impact)
    assert got_likelihood * got_impact == score
    assert band_for(score) == band


def test_internet_facing_note():
    _, notes = score_likelihood(data(epss_percentile=0.96), EXPOSED)
    assert notes == ["EPSS percentile 96%", "Internet-facing (+1)"]


def test_no_bonus_when_switched_off(monkeypatch):
    monkeypatch.setattr("risk_translator.scoring.INTERNET_FACING_LIKELIHOOD_BONUS", 0)
    assert score_likelihood(data(epss_percentile=0.96), EXPOSED)[0] == 4


def test_notes_explain_the_score():
    _, notes = score_likelihood(data(epss_percentile=0.96), MODERATE)
    assert notes == ["EPSS percentile 96%"]
    _, notes = score_impact(data(), CRITICAL)
    assert notes == ["No CVSS score: impact assumed 3", "Critical asset (+1)"]


@pytest.mark.parametrize(
    "score, band",
    [
        (1, "Low"),
        (4, "Low"),
        (5, "Medium"),
        (9, "Medium"),
        (10, "High"),
        (16, "High"),
        (20, "Critical"),
        (25, "Critical"),
    ],
)
def test_band_edges(score, band):
    assert band_for(score) == band


def test_every_band_has_a_treatment():
    for band in ["Low", "Medium", "High", "Critical"]:
        assert treatment_for(band) != "Review"
