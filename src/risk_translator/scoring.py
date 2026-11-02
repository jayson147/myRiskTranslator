"""Score each finding as likelihood x impact on a 5 x 5 matrix.

Every number in the DECISIONS block below is a placeholder copied from the
starting point in docs/SPEC.md. They are Jayson's calls: change them here, then
log each decision and the reason in docs/decisions.md.
"""

from risk_translator.models import Asset, Enrichment

# ---------------------------------------------------------------------------
# DECISIONS
# TODO(human): review every value in this block and log your choices in
# docs/decisions.md. The tests in tests/test_scoring.py encode these values,
# so update the expected results there when you change them.
# ---------------------------------------------------------------------------

# Asset criticality scale used in assets.yaml. TODO(human): confirm the levels
# and write what each one means for your organisation.
CRITICALITY_SCALE: dict[int, str] = {
    1: "Negligible",
    2: "Low",
    3: "Moderate",
    4: "High",
    5: "Critical",
}

# Likelihood. A CVE on CISA KEV is being exploited now, so it overrides EPSS.
# TODO(human): should KEV always override? (Options: always 5; 5 only if
# EPSS also high; KEV adds +1 on top of EPSS.)
KEV_LIKELIHOOD = 5

# EPSS percentile thresholds, checked from the top down: (minimum percentile, likelihood).
# EPSS returns the percentile as a fraction, so 0.95 means the 95th percentile.
EPSS_PERCENTILE_LIKELIHOOD: list[tuple[float, int]] = [
    (0.95, 4),
    (0.80, 3),
    (0.50, 2),
]

# Used when the percentile is below every threshold, or there is no EPSS score.
DEFAULT_LIKELIHOOD = 1

# Added to likelihood for internet-facing assets (capped at 5).
# TODO(human): decide. Options: 0 (ignore exposure, the current placeholder);
# +1 (exposed systems are easier to reach); or make exposure an impact factor.
INTERNET_FACING_LIKELIHOOD_BONUS = 0

# Impact starts from the CVSS severity band.
SEVERITY_IMPACT: dict[str, int] = {
    "NONE": 1,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Impact used when NVD has no CVSS score yet.
# TODO(human): decide. Options: 3 (assume high until proven otherwise, the
# cautious placeholder); 2 (assume medium); or leave unscored and flag only.
NO_CVSS_IMPACT = 3

# Impact adjustment for asset criticality (result kept within 1 to 5).
# TODO(human): the SPEC suggests +1 for critical and -1 for low; decide
# whether criticality 2 and 4 should also move impact.
CRITICALITY_IMPACT_ADJUSTMENT: dict[int, int] = {
    1: -1,
    2: 0,
    3: 0,
    4: 0,
    5: 1,
}

# Risk bands, checked from the top down: (minimum score, band).
# Note: no product of two numbers from 1 to 5 falls between 17 and 19.
BANDS: list[tuple[int, str]] = [
    (20, "Critical"),
    (10, "High"),
    (5, "Medium"),
    (1, "Low"),
]

# Suggested treatment per band. TODO(human): write the wording and timescales
# your organisation would actually commit to.
TREATMENTS: dict[str, str] = {
    "Critical": "Patch or mitigate within 7 days",
    "High": "Patch or mitigate within 30 days",
    "Medium": "Patch within 90 days, in the normal patch cycle",
    "Low": "Fix when convenient, or accept and record the risk",
}

# ---------------------------------------------------------------------------
# End of DECISIONS. The functions below only apply the rules above.
# ---------------------------------------------------------------------------

BAND_ORDER = [band for _, band in BANDS]  # highest first


def clamp(value: int, low: int = 1, high: int = 5) -> int:
    """Keep a value within the 1 to 5 scale."""
    return max(low, min(high, value))


def score_likelihood(enrichment: Enrichment, asset: Asset) -> tuple[int, list[str]]:
    """Return the likelihood (1 to 5) and short notes explaining how it was reached."""
    notes: list[str] = []
    if enrichment.on_kev:
        likelihood = KEV_LIKELIHOOD
        notes.append("On CISA KEV (exploited in the wild)")
    elif enrichment.epss_percentile is None:
        likelihood = DEFAULT_LIKELIHOOD
        notes.append("No EPSS score")
    else:
        likelihood = DEFAULT_LIKELIHOOD
        for threshold, level in EPSS_PERCENTILE_LIKELIHOOD:
            if enrichment.epss_percentile >= threshold:
                likelihood = level
                break
        notes.append(f"EPSS percentile {enrichment.epss_percentile:.0%}")

    if asset.internet_facing and INTERNET_FACING_LIKELIHOOD_BONUS:
        likelihood += INTERNET_FACING_LIKELIHOOD_BONUS
        notes.append(f"Internet-facing (+{INTERNET_FACING_LIKELIHOOD_BONUS})")
    return clamp(likelihood), notes


def score_impact(enrichment: Enrichment, asset: Asset) -> tuple[int, list[str]]:
    """Return the impact (1 to 5) and short notes explaining how it was reached."""
    notes: list[str] = []
    severity = (enrichment.cvss_severity or "").upper()
    if severity in SEVERITY_IMPACT:
        impact = SEVERITY_IMPACT[severity]
        notes.append(f"CVSS {severity.lower()}")
    else:
        impact = NO_CVSS_IMPACT
        notes.append(f"No CVSS score: impact assumed {NO_CVSS_IMPACT}")

    adjustment = CRITICALITY_IMPACT_ADJUSTMENT.get(asset.criticality, 0)
    if adjustment:
        impact += adjustment
        label = CRITICALITY_SCALE.get(asset.criticality, str(asset.criticality))
        notes.append(f"{label} asset ({adjustment:+d})")
    return clamp(impact), notes


def band_for(score: int) -> str:
    """Return the risk band for a score from 1 to 25."""
    for minimum, band in BANDS:
        if score >= minimum:
            return band
    return BANDS[-1][1]


def treatment_for(band: str) -> str:
    """Return the suggested treatment for a band."""
    return TREATMENTS.get(band, "Review")
