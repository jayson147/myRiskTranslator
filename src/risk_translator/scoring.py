"""Score each finding as likelihood x impact on a 5 x 5 matrix.

All the scoring rules live in the DECISIONS block below, each with the reason
for it. Change a rule here and update the matching rows in
tests/test_scoring.py.
"""

from risk_translator.models import Asset, Enrichment

# ---------------------------------------------------------------------------
# DECISIONS
# ---------------------------------------------------------------------------

# Asset criticality scale used in assets.yaml. "Importance" means the harm to
# the business if the system were breached or went offline.
#   1 Negligible: test or lab system, no business data; an outage goes unnoticed.
#   2 Low: internal convenience tool, no sensitive data; an outage is an annoyance.
#   3 Moderate: supports day-to-day work or holds internal data; an outage
#     disrupts teams for a day or so.
#   4 High: runs an important business process or holds personal or financial
#     data; a breach could mean financial loss or a report to the regulator.
#   5 Critical: customer-facing or core to revenue, or holds payment or special
#     category data; a breach would cause serious financial, legal or
#     reputational harm.
CRITICALITY_SCALE: dict[int, str] = {
    1: "Negligible",
    2: "Low",
    3: "Moderate",
    4: "High",
    5: "Critical",
}

# Likelihood. A CVE on CISA KEV always scores 5: confirmed exploitation in the
# wild is stronger evidence than any forecast, so it overrides EPSS.
KEV_LIKELIHOOD = 5

# EPSS percentile thresholds, checked from the top down: (minimum percentile,
# likelihood). We use the percentile rather than the raw score because raw EPSS
# scores are mostly tiny; the percentile says how a flaw ranks against all
# others, which is easier to explain. EPSS gives it as a fraction (0.95 = 95th).
EPSS_PERCENTILE_LIKELIHOOD: list[tuple[float, int]] = [
    (0.95, 4),  # top 5% of all CVEs
    (0.80, 3),  # top 20%
    (0.50, 2),  # top half
]

# Used when the percentile is below every threshold, or there is no EPSS score.
DEFAULT_LIKELIHOOD = 1

# Internet-facing systems can be reached by any attacker in the world, not just
# someone already inside the network, so they get +1 likelihood (capped at 5).
# Exposure changes how likely an attack is, not how much damage it does, which
# is why it adjusts likelihood rather than impact.
INTERNET_FACING_LIKELIHOOD_BONUS = 1

# Impact starts from the CVSS severity band. The maximum from CVSS alone is 4,
# so only the asset's importance can push impact to 5: technical severity alone
# never decides that a risk is as bad as it gets for the business.
SEVERITY_IMPACT: dict[str, int] = {
    "NONE": 1,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Impact used when NVD has no CVSS score yet. We assume "high" (3) rather than
# skipping or downgrading it: brand-new CVEs are often waiting for NVD analysis
# and can be the most urgent. A note in the register flags the estimate.
NO_CVSS_IMPACT = 3

# Impact adjustment for asset criticality (result kept within 1 to 5). A flaw on
# a system that matters little does less damage, and one on an important system
# does more. Moderate (3) is the neutral point; each side moves by one step.
CRITICALITY_IMPACT_ADJUSTMENT: dict[int, int] = {
    1: -1,
    2: -1,
    3: 0,
    4: 1,
    5: 1,
}

# Risk bands, checked from the top down: (minimum score, band). Critical needs
# both likelihood and impact near the top (5 x 4, 4 x 5 or 5 x 5), so it is
# kept for flaws that are both likely to be used and damaging if they are.
# Note: no product of two numbers from 1 to 5 falls between 17 and 19.
BANDS: list[tuple[int, str]] = [
    (20, "Critical"),
    (10, "High"),
    (5, "Medium"),
    (1, "Low"),
]

# Suggested treatment per band. The 14-day target for High matches the UK
# Cyber Essentials rule for high and critical security updates; Critical is
# tighter because these flaws are being used or about to be.
TREATMENTS: dict[str, str] = {
    "Critical": "Fix or put a workaround in place within 7 days, and tell the owner today",
    "High": "Fix within 14 days",
    "Medium": "Fix within 30 days, in the monthly patch cycle",
    "Low": "Fix at the next scheduled update, or accept the risk with the owner's sign-off",
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
