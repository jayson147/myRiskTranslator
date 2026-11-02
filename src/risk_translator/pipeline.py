"""Turn findings plus enrichment into scored, mapped, sorted risks."""

from risk_translator.iso_mapping import IsoMapping
from risk_translator.models import Enrichment, Finding, Risk
from risk_translator.scoring import band_for, score_impact, score_likelihood, treatment_for

FALLBACK_BOARD_SUMMARY = "a known security flaw in the software"


def _sort_key(risk: Risk) -> tuple:
    """Highest score first; ties broken by likelihood, then CVSS, then name for stability."""
    cvss = risk.enrichment.cvss_score if risk.enrichment.cvss_score is not None else -1.0
    return (-risk.score, -risk.likelihood, -cvss, risk.finding.asset.name, risk.finding.cve_id)


def build_risk(finding: Finding, enrichment: Enrichment, mapping: IsoMapping) -> Risk:
    """Score and map one finding. The risk ID is filled in later, after sorting."""
    likelihood, likelihood_notes = score_likelihood(enrichment, finding.asset)
    impact, impact_notes = score_impact(enrichment, finding.asset)
    score = likelihood * impact
    band = band_for(score)
    group = mapping.group_for(enrichment.cwe_ids)
    return Risk(
        risk_id="",
        finding=finding,
        enrichment=enrichment,
        likelihood=likelihood,
        impact=impact,
        score=score,
        band=band,
        controls=mapping.controls_for(enrichment.cwe_ids),
        treatment=treatment_for(band),
        weakness=group.name if group else None,
        board_summary=(group.board_summary if group and group.board_summary else None)
        or FALLBACK_BOARD_SUMMARY,
        notes=likelihood_notes + impact_notes + enrichment.gaps,
    )


def build_risks(
    findings: list[Finding], enrichments: dict[str, Enrichment], mapping: IsoMapping
) -> list[Risk]:
    """Score, map and sort every finding, then number them R-001, R-002, ..."""
    risks = [
        build_risk(f, enrichments.get(f.cve_id) or Enrichment(cve_id=f.cve_id), mapping)
        for f in findings
    ]
    risks.sort(key=_sort_key)
    for number, risk in enumerate(risks, start=1):
        risk.risk_id = f"R-{number:03d}"
    return risks
