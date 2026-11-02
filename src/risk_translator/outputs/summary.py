"""Write summary.md: a one-page summary of the register for a board.

Plain English, business impact first, no jargon without a short explanation.
British English and no em dashes, as set out in CLAUDE.md.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from risk_translator.models import Risk
from risk_translator.scoring import BAND_ORDER, CRITICALITY_SCALE, TREATMENTS

TOP_N = 5
MAX_KEV_ROWS = 10

REQUIRED_SECTIONS = [
    "## The headline",
    "## Top five risks",
    "## Being exploited right now",
    "## Recommended actions",
    "## How this was scored",
    "## Gaps in this report",
    "## Data sources",
]

NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD."


@dataclass
class SummaryContext:
    """Facts about the run that the summary reports alongside the risks."""

    input_name: str
    asset_count: int
    generated_on: date = field(default_factory=date.today)
    warnings: list[str] = field(default_factory=list)
    kev_version: str | None = None


def _plural(count: int, word: str, plural: str | None = None) -> str:
    return f"{count} {word if count == 1 else (plural or word + 's')}"


def _epss_phrase(risk: Risk) -> str:
    """Describe the EPSS forecast in plain English, or '' if there is none."""
    score = risk.enrichment.epss_score
    if score is None:
        return ""
    chance = "less than 1%" if score < 0.01 else f"about {score:.0%}"
    return f"Industry forecasts put the chance of attacks on it in the next 30 days at {chance}."


def _lower_first(text: str) -> str:
    return text[:1].lower() + text[1:]


def _upper_first(text: str) -> str:
    return text[:1].upper() + text[1:]


def _why_it_matters(risk: Risk) -> str:
    asset = risk.finding.asset
    level = CRITICALITY_SCALE.get(asset.criticality, str(asset.criticality)).lower()
    parts = []
    if asset.description:
        parts.append(f"It affects {asset.name}, {_lower_first(asset.description)}.")
    parts.append(
        f"The business rates this system's importance as {level} ({asset.criticality} of 5)."
    )
    if asset.internet_facing:
        parts.append("It can be reached from the internet.")
    if risk.enrichment.on_kev:
        parts.append("Criminals are already exploiting this flaw elsewhere.")
        if risk.enrichment.kev_ransomware:
            parts.append("It has been used in ransomware attacks.")
    else:
        epss = _epss_phrase(risk)
        if epss:
            parts.append(epss)
    return " ".join(parts)


def _headline(risks: list[Risk], context: SummaryContext) -> list[str]:
    bands = Counter(risk.band for risk in risks)
    systems = {risk.finding.asset.name for risk in risks}
    kev = [risk for risk in risks if risk.enrichment.on_kev]
    lines = ["## The headline", ""]
    if not risks:
        return [*lines, "No vulnerabilities were found in this scan.", ""]
    urgent = bands["Critical"] + bands["High"]
    lines.append(
        f"- **{_plural(urgent, 'risk')} {'needs' if urgent == 1 else 'need'} action soon**: "
        f"{bands['Critical']} critical and {bands['High']} high, out of "
        f"{_plural(len(risks), 'risk')} across {_plural(len(systems), 'system')}."
    )
    if any(risk.enrichment.on_kev is None for risk in risks):
        lines.append(
            "- **We could not check which flaws are being actively exploited**, because the "
            "US government's list of known exploited vulnerabilities was unavailable."
        )
    else:
        lines.append(
            f"- **{_plural(len(kev), 'flaw')} {'is' if len(kev) == 1 else 'are'} being actively "
            "exploited** by attackers today, according to the US government's list of known "
            "exploited vulnerabilities."
        )
    by_asset = Counter(risk.finding.asset.name for risk in risks)
    worst = risks[0]
    lines.append(
        f"- **Most exposed system: {worst.finding.asset.name}** "
        f"({_plural(by_asset[worst.finding.asset.name], 'risk')}, "
        f"highest score {worst.score} of 25, owner: {worst.finding.asset.owner})."
    )
    lines += ["", "| Band | Risks | Suggested treatment |", "|---|---|---|"]
    lines += [f"| {band} | {bands[band]} | {TREATMENTS.get(band, '')} |" for band in BAND_ORDER]
    return [*lines, ""]


def _top_risks(risks: list[Risk]) -> list[str]:
    lines = ["## Top five risks", ""]
    if not risks:
        return [*lines, "None.", ""]
    for number, risk in enumerate(risks[:TOP_N], start=1):
        asset = risk.finding.asset
        lines.append(
            f"{number}. **{asset.name}: {risk.board_summary}** "
            f"({risk.band}, score {risk.score} of 25, {risk.risk_id})"
        )
        what = _upper_first(risk.board_summary or "")
        lines.append(f"   - *What it is:* {what} ({risk.enrichment.cve_id}).")
        lines.append(f"   - *Why it matters:* {_why_it_matters(risk)}")
        lines.append(f"   - *What to do:* {risk.treatment}. Owner: {asset.owner}.")
    return [*lines, ""]


def _kev_section(risks: list[Risk]) -> list[str]:
    lines = ["## Being exploited right now", ""]
    kev = [risk for risk in risks if risk.enrichment.on_kev]
    if not kev:
        return [*lines, "None of the findings are on the known exploited list.", ""]
    lines += [
        "These flaws are on CISA's Known Exploited Vulnerabilities list, so fix them first.",
        "",
        "| System | Flaw | On the list since | Used in ransomware | Risk |",
        "|---|---|---|---|---|",
    ]
    for risk in kev[:MAX_KEV_ROWS]:
        lines.append(
            f"| {risk.finding.asset.name} | {risk.enrichment.cve_id} | "
            f"{risk.enrichment.kev_date_added or 'unknown'} | "
            f"{'Yes' if risk.enrichment.kev_ransomware else 'Not known'} | {risk.risk_id} |"
        )
    if len(kev) > MAX_KEV_ROWS:
        lines.append(f"\n...and {len(kev) - MAX_KEV_ROWS} more in the register.")
    return [*lines, ""]


def _actions(risks: list[Risk]) -> list[str]:
    """Three recommended actions, chosen by rules from the results.

    TODO(human): these rules and their wording are placeholders. Decide what a
    board should be asked to do, and rewrite them in your own words.
    """
    kev = [risk for risk in risks if risk.enrichment.on_kev]
    urgent = [risk for risk in risks if risk.band in ("Critical", "High")]
    actions: list[str] = []
    if kev:
        systems = sorted({risk.finding.asset.name for risk in kev})
        actions.append(
            f"Fix the {_plural(len(kev), 'actively exploited flaw')} first, on "
            f"{', '.join(systems)}. {TREATMENTS.get('Critical', '')}."
        )
    if urgent:
        owners = sorted({risk.finding.asset.owner for risk in urgent})
        actions.append(
            f"Ask {', '.join(owners)} to agree fix dates for the "
            f"{_plural(len(urgent), 'critical or high risk')} "
            "and report progress at the next meeting."
        )
    actions += [
        "Repeat this assessment monthly, so new flaws and fixes are tracked over time.",
        "Confirm each system's importance rating with its owner, as it drives these scores.",
        "Patch the medium and low risks through the normal monthly update cycle.",
    ]
    lines = ["## Recommended actions", ""]
    lines += [f"{number}. {action}" for number, action in enumerate(actions[:3], start=1)]
    return [*lines, ""]


def _method() -> list[str]:
    return [
        "## How this was scored",
        "",
        "Each finding is a known software flaw (a *CVE*, the public ID for a vulnerability) "
        "on one of our systems. Each gets two scores from 1 to 5:",
        "",
        "- **Likelihood:** how likely an attack is. Flaws on CISA's *KEV* list (known to be "
        "exploited right now) score highest. Otherwise we use *EPSS*, an industry forecast of "
        "how likely a flaw is to be attacked in the next 30 days.",
        "- **Impact:** how much damage it could do. We start from *CVSS*, the standard 0 to 10 "
        "severity rating, and adjust it for how important the system is to the business.",
        "",
        "Risk score = likelihood x impact, from 1 to 25. Each risk is mapped to the matching "
        "ISO/IEC 27001:2022 controls, the security standard we measure ourselves against.",
        "",
    ]


def _gaps(context: SummaryContext, risks: list[Risk]) -> list[str]:
    lines = ["## Gaps in this report", ""]
    gaps = list(context.warnings)
    missing_cvss = [r for r in risks if r.enrichment.cvss_score is None]
    if missing_cvss:
        gaps.append(
            f"{_plural(len(missing_cvss), 'finding')} had no severity score yet, "
            "so impact was estimated."
        )
    if not gaps:
        return [*lines, "None: all data sources answered for every finding.", ""]
    return [*lines, *[f"- {gap}" for gap in gaps], ""]


def _credits(context: SummaryContext) -> list[str]:
    kev = f" (catalogue version {context.kev_version})" if context.kev_version else ""
    return [
        "## Data sources",
        "",
        "- Severity, descriptions and weakness types: NIST National Vulnerability Database "
        f"(NVD). {NVD_NOTICE}",
        "- Exploit forecasts: EPSS, by FIRST (first.org/epss).",
        f"- Known exploited flaws: CISA Known Exploited Vulnerabilities catalogue{kev}.",
        "- Controls are cited from ISO/IEC 27001:2022 Annex A by number and short name only.",
        "",
    ]


def build_summary(risks: list[Risk], context: SummaryContext) -> str:
    """Return the summary as Markdown. risks must already be sorted, highest first."""
    lines = [
        "# Cyber risk summary",
        "",
        f"Prepared {context.generated_on.day} {context.generated_on:%B %Y} "
        f"from `{context.input_name}`, "
        f"covering {_plural(context.asset_count, 'system')} in the asset list. "
        "Full detail is in the risk register (register.xlsx) and the heat map (heatmap.png).",
        "",
    ]
    if context.warnings or any(risk.enrichment.gaps for risk in risks):
        lines += [
            "> **Warning: incomplete data.** Some public data could not be retrieved, so some "
            "scores may understate the real risk. See *Gaps in this report* below.",
            "",
        ]
    lines += _headline(risks, context)
    lines += _top_risks(risks)
    lines += _kev_section(risks)
    lines += _actions(risks)
    lines += _method()
    lines += _gaps(context, risks)
    lines += _credits(context)
    return "\n".join(lines).rstrip() + "\n"


def write_summary(risks: list[Risk], context: SummaryContext, path: Path) -> None:
    """Write summary.md."""
    path.write_text(build_summary(risks, context), encoding="utf-8")
