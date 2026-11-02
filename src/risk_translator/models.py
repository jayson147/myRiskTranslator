"""Data models shared across the tool.

The flow is: Asset + Finding (from the inputs) -> Enrichment (from public data)
-> Risk (scored, mapped and ready to write out).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Asset:
    """A system the organisation cares about, as described in assets.yaml.

    Attributes:
        name: Short unique name, used to match rows in the CVE list.
        ip: IP address, used to match hosts in an Nmap scan. Optional for CSV input.
        owner: The person or role accountable for the system's risk.
        description: One line on what the system does for the business.
        criticality: How much the system matters to the business, on the scale
            defined in scoring.CRITICALITY_SCALE.
        internet_facing: Whether the system can be reached from the internet.
    """

    name: str
    ip: str | None
    owner: str
    description: str
    criticality: int
    internet_facing: bool = False


@dataclass(frozen=True)
class Finding:
    """One CVE found on one asset (and, for scans, on one service).

    Attributes:
        asset: The affected asset.
        cve_id: The CVE identifier, normalised to upper case.
        source: Where the finding came from, for traceability (e.g. "cves.csv row 4").
        service: The affected network service, if known (e.g. "tcp/22 ssh OpenSSH 8.9p1").
    """

    asset: Asset
    cve_id: str
    source: str
    service: str = ""


@dataclass(frozen=True)
class Control:
    """An ISO/IEC 27001:2022 Annex A control, by number and our own short name."""

    id: str
    name: str

    def label(self) -> str:
        """Return the control as display text, such as "8.8 Management of technical ..."."""
        return f"{self.id} {self.name}"


@dataclass
class Enrichment:
    """Public data gathered about one CVE. A None value means the data is missing.

    Attributes:
        cve_id: The CVE identifier.
        cvss_score: CVSS base score, 0.0 to 10.0.
        cvss_severity: CVSS severity label: NONE, LOW, MEDIUM, HIGH or CRITICAL.
        cvss_version: Which CVSS version the score came from (e.g. "3.1").
        description: NVD's English description of the flaw.
        cwe_ids: Weakness types from NVD, e.g. ["CWE-502"].
        epss_score: Probability of exploitation activity in the next 30 days, 0 to 1.
        epss_percentile: How this CVE ranks against all scored CVEs, 0 to 1.
        on_kev: True if on CISA's Known Exploited Vulnerabilities list; None if unknown.
        kev_date_added: The date CISA added it to the list (YYYY-MM-DD).
        kev_ransomware: True if CISA says it is known to be used in ransomware campaigns.
        gaps: Plain-English notes about data that could not be found.
    """

    cve_id: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    description: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    epss_score: float | None = None
    epss_percentile: float | None = None
    on_kev: bool | None = None
    kev_date_added: str | None = None
    kev_ransomware: bool = False
    gaps: list[str] = field(default_factory=list)


@dataclass
class Risk:
    """A scored, mapped risk: one row of the register.

    Attributes:
        risk_id: Register reference such as "R-001", assigned after sorting.
        finding: The underlying finding (asset + CVE + service).
        enrichment: The public data used to score it.
        likelihood: 1 to 5.
        impact: 1 to 5.
        score: likelihood x impact, 1 to 25.
        band: Low, Medium, High or Critical.
        controls: ISO 27001 Annex A controls this risk maps to.
        treatment: Suggested treatment for the band.
        weakness: Plain-English name of the weakness group, if the CWE was mapped.
        board_summary: Plain-English description of the flaw for the summary.
        notes: How the score was reached and any data gaps, for the register.
    """

    risk_id: str
    finding: Finding
    enrichment: Enrichment
    likelihood: int
    impact: int
    score: int
    band: str
    controls: list[Control]
    treatment: str
    weakness: str | None = None
    board_summary: str | None = None
    notes: list[str] = field(default_factory=list)
