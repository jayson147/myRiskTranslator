"""Combine KEV, EPSS and NVD data into one Enrichment per CVE.

If a source is down, we carry on: the affected fields stay empty, the gap is
noted on each Enrichment, and a warning is returned for the summary.
"""

import logging
import time
from collections.abc import Callable
from pathlib import Path

from risk_translator.cache import DiskCache
from risk_translator.errors import SourceUnavailable
from risk_translator.models import Enrichment
from risk_translator.sources.epss import fetch_epss
from risk_translator.sources.fetch import HttpSession, new_session
from risk_translator.sources.kev import KevCatalogue, load_kev
from risk_translator.sources.nvd import fetch_nvd

log = logging.getLogger(__name__)


def enrich_cves(
    cve_ids: list[str],
    cache_dir: Path,
    api_key: str | None = None,
    offline: bool = False,
    refresh: bool = False,
    session: HttpSession | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, Enrichment], list[str], str | None]:
    """Gather public data for each unique CVE.

    Returns (enrichments by CVE ID, warnings, KEV catalogue version or None).
    """
    session = session or new_session()
    cache = DiskCache(cache_dir, refresh=refresh)
    unique = list(dict.fromkeys(cve_ids))
    warnings: list[str] = []

    kev: KevCatalogue | None
    try:
        kev = load_kev(session, cache, offline=offline, sleep=sleep)
    except SourceUnavailable as exc:
        kev = None
        warnings.append(f"CISA KEV catalogue unavailable ({exc}): KEV status is unknown")

    epss, epss_warnings = fetch_epss(unique, session, cache, offline=offline, sleep=sleep)
    warnings.extend(epss_warnings)
    nvd, nvd_warnings = fetch_nvd(unique, session, cache, api_key, offline=offline, sleep=sleep)
    warnings.extend(nvd_warnings)

    enrichments: dict[str, Enrichment] = {}
    for cve_id in unique:
        item = Enrichment(cve_id=cve_id)

        if kev is None:
            item.gaps.append("KEV status unknown")
        else:
            entry = kev.lookup(cve_id)
            item.on_kev = entry is not None
            if entry:
                item.kev_date_added = entry.date_added
                item.kev_ransomware = entry.ransomware

        if cve_id not in epss:
            item.gaps.append("EPSS unavailable")
        elif epss[cve_id] is not None:
            item.epss_score = epss[cve_id].score
            item.epss_percentile = epss[cve_id].percentile

        if cve_id not in nvd:
            item.gaps.append("NVD unavailable")
        elif nvd[cve_id] is None:
            item.gaps.append("Not found in NVD")
        else:
            record = nvd[cve_id]
            item.cvss_score = record.cvss_score
            item.cvss_severity = record.cvss_severity
            item.cvss_version = record.cvss_version
            item.description = record.description
            item.cwe_ids = record.cwe_ids
            if record.status.lower() == "rejected":
                item.gaps.append("NVD marks this CVE as rejected")
            if record.cvss_score is None:
                item.gaps.append("No CVSS score in NVD yet")

        enrichments[cve_id] = item
    return enrichments, warnings, kev.version if kev else None
