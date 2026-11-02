"""NIST National Vulnerability Database (NVD) CVE API 2.0.

One request per CVE: GET .../cves/2.0?cveId=CVE-2021-44228. We take the CVSS
base score and severity, the English description and the CWE weakness IDs.

Rate limits: about 5 requests per 30 seconds without an API key, 50 with one.
We pause between requests to stay under that, back off and retry on HTTP 403
or 429 (NVD's "slow down" responses), and cache each CVE for a week because
NVD records change slowly. The key is sent in a header, never in the URL, and
is never printed or logged.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from risk_translator.cache import DiskCache
from risk_translator.errors import SourceUnavailable
from risk_translator.sources.fetch import HttpSession, fetch_json

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_NAMESPACE = "nvd"
MAX_AGE = timedelta(days=7)
PAUSE_WITH_KEY = 0.7  # seconds between requests: 50 per 30 s allowed
PAUSE_WITHOUT_KEY = 6.5  # 5 per 30 s allowed
RETRY_STATUSES = frozenset({403, 429, 500, 502, 503, 504})

# Which CVSS version to use, best first. v3.1 is what most current scores use.
# v3.0 is nearly identical. v4.0 is newer but still sparse in NVD. v2 is the old
# system (no "Critical" rating), used only when nothing newer exists.
CVSS_PREFERENCE: list[tuple[str, str]] = [
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
]
IGNORED_CWES = {"NVD-CWE-Other", "NVD-CWE-noinfo"}


@dataclass(frozen=True)
class NvdRecord:
    """The fields we use from one NVD CVE record."""

    cvss_score: float | None
    cvss_severity: str | None
    cvss_version: str | None
    description: str | None
    cwe_ids: list[str] = field(default_factory=list)
    status: str = ""


def severity_from_score(score: float) -> str:
    """Return the CVSS v3 severity label for a base score."""
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _pick_metric(metrics: dict) -> tuple[dict, str] | None:
    """Return the best CVSS metric and its version, preferring NVD's own (Primary) score."""
    for key, version in CVSS_PREFERENCE:
        candidates = metrics.get(key) or []
        if candidates:
            primary = [m for m in candidates if m.get("type") == "Primary"]
            return (primary or candidates)[0], version
    return None


def parse_nvd_cve(cve: dict) -> NvdRecord:
    """Pull the fields we need out of one NVD 'cve' object."""
    score = severity = version = None
    picked = _pick_metric(cve.get("metrics") or {})
    if picked:
        metric, version = picked
        data = metric.get("cvssData") or {}
        if data.get("baseScore") is not None:
            score = float(data["baseScore"])
        # v3 and v4 put severity inside cvssData; v2 puts it on the metric itself.
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        if severity is None and score is not None:
            severity = severity_from_score(score)
        severity = severity.upper() if severity else None

    description = next(
        (d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"),
        None,
    )

    cwe_ids: list[str] = []
    weaknesses = cve.get("weaknesses") or []
    # NVD's own analysis ("Primary") first, then other sources ("Secondary").
    weaknesses = sorted(weaknesses, key=lambda w: w.get("type") != "Primary")
    for weakness in weaknesses:
        for item in weakness.get("description") or []:
            value = item.get("value", "")
            if value.startswith("CWE-") and value not in IGNORED_CWES:
                cwe_ids.append(value)

    return NvdRecord(
        cvss_score=score,
        cvss_severity=severity,
        cvss_version=version,
        description=description,
        cwe_ids=list(dict.fromkeys(cwe_ids)),
        status=str(cve.get("vulnStatus", "")),
    )


def _from_cache_entry(entry: dict) -> NvdRecord | None:
    return parse_nvd_cve(entry["cve"]) if entry.get("found") else None


def fetch_nvd(
    cve_ids: list[str],
    session: HttpSession,
    cache: DiskCache,
    api_key: str | None = None,
    offline: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, NvdRecord | None], list[str]]:
    """Look up each CVE in NVD, one request at a time.

    Returns (results, warnings). results maps each CVE we could look up to its
    record, or to None if NVD has no record of it. CVEs missing from results
    could not be looked up; warnings says why. If NVD keeps failing, we stop
    asking for the rest of the run rather than waiting on every CVE.
    """
    results: dict[str, NvdRecord | None] = {}
    to_fetch: list[str] = []
    for cve_id in dict.fromkeys(cve_ids):
        entry = cache.get(CACHE_NAMESPACE, cve_id, max_age=None if offline else MAX_AGE)
        if entry is not None:
            results[cve_id] = _from_cache_entry(entry)
        else:
            to_fetch.append(cve_id)

    if not to_fetch:
        return results, []
    if offline:
        return results, [f"NVD: offline mode, {len(to_fetch)} CVE(s) not in the cache"]

    headers = {"apiKey": api_key} if api_key else None
    pause = PAUSE_WITH_KEY if api_key else PAUSE_WITHOUT_KEY
    if not api_key:
        log.info("No NVD_API_KEY set: NVD lookups will take about %.0fs each", pause)

    warnings: list[str] = []
    consecutive_failures = 0
    for index, cve_id in enumerate(to_fetch):
        if index:
            sleep(pause)
        log.info("NVD lookup %d of %d: %s", index + 1, len(to_fetch), cve_id)
        try:
            raw = fetch_json(
                session,
                NVD_URL,
                params={"cveId": cve_id},
                headers=headers,
                retry_statuses=RETRY_STATUSES,
                base_delay=6.0,
                sleep=sleep,
            )
            vulnerabilities = raw.get("vulnerabilities") or []
            cve = vulnerabilities[0]["cve"] if vulnerabilities else None
            record = parse_nvd_cve(cve) if cve else None
        except SourceUnavailable as exc:
            warnings.append(f"NVD unavailable for {cve_id}: {exc}")
            consecutive_failures += 1
            if consecutive_failures >= 3:
                remaining = len(to_fetch) - index - 1
                if remaining:
                    warnings.append(
                        f"NVD: skipped the remaining {remaining} CVE(s) after 3 failures"
                    )
                break
            continue
        except (KeyError, TypeError, ValueError, AttributeError, IndexError):
            warnings.append(f"NVD returned data in an unexpected format for {cve_id}")
            continue
        consecutive_failures = 0
        cache.set(CACHE_NAMESPACE, cve_id, {"found": cve is not None, "cve": cve})
        results[cve_id] = record
    return results, warnings
