"""FIRST Exploit Prediction Scoring System (EPSS).

EPSS estimates the probability that a CVE will see exploitation activity in the
next 30 days (the "score", 0 to 1) and how that compares with every other CVE
(the "percentile", 0 to 1). The API takes many CVEs per request, comma-separated,
so we send them in batches. No key is needed; we stay polite by batching and
caching each CVE's result for a day (scores are updated daily).
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from risk_translator.cache import DiskCache
from risk_translator.errors import SourceUnavailable
from risk_translator.sources.fetch import HttpSession, fetch_json

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_NAMESPACE = "epss"
MAX_AGE = timedelta(hours=24)
BATCH_SIZE = 50  # keeps the URL well under common length limits


@dataclass(frozen=True)
class EpssScore:
    """One CVE's EPSS score and percentile, both as fractions from 0 to 1."""

    score: float
    percentile: float
    date: str


def _parse_row(row: dict) -> EpssScore:
    return EpssScore(
        score=float(row["epss"]),
        percentile=float(row["percentile"]),
        date=str(row.get("date", "")),
    )


def _from_cache_entry(entry: dict) -> EpssScore | None:
    return _parse_row(entry["row"]) if entry.get("found") else None


def fetch_epss(
    cve_ids: list[str],
    session: HttpSession,
    cache: DiskCache,
    offline: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, EpssScore | None], list[str]]:
    """Look up EPSS scores for several CVEs.

    Returns (results, warnings). results maps each CVE we could look up to its
    score, or to None if EPSS has no score for it. CVEs missing from results
    could not be looked up (the API was unavailable); warnings says why.
    """
    results: dict[str, EpssScore | None] = {}
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
        return results, [f"EPSS: offline mode, {len(to_fetch)} CVE(s) not in the cache"]

    warnings: list[str] = []
    for start in range(0, len(to_fetch), BATCH_SIZE):
        batch = to_fetch[start : start + BATCH_SIZE]
        log.info("Fetching EPSS scores for %d CVE(s)", len(batch))
        params = {"cve": ",".join(batch)}
        try:
            raw = fetch_json(session, EPSS_URL, params=params, sleep=sleep)
            rows = {row["cve"].upper(): row for row in raw["data"]}
            for cve_id in batch:
                row = rows.get(cve_id)
                result = _parse_row(row) if row else None
                cache.set(CACHE_NAMESPACE, cve_id, {"found": row is not None, "row": row})
                results[cve_id] = result
        except SourceUnavailable as exc:
            warnings.append(f"EPSS unavailable for {len(batch)} CVE(s): {exc}")
        except (KeyError, TypeError, ValueError, AttributeError):
            warnings.append(f"EPSS returned data in an unexpected format for {len(batch)} CVE(s)")
    return results, warnings
