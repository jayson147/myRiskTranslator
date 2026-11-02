"""CISA Known Exploited Vulnerabilities (KEV) catalogue.

One JSON file listing every CVE that CISA has evidence is being exploited in
the wild. We download it at most once per run (and reuse the cached copy for a
day), then look CVEs up locally. There is no API key and no rate limit, but the
file is over a megabyte, so we don't fetch it more than we need to.
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

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_NAMESPACE = "kev"
CACHE_KEY = "catalogue"
MAX_AGE = timedelta(hours=24)


@dataclass(frozen=True)
class KevEntry:
    """What KEV tells us about one CVE."""

    date_added: str
    ransomware: bool


@dataclass(frozen=True)
class KevCatalogue:
    """The KEV entries we need, keyed by CVE ID, plus the catalogue version."""

    version: str
    entries: dict[str, KevEntry]

    def lookup(self, cve_id: str) -> KevEntry | None:
        """Return the KEV entry for a CVE, or None if it is not on the list."""
        return self.entries.get(cve_id.upper())


def parse_kev(raw: dict) -> KevCatalogue:
    """Turn the KEV JSON feed into a KevCatalogue. Raises SourceUnavailable if malformed."""
    try:
        vulnerabilities = raw["vulnerabilities"]
        entries = {
            item["cveID"].upper(): KevEntry(
                date_added=item.get("dateAdded", ""),
                ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            )
            for item in vulnerabilities
        }
    except (KeyError, TypeError, AttributeError):
        raise SourceUnavailable("the KEV catalogue was not in the expected format") from None
    return KevCatalogue(version=str(raw.get("catalogVersion", "unknown")), entries=entries)


def load_kev(
    session: HttpSession,
    cache: DiskCache,
    offline: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> KevCatalogue:
    """Return the KEV catalogue, from the cache if fresh, otherwise downloaded.

    Raises SourceUnavailable if it can't be loaded either way.
    """
    cached = cache.get(CACHE_NAMESPACE, CACHE_KEY, max_age=None if offline else MAX_AGE)
    if cached is not None:
        return parse_kev(cached)
    if offline:
        raise SourceUnavailable("offline mode and no cached KEV catalogue")

    log.info("Downloading the CISA KEV catalogue")
    raw = fetch_json(session, KEV_URL, sleep=sleep)
    catalogue = parse_kev(raw)  # validate before caching
    cache.set(CACHE_NAMESPACE, CACHE_KEY, raw)
    return catalogue
