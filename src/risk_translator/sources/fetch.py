"""One polite way to fetch JSON: timeouts, retries and exponential backoff."""

import logging
import time
from collections.abc import Callable
from typing import Any, Protocol

import requests

from risk_translator.errors import SourceUnavailable

log = logging.getLogger(__name__)

USER_AGENT = "risk-translator/0.1 (+https://github.com/jayson147/myRiskTranslator)"
DEFAULT_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class HttpSession(Protocol):
    """The part of requests.Session we use, so tests can pass a fake."""

    def get(self, url: str, **kwargs: Any) -> Any: ...


def new_session() -> requests.Session:
    """Return a requests session with our User-Agent set."""
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session


def _retry_after(response: Any) -> float | None:
    """Return the server's Retry-After value in seconds, if it sent a number."""
    value = getattr(response, "headers", {}).get("Retry-After")
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def fetch_json(
    session: HttpSession,
    url: str,
    *,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    retry_statuses: frozenset[int] = DEFAULT_RETRY_STATUSES,
    max_attempts: int = 4,
    base_delay: float = 2.0,
    timeout: float = 30.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Any:
    """GET a URL and return the parsed JSON body.

    Retries on network errors and on the given HTTP statuses, waiting
    base_delay, then 2x, then 4x (or the server's Retry-After, if longer).
    Raises SourceUnavailable when it gives up. Error messages never include
    request headers, so an API key cannot leak into logs.
    """
    problem = "no response"
    for attempt in range(1, max_attempts + 1):
        wait = base_delay * 2 ** (attempt - 1)
        try:
            response = session.get(url, params=params, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            problem = f"network error ({type(exc).__name__})"
        else:
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    raise SourceUnavailable("the response was not valid JSON") from None
            problem = f"HTTP {response.status_code}"
            if response.status_code not in retry_statuses:
                raise SourceUnavailable(problem)
            wait = max(wait, _retry_after(response) or 0)
        if attempt < max_attempts:
            log.debug("Attempt %d failed (%s); retrying in %.0fs", attempt, problem, wait)
            sleep(wait)
    raise SourceUnavailable(f"gave up after {max_attempts} attempts ({problem})")
