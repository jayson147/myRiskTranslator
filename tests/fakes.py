"""Test doubles: a fake HTTP session that serves fixture files, and helpers."""

import json
from pathlib import Path
from typing import Any

import requests

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    """Return the parsed JSON of a fixture file."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeResponse:
    """Just enough of requests.Response for our code."""

    def __init__(self, status_code: int = 200, body: Any = None, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeSession:
    """Serves queued responses per URL prefix and records every call.

    routes maps a URL prefix to a list of responses (FakeResponse or an
    exception to raise), served in order; the last one repeats.
    """

    def __init__(self, routes: dict[str, list[Any]] | None = None):
        self.routes = routes or {}
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        for prefix, responses in self.routes.items():
            if url.startswith(prefix):
                item = responses.pop(0) if len(responses) > 1 else responses[0]
                if isinstance(item, Exception):
                    raise item
                return item
        raise requests.ConnectionError(f"no fake route for {url}")


def no_sleep(seconds: float) -> None:
    """Stand-in for time.sleep so tests run instantly."""
