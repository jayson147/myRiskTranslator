"""Tests for the disk cache and the shared fetch-with-retry helper."""

import json
from datetime import UTC, datetime, timedelta

import pytest
import requests

from fakes import FakeResponse, FakeSession
from risk_translator.cache import DiskCache
from risk_translator.errors import SourceUnavailable
from risk_translator.sources.fetch import fetch_json

# --- cache ---------------------------------------------------------------


def test_cache_round_trip(tmp_path):
    cache = DiskCache(tmp_path)
    cache.set("nvd", "CVE-2021-44228", {"found": True})
    assert cache.get("nvd", "CVE-2021-44228") == {"found": True}
    assert cache.get("nvd", "CVE-2014-0160") is None


def test_cache_expires_old_entries(tmp_path):
    cache = DiskCache(tmp_path)
    cache.set("epss", "CVE-1", {"x": 1})
    path = tmp_path / "epss" / "CVE-1.json"
    entry = json.loads(path.read_text())
    entry["saved_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    path.write_text(json.dumps(entry))
    assert cache.get("epss", "CVE-1", max_age=timedelta(days=1)) is None
    assert cache.get("epss", "CVE-1", max_age=None) == {"x": 1}


def test_cache_refresh_ignores_reads(tmp_path):
    DiskCache(tmp_path).set("kev", "catalogue", [1])
    assert DiskCache(tmp_path, refresh=True).get("kev", "catalogue") is None


def test_cache_treats_corrupt_file_as_miss(tmp_path):
    (tmp_path / "nvd").mkdir()
    (tmp_path / "nvd" / "CVE-1.json").write_text("{not json")
    assert DiskCache(tmp_path).get("nvd", "CVE-1") is None


@pytest.mark.parametrize("key", ["../escape", "a/b", "", ".hidden"])
def test_cache_rejects_unsafe_keys(tmp_path, key):
    with pytest.raises(ValueError):
        DiskCache(tmp_path).set("nvd", key, {})


# --- fetch_json ----------------------------------------------------------

URL = "https://example.test/api"


def test_fetch_returns_json():
    session = FakeSession({URL: [FakeResponse(200, {"ok": True})]})
    assert fetch_json(session, URL, params={"a": "b"}) == {"ok": True}
    assert session.calls[0]["params"] == {"a": "b"}
    assert session.calls[0]["timeout"] == 30.0


def test_fetch_retries_with_exponential_backoff():
    waits: list[float] = []
    session = FakeSession(
        {URL: [FakeResponse(429), FakeResponse(503), FakeResponse(200, {"ok": 1})]}
    )
    assert fetch_json(session, URL, base_delay=2, sleep=waits.append) == {"ok": 1}
    assert waits == [2, 4]


def test_fetch_honours_retry_after():
    waits: list[float] = []
    session = FakeSession(
        {URL: [FakeResponse(429, headers={"Retry-After": "30"}), FakeResponse(200, {})]}
    )
    fetch_json(session, URL, base_delay=2, sleep=waits.append)
    assert waits == [30]


def test_fetch_gives_up_after_max_attempts():
    waits: list[float] = []
    session = FakeSession({URL: [FakeResponse(429)]})
    with pytest.raises(SourceUnavailable, match="gave up after 3 attempts"):
        fetch_json(session, URL, max_attempts=3, sleep=waits.append)
    assert len(session.calls) == 3 and len(waits) == 2


def test_fetch_does_not_retry_permanent_errors():
    session = FakeSession({URL: [FakeResponse(404)]})
    with pytest.raises(SourceUnavailable, match="HTTP 404"):
        fetch_json(session, URL, sleep=lambda s: None)
    assert len(session.calls) == 1


def test_fetch_retries_network_errors():
    session = FakeSession({URL: [requests.ConnectionError("down"), FakeResponse(200, [])]})
    assert fetch_json(session, URL, sleep=lambda s: None) == []


def test_fetch_bad_json():
    session = FakeSession({URL: [FakeResponse(200, ValueError("bad"))]})
    with pytest.raises(SourceUnavailable, match="not valid JSON"):
        fetch_json(session, URL)


def test_fetch_error_never_contains_headers():
    session = FakeSession({URL: [requests.ConnectionError("secret-key-123 leaked?")]})
    with pytest.raises(SourceUnavailable) as error:
        fetch_json(session, URL, headers={"apiKey": "secret-key-123"}, max_attempts=1)
    assert "secret-key-123" not in str(error.value)
