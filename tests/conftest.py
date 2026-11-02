"""Shared fixtures. Every test runs with real network access blocked."""

import socket
from pathlib import Path

import pytest

from risk_translator.models import Asset

ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any attempt to open a network connection fail the test loudly."""

    def refuse(*args, **kwargs):
        raise RuntimeError("Tests must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def critical_asset() -> Asset:
    return Asset("booking-web", "10.0.10.5", "Head of Digital", "the booking website", 5, True)


@pytest.fixture
def moderate_asset() -> Asset:
    return Asset("hr-app", "10.0.40.2", "HR Director", "the HR system", 3, False)


@pytest.fixture
def low_asset() -> Asset:
    return Asset("staff-wiki", "10.0.30.8", "IT Manager", "the staff wiki", 1, False)


@pytest.fixture
def samples_dir() -> Path:
    return ROOT / "samples"


@pytest.fixture
def mapping_path() -> Path:
    return ROOT / "mappings" / "iso27001.yaml"
