"""Tests for the ISO 27001 mapping loader and lookup."""

from pathlib import Path

import pytest

from risk_translator.errors import ConfigError
from risk_translator.iso_mapping import load_mapping


def test_real_mapping_file_loads(mapping_path):
    mapping = load_mapping(mapping_path)
    assert mapping.baseline.id == "8.8"
    assert all(group.cwe_ids for group in mapping.groups)


def test_every_finding_gets_8_8(mapping_path):
    mapping = load_mapping(mapping_path)
    assert [c.id for c in mapping.controls_for([])] == ["8.8"]
    assert [c.id for c in mapping.controls_for(["CWE-99999"])] == ["8.8"]


def test_cwe_adds_second_control(mapping_path):
    mapping = load_mapping(mapping_path)
    assert [c.id for c in mapping.controls_for(["CWE-89"])] == ["8.8", "8.28"]
    assert mapping.group_for(["CWE-287"]).name == "Authentication flaws"


def test_first_mapped_cwe_wins(mapping_path):
    mapping = load_mapping(mapping_path)
    assert [c.id for c in mapping.controls_for(["CWE-99999", "CWE-200", "CWE-79"])] == [
        "8.8",
        "8.12",
    ]


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "map.yaml"
    path.write_text(text, encoding="utf-8")
    return path


VALID = """
baseline: {id: "8.8", name: Technical vulnerabilities}
weakness_groups:
  - name: Auth
    cwes: [287, cwe-306]
    control: {id: "8.5", name: Secure authentication}
"""


def test_accepts_bare_and_lower_case_cwe_numbers(tmp_path):
    mapping = load_mapping(write(tmp_path, VALID))
    assert mapping.groups[0].cwe_ids == {"CWE-287", "CWE-306"}


@pytest.mark.parametrize(
    "text, message",
    [
        ("baseline: {id: '27', name: x}\nweakness_groups: []", "not an Annex A control"),
        ("baseline: {id: '8.8'}\nweakness_groups: []", "name is required"),
        (
            VALID + "  - name: Dup\n    cwes: [CWE-287]\n    control: {id: '8.9', name: y}\n",
            "already in 'Auth'",
        ),
        (VALID.replace("[287, cwe-306]", "[XSS]"), "not a CWE ID"),
        ("- a list", "must contain"),
    ],
)
def test_rejects_bad_mapping(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load_mapping(write(tmp_path, text))


def test_missing_mapping_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_mapping(tmp_path / "nope.yaml")
