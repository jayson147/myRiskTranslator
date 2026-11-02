"""Map each risk to ISO/IEC 27001:2022 Annex A controls.

Every finding maps to a baseline control (8.8, technical vulnerabilities). A
second control comes from the CWE weakness IDs NVD gives, using the groups in
mappings/iso27001.yaml. Controls are referred to by number and a short name in
our own words only: the text of the standard is copyrighted.
"""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from risk_translator.errors import ConfigError
from risk_translator.models import Control

CONTROL_ID = re.compile(r"^[5-8]\.\d{1,2}$")  # Annex A 2022 has themes 5 to 8
CWE_ID = re.compile(r"^CWE-\d+$")


@dataclass(frozen=True)
class WeaknessGroup:
    """A family of CWE weakness types that share an extra control."""

    name: str
    cwe_ids: frozenset[str]
    control: Control
    board_summary: str


@dataclass(frozen=True)
class IsoMapping:
    """The baseline control plus the CWE-based weakness groups."""

    baseline: Control
    groups: list[WeaknessGroup]

    def group_for(self, cwe_ids: list[str]) -> WeaknessGroup | None:
        """Return the group for the first of the CVE's CWEs that is mapped, or None.

        TODO(human): decide what happens when a CVE's CWEs fall in more than one
        group. The placeholder takes the first match in NVD's order, to keep
        "8.8 plus one". The alternative is to list every matched control.
        """
        for cwe_id in cwe_ids:
            for group in self.groups:
                if cwe_id in group.cwe_ids:
                    return group
        return None

    def controls_for(self, cwe_ids: list[str]) -> list[Control]:
        """Return the baseline control, plus the weakness group's control if there is one."""
        controls = [self.baseline]
        group = self.group_for(cwe_ids)
        if group and group.control != self.baseline:
            controls.append(group.control)
        return controls


def _parse_control(value: object, where: str, errors: list[str]) -> Control | None:
    """Validate a {id, name} control entry."""
    if not isinstance(value, dict):
        errors.append(f"{where}: control must have 'id' and 'name'")
        return None
    control_id = str(value.get("id", "")).strip()
    name = str(value.get("name", "")).strip()
    if not CONTROL_ID.match(control_id):
        errors.append(f"{where}: '{control_id}' is not an Annex A control number like 8.8")
    if not name:
        errors.append(f"{where}: control name is required")
    return Control(id=control_id, name=name)


def _normalise_cwe(value: object) -> str | None:
    """Accept CWE-79, cwe-79 or 79 and return CWE-79; None if invalid."""
    text = str(value).strip().upper()
    if text.isdigit():
        text = f"CWE-{text}"
    return text if CWE_ID.match(text) else None


def load_mapping(path: Path) -> IsoMapping:
    """Load and validate mappings/iso27001.yaml. Raises ConfigError listing every problem."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"ISO 27001 mapping file not found: {path}") from None
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Could not read ISO 27001 mapping file {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain 'baseline' and 'weakness_groups'")

    errors: list[str] = []
    baseline = _parse_control(data.get("baseline"), "baseline", errors)
    groups: list[WeaknessGroup] = []
    owner_of: dict[str, str] = {}
    for index, entry in enumerate(data.get("weakness_groups") or [], start=1):
        if not isinstance(entry, dict):
            errors.append(f"weakness group {index}: expected a mapping of fields")
            continue
        name = str(entry.get("name", "")).strip() or f"group {index}"
        where = f"weakness group '{name}'"
        control = _parse_control(entry.get("control"), where, errors)
        cwe_ids: set[str] = set()
        for raw in entry.get("cwes") or []:
            cwe_id = _normalise_cwe(raw)
            if cwe_id is None:
                errors.append(f"{where}: '{raw}' is not a CWE ID like CWE-79")
            elif cwe_id in owner_of:
                errors.append(f"{where}: {cwe_id} is already in '{owner_of[cwe_id]}'")
            else:
                owner_of[cwe_id] = name
                cwe_ids.add(cwe_id)
        if not cwe_ids:
            errors.append(f"{where}: needs at least one CWE")
        if control:
            groups.append(
                WeaknessGroup(
                    name=name,
                    cwe_ids=frozenset(cwe_ids),
                    control=control,
                    board_summary=str(entry.get("board_summary", "")).strip(),
                )
            )

    if errors or baseline is None:
        lines = "\n".join(f"  - {error}" for error in errors)
        raise ConfigError(f"{path} has {len(errors)} problem(s):\n{lines}")
    return IsoMapping(baseline=baseline, groups=groups)
