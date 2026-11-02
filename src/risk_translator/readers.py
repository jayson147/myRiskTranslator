"""Read and validate the assets file and the CVE list (CSV).

Every reader collects all the problems it finds and reports them together, so
the user can fix a file in one go rather than one error per run.
"""

import csv
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from risk_translator.errors import InputError
from risk_translator.models import Asset, Finding
from risk_translator.scoring import CRITICALITY_SCALE

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
MAX_ERRORS_SHOWN = 20


@dataclass
class InputResult:
    """Findings read from an input file, plus warnings about anything left out."""

    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)


class AssetRegistry:
    """The assets from assets.yaml, looked up by name or by IP address."""

    def __init__(self, assets: list[Asset]) -> None:
        self.assets = assets
        self._by_name = {asset.name.lower(): asset for asset in assets}
        self._by_ip = {asset.ip: asset for asset in assets if asset.ip}

    def __len__(self) -> int:
        return len(self.assets)

    def find(self, key: str) -> Asset | None:
        """Return the asset whose name (case-insensitive) or IP matches key, or None."""
        key = key.strip()
        return self._by_name.get(key.lower()) or self._by_ip.get(key)

    def find_by_ip(self, ip: str) -> Asset | None:
        """Return the asset with this IP address, or None."""
        return self._by_ip.get(ip)


def normalise_cve_id(value: str) -> str | None:
    """Return the CVE ID in upper case, or None if it is not a valid CVE ID."""
    value = value.strip()
    return value.upper() if CVE_PATTERN.match(value) else None


def _raise_if_errors(errors: list[str], path: Path) -> None:
    """Raise one InputError listing every problem found in a file."""
    if not errors:
        return
    shown = errors[:MAX_ERRORS_SHOWN]
    more = len(errors) - len(shown)
    lines = "\n".join(f"  - {error}" for error in shown)
    if more:
        lines += f"\n  - ...and {more} more"
    raise InputError(f"{path} has {len(errors)} problem(s):\n{lines}")


def _read_text(path: Path, what: str) -> str:
    """Read a text file, turning a missing or unreadable file into an InputError."""
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise InputError(f"{what} not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"Could not read {what} {path}: {exc}") from None


def _parse_asset(index: int, entry: object, errors: list[str]) -> Asset | None:
    """Validate one asset entry from assets.yaml. Append problems to errors."""
    where = f"asset {index}"
    if not isinstance(entry, dict):
        errors.append(f"{where}: expected a mapping of fields, got {type(entry).__name__}")
        return None

    name = str(entry.get("name") or "").strip()
    if name:
        where = f"asset {index} ({name})"
    else:
        errors.append(f"{where}: 'name' is required")

    owner = str(entry.get("owner") or "").strip()
    if not owner:
        errors.append(f"{where}: 'owner' is required")

    ip = entry.get("ip")
    if ip is not None:
        ip = str(ip).strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            errors.append(f"{where}: '{ip}' is not a valid IP address")

    criticality = entry.get("criticality")
    if isinstance(criticality, bool) or criticality not in CRITICALITY_SCALE:
        allowed = ", ".join(str(level) for level in CRITICALITY_SCALE)
        errors.append(f"{where}: 'criticality' must be one of {allowed}, got {criticality!r}")

    internet_facing = entry.get("internet_facing", False)
    if not isinstance(internet_facing, bool):
        errors.append(f"{where}: 'internet_facing' must be true or false")

    if not name:
        return None
    return Asset(
        name=name,
        ip=ip,
        owner=owner,
        description=str(entry.get("description") or "").strip(),
        criticality=criticality if isinstance(criticality, int) else 0,
        internet_facing=bool(internet_facing),
    )


def load_assets(path: Path) -> AssetRegistry:
    """Load and validate assets.yaml.

    Expected format:

        assets:
          - name: booking-web
            ip: 10.0.10.5
            owner: Head of Digital
            description: Customer booking website
            criticality: 5
            internet_facing: true

    Raises InputError listing every problem found.
    """
    text = _read_text(path, "Assets file")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InputError(f"Assets file {path} is not valid YAML: {exc}") from None

    entries = data.get("assets") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise InputError(f"Assets file {path} must contain a non-empty 'assets:' list")

    errors: list[str] = []
    assets: list[Asset] = []
    seen_names: set[str] = set()
    seen_ips: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        asset = _parse_asset(index, entry, errors)
        if asset is None:
            continue
        if asset.name.lower() in seen_names:
            errors.append(f"asset {index}: name '{asset.name}' is used more than once")
        if asset.ip and asset.ip in seen_ips:
            errors.append(f"asset {index}: IP {asset.ip} is used more than once")
        seen_names.add(asset.name.lower())
        if asset.ip:
            seen_ips.add(asset.ip)
        assets.append(asset)

    _raise_if_errors(errors, path)
    return AssetRegistry(assets)


def read_cve_csv(path: Path, assets: AssetRegistry) -> InputResult:
    """Read a CSV of asset,cve pairs and turn each row into a Finding.

    The 'asset' column can hold an asset's name or its IP address. Blank rows
    are skipped. Raises InputError for malformed CVE IDs, duplicate rows and
    assets that are not in assets.yaml, listing every problem found.
    """
    text = _read_text(path, "CVE list")
    reader = csv.DictReader(text.splitlines())
    headers = {(name or "").strip().lower(): name for name in reader.fieldnames or []}
    if "asset" not in headers or "cve" not in headers:
        raise InputError(f"CVE list {path} must have a header row with 'asset' and 'cve' columns")

    errors: list[str] = []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for row_number, row in enumerate(reader, start=2):  # row 1 is the header
        asset_key = (row.get(headers["asset"]) or "").strip()
        raw_cve = (row.get(headers["cve"]) or "").strip()
        if not asset_key and not raw_cve:
            continue

        where = f"row {row_number}"
        cve_id = normalise_cve_id(raw_cve)
        if cve_id is None:
            errors.append(f"{where}: '{raw_cve}' is not a valid CVE ID (expected CVE-YYYY-NNNN)")
        asset = assets.find(asset_key) if asset_key else None
        if asset is None:
            errors.append(f"{where}: asset '{asset_key}' is not in the assets file")
        if cve_id is None or asset is None:
            continue

        key = (asset.name, cve_id)
        if key in seen:
            errors.append(f"{where}: duplicate of an earlier row ({asset.name}, {cve_id})")
            continue
        seen.add(key)
        findings.append(Finding(asset=asset, cve_id=cve_id, source=f"{path.name} row {row_number}"))

    _raise_if_errors(errors, path)
    return InputResult(findings=findings)


def detect_input_type(path: Path, override: str | None = None) -> str:
    """Return "csv" or "nmap", from the --input-type override or the file extension."""
    if override:
        return override
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix == ".xml":
        return "nmap"
    raise InputError(
        f"Can't tell the input type from '{path.name}'. "
        "Use a .csv or .xml file, or pass --input-type csv or --input-type nmap."
    )
