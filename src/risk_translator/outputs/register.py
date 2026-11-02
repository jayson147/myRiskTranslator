"""Write the risk register as register.csv and register.xlsx."""

import csv
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from risk_translator.models import Risk
from risk_translator.scoring import CRITICALITY_SCALE

COLUMNS = [
    "Risk ID",
    "Asset",
    "Owner",
    "Asset description",
    "Asset criticality",
    "Service",
    "CVE",
    "Vulnerability description",
    "CVSS",
    "CVSS severity",
    "CVSS version",
    "CWE",
    "EPSS",
    "EPSS percentile",
    "On KEV",
    "KEV date added",
    "Likelihood",
    "Impact",
    "Score",
    "Band",
    "ISO 27001 controls",
    "Suggested treatment",
    "Notes",
]

# Band colours: also used by the heat map, so the two always match.
BAND_COLOURS = {
    "Critical": "D7191C",
    "High": "FDAE61",
    "Medium": "FEE08B",
    "Low": "A6D96A",
}

# A cell starting with one of these can be run as a formula by spreadsheet
# software ("CSV injection"), so text from scans and APIs is defused first.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_text(value: str) -> str:
    """Prefix text that a spreadsheet would treat as a formula with an apostrophe."""
    return f"'{value}" if value.startswith(FORMULA_PREFIXES) else value


def _kev_text(on_kev: bool | None) -> str:
    if on_kev is None:
        return "Unknown"
    return "Yes" if on_kev else "No"


def risk_to_row(risk: Risk) -> dict[str, object]:
    """Return one register row as {column: value}. Missing numbers are left blank."""
    asset = risk.finding.asset
    data = risk.enrichment
    criticality = f"{asset.criticality} ({CRITICALITY_SCALE.get(asset.criticality, '?')})"
    row: dict[str, object] = {
        "Risk ID": risk.risk_id,
        "Asset": asset.name,
        "Owner": asset.owner,
        "Asset description": asset.description,
        "Asset criticality": criticality,
        "Service": risk.finding.service,
        "CVE": data.cve_id,
        "Vulnerability description": data.description or "",
        "CVSS": data.cvss_score,
        "CVSS severity": (data.cvss_severity or "").title(),
        "CVSS version": data.cvss_version or "",
        "CWE": ", ".join(data.cwe_ids),
        "EPSS": None if data.epss_score is None else round(data.epss_score, 5),
        "EPSS percentile": None if data.epss_percentile is None else round(data.epss_percentile, 5),
        "On KEV": _kev_text(data.on_kev),
        "KEV date added": data.kev_date_added or "",
        "Likelihood": risk.likelihood,
        "Impact": risk.impact,
        "Score": risk.score,
        "Band": risk.band,
        "ISO 27001 controls": "; ".join(control.label() for control in risk.controls),
        "Suggested treatment": risk.treatment,
        "Notes": "; ".join(risk.notes),
    }
    return row


def _csv_value(value: object) -> object:
    """Blank for missing values; defused text for strings."""
    if value is None:
        return ""
    return safe_text(value) if isinstance(value, str) else value


def write_register_csv(risks: list[Risk], path: Path) -> None:
    """Write register.csv, one row per risk, in the order given."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for risk in risks:
            row = risk_to_row(risk)
            writer.writerow({k: _csv_value(v) for k, v in row.items()})


COLUMN_WIDTHS = {
    "Asset description": 32,
    "Vulnerability description": 50,
    "ISO 27001 controls": 40,
    "Suggested treatment": 30,
    "Notes": 45,
}


def write_register_xlsx(risks: list[Risk], path: Path) -> None:
    """Write register.xlsx with a frozen header, a filter and colour-coded bands."""
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Risk register"
    sheet.append(COLUMNS)
    header_fill = PatternFill("solid", fgColor="1F3864")
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = header_fill
        cell.alignment = Alignment(wrap_text=True, vertical="top")

    band_column = COLUMNS.index("Band") + 1
    percent_columns = {COLUMNS.index("EPSS") + 1, COLUMNS.index("EPSS percentile") + 1}
    for risk in risks:
        row = risk_to_row(risk)
        sheet.append([row[column] for column in COLUMNS])
        row_index = sheet.max_row
        for column_index in range(1, len(COLUMNS) + 1):
            cell = sheet.cell(row=row_index, column=column_index)
            if isinstance(cell.value, str):
                cell.data_type = "s"  # store as text, never as a formula (CSV injection)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            if column_index in percent_columns:
                cell.number_format = "0.0%"
        band_cell = sheet.cell(row=row_index, column=band_column)
        colour = BAND_COLOURS.get(risk.band)
        if colour:
            band_cell.fill = PatternFill("solid", fgColor=colour)
            band_cell.font = Font(
                bold=True, color="FFFFFF" if risk.band == "Critical" else "000000"
            )

    for index, column in enumerate(COLUMNS, start=1):
        letter = sheet.cell(row=1, column=index).column_letter
        sheet.column_dimensions[letter].width = COLUMN_WIDTHS.get(column, max(12, len(column) + 2))
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    workbook.save(path)
