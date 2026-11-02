"""Command-line entry point: risk-translator --input ... --assets ... --out ..."""

import argparse
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from risk_translator import __version__
from risk_translator.enrich import enrich_cves
from risk_translator.errors import RiskTranslatorError
from risk_translator.iso_mapping import load_mapping
from risk_translator.models import Risk
from risk_translator.nmap_reader import read_nmap_xml
from risk_translator.outputs.heatmap import write_heatmap
from risk_translator.outputs.register import write_register_csv, write_register_xlsx
from risk_translator.outputs.summary import SummaryContext, write_summary
from risk_translator.pipeline import build_risks
from risk_translator.readers import InputResult, detect_input_type, load_assets, read_cve_csv

log = logging.getLogger("risk_translator")
TABLE_ROWS = 20


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line options."""
    parser = argparse.ArgumentParser(
        prog="risk-translator",
        description="Turn vulnerability scan output into a board-ready risk register.",
    )
    parser.add_argument("--input", required=True, type=Path, help="CVE list (.csv) or Nmap XML")
    parser.add_argument("--assets", required=True, type=Path, help="assets.yaml")
    parser.add_argument("--out", required=True, type=Path, help="folder for the outputs")
    parser.add_argument(
        "--input-type", choices=["csv", "nmap"], help="override detection from the file extension"
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path("mappings/iso27001.yaml"),
        help="ISO 27001 mapping file (default: mappings/iso27001.yaml)",
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=Path(".cache"), help="API cache folder (default: .cache)"
    )
    cache_mode = parser.add_mutually_exclusive_group()
    cache_mode.add_argument(
        "--offline", action="store_true", help="use cached data only; make no network calls"
    )
    cache_mode.add_argument(
        "--refresh", action="store_true", help="ignore the cache and fetch everything again"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug messages")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def read_input(path: Path, input_type: str, assets) -> InputResult:
    """Read findings from the input file using the right reader."""
    if input_type == "nmap":
        return read_nmap_xml(path, assets)
    return read_cve_csv(path, assets)


def format_table(risks: list[Risk], limit: int = TABLE_ROWS) -> str:
    """Return a plain-text table of the highest risks, for the terminal."""
    header = (
        f"{'ID':<6} {'Asset':<18} {'CVE':<16} {'CVSS':>4} {'EPSS':>6} {'KEV':<3}  L  I  Score  Band"
    )
    lines = [header, "-" * len(header)]
    for risk in risks[:limit]:
        data = risk.enrichment
        cvss = "-" if data.cvss_score is None else f"{data.cvss_score:.1f}"
        epss = "-" if data.epss_score is None else f"{data.epss_score:.1%}"
        kev = {True: "Yes", False: "No", None: "?"}[data.on_kev]
        lines.append(
            f"{risk.risk_id:<6} {risk.finding.asset.name[:18]:<18} {data.cve_id:<16} {cvss:>4} "
            f"{epss:>6} {kev:<3}  {risk.likelihood}  {risk.impact}  {risk.score:>5}  {risk.band}"
        )
    if len(risks) > limit:
        lines.append(f"...and {len(risks) - limit} more in the register")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    """Run the whole pipeline. Raises RiskTranslatorError for problems the user can fix."""
    assets = load_assets(args.assets)
    mapping = load_mapping(args.mapping)
    input_type = detect_input_type(args.input, args.input_type)
    result = read_input(args.input, input_type, assets)
    for warning in result.warnings:
        log.warning(warning)
    log.info("Read %d finding(s) from %s", len(result.findings), args.input.name)

    api_key = os.environ.get("NVD_API_KEY") or None
    enrichments, enrich_warnings, kev_version = enrich_cves(
        [finding.cve_id for finding in result.findings],
        cache_dir=args.cache_dir,
        api_key=api_key,
        offline=args.offline,
        refresh=args.refresh,
    )
    for warning in enrich_warnings:
        log.warning(warning)

    risks = build_risks(result.findings, enrichments, mapping)
    try:
        args.out.mkdir(parents=True, exist_ok=True)
        write_register_csv(risks, args.out / "register.csv")
        write_register_xlsx(risks, args.out / "register.xlsx")
        write_heatmap(risks, args.out / "heatmap.png")
        context = SummaryContext(
            input_name=args.input.name,
            asset_count=len(assets),
            warnings=result.warnings + enrich_warnings,
            kev_version=kev_version,
        )
        write_summary(risks, context, args.out / "summary.md")
    except OSError as exc:
        raise RiskTranslatorError(f"Could not write outputs to {args.out}: {exc}") from None

    print(format_table(risks))
    print(f"\nWrote register.csv, register.xlsx, heatmap.png and summary.md to {args.out}/")
    if result.warnings or enrich_warnings:
        print("Some data is missing: see 'Gaps in this report' in summary.md.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for the risk-translator command. Returns the exit code."""
    args = build_parser().parse_args(argv)
    load_dotenv()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    # requests/urllib3 debug logs can include request details; keep them quiet.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    try:
        return run(args)
    except RiskTranslatorError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
