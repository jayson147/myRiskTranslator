"""End-to-end tests of the command, with the API cache pre-filled from fixtures."""

import csv
import json
import shutil
from datetime import UTC, datetime

import pytest

from fakes import FIXTURES, load_fixture
from risk_translator.cli import main


def seed_cache(cache_dir) -> None:
    """Fill the cache as if a previous run had fetched these fixtures."""

    def put(namespace, key, data):
        folder = cache_dir / namespace
        folder.mkdir(parents=True, exist_ok=True)
        entry = {"saved_at": datetime.now(UTC).isoformat(), "data": data}
        (folder / f"{key}.json").write_text(json.dumps(entry))

    put("kev", "catalogue", load_fixture("kev_catalogue.json"))
    for row in load_fixture("epss_batch.json")["data"]:
        put("epss", row["cve"], {"found": True, "row": row})
    for name in ["nvd_v31.json", "nvd_v2_only.json"]:
        cve = load_fixture(name)["vulnerabilities"][0]["cve"]
        put("nvd", cve["id"], {"found": True, "cve": cve})


@pytest.fixture
def workdir(tmp_path, samples_dir, mapping_path):
    (tmp_path / "mappings").mkdir()
    shutil.copy(mapping_path, tmp_path / "mappings" / "iso27001.yaml")
    shutil.copy(samples_dir / "assets.yaml", tmp_path / "assets.yaml")
    seed_cache(tmp_path / ".cache")
    return tmp_path


def run(workdir, *args) -> int:
    return main(
        [
            "--assets",
            str(workdir / "assets.yaml"),
            "--out",
            str(workdir / "out"),
            "--mapping",
            str(workdir / "mappings" / "iso27001.yaml"),
            "--cache-dir",
            str(workdir / ".cache"),
            "--offline",
            *args,
        ]
    )


def test_csv_run_writes_all_outputs(workdir, samples_dir, capsys):
    assert run(workdir, "--input", str(samples_dir / "cves.csv")) == 0
    out = workdir / "out"
    for name in ["register.csv", "register.xlsx", "heatmap.png", "summary.md"]:
        assert (out / name).exists(), name
    with (out / "register.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 8
    assert rows[0]["CVE"] == "CVE-2021-44228"  # on KEV, critical, critical asset
    printed = capsys.readouterr().out
    assert "R-001" in printed and "CVE-2021-44228" in printed
    # Only 2 of the 8 CVEs are in the seeded cache, so the summary must say so.
    assert "Warning: incomplete data" in (out / "summary.md").read_text()


def test_nmap_run(workdir, caplog):
    assert run(workdir, "--input", str(FIXTURES / "nmap_edge_cases.xml")) == 0
    assert "192.168.99.99" in caplog.text  # warned on the terminal
    summary = (workdir / "out" / "summary.md").read_text()
    assert "192.168.99.99" in summary  # unknown host reported in the gaps section


def test_input_type_override(workdir, samples_dir):
    copy = workdir / "cves.txt"
    shutil.copy(samples_dir / "cves.csv", copy)
    assert run(workdir, "--input", str(copy), "--input-type", "csv") == 0


@pytest.mark.parametrize(
    "csv_text, message",
    [
        ("asset,cve\nbooking-web,CVE-BAD\n", "not a valid CVE ID"),
        ("asset,cve\nmystery-box,CVE-2021-44228\n", "not in the assets file"),
    ],
)
def test_bad_input_gives_readable_error(workdir, capsys, csv_text, message):
    bad = workdir / "bad.csv"
    bad.write_text(csv_text)
    assert run(workdir, "--input", str(bad)) == 2
    err = capsys.readouterr().err
    assert err.startswith("Error:") and message in err
    assert "Traceback" not in err


def test_missing_mapping_gives_readable_error(workdir, samples_dir, capsys):
    (workdir / "mappings" / "iso27001.yaml").unlink()
    assert run(workdir, "--input", str(samples_dir / "cves.csv")) == 2
    assert "mapping file not found" in capsys.readouterr().err
