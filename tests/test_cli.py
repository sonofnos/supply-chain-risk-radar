import json
from pathlib import Path

from scradar.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_sbom_command_writes_valid_json(tmp_path):
    out = tmp_path / "out.sbom.json"
    rc = main(["sbom", "--path", str(FIXTURES / "nodelib"), "--supplier", "test-vendor", "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["bomFormat"] == "CycloneDX"
    assert len(data["components"]) == 8


def test_diff_baseline_flags_new_critical(tmp_path):
    baseline = [{"supplier": "v1", "vuln_counts_by_severity": {"CRITICAL": 0}}]
    current = [{"supplier": "v1", "vuln_counts_by_severity": {"CRITICAL": 1}}]
    b_path = tmp_path / "baseline.json"
    c_path = tmp_path / "current.json"
    b_path.write_text(json.dumps(baseline))
    c_path.write_text(json.dumps(current))
    rc = main(["diff-baseline", "--baseline", str(b_path), "--current", str(c_path)])
    assert rc == 1


def test_diff_baseline_passes_when_no_new_critical(tmp_path):
    baseline = [{"supplier": "v1", "vuln_counts_by_severity": {"CRITICAL": 1}}]
    current = [{"supplier": "v1", "vuln_counts_by_severity": {"CRITICAL": 1}}]
    b_path = tmp_path / "baseline.json"
    c_path = tmp_path / "current.json"
    b_path.write_text(json.dumps(baseline))
    c_path.write_text(json.dumps(current))
    rc = main(["diff-baseline", "--baseline", str(b_path), "--current", str(c_path)])
    assert rc == 0


def test_diff_baseline_new_supplier_with_critical_flags(tmp_path):
    baseline = []
    current = [{"supplier": "new-vendor", "vuln_counts_by_severity": {"CRITICAL": 1}}]
    b_path = tmp_path / "baseline.json"
    c_path = tmp_path / "current.json"
    b_path.write_text(json.dumps(baseline))
    c_path.write_text(json.dumps(current))
    rc = main(["diff-baseline", "--baseline", str(b_path), "--current", str(c_path)])
    assert rc == 1


def test_scan_skip_osv_end_to_end(tmp_path):
    config = {
        "suppliers": [
            {"name": "nodelib-vendor", "path": str(FIXTURES / "nodelib")},
            {"name": "pylib-vendor", "path": str(FIXTURES / "pylib")},
        ]
    }
    config_path = tmp_path / "suppliers.json"
    config_path.write_text(json.dumps(config))
    out_dir = tmp_path / "out"
    rc = main(["scan", "--config", str(config_path), "--out-dir", str(out_dir), "--skip-osv"])
    assert rc == 0
    register = json.loads((out_dir / "risk-register.json").read_text())
    assert {e["supplier"] for e in register} == {"nodelib-vendor", "pylib-vendor"}
    assert (out_dir / "nodelib-vendor.sbom.json").exists()
    assert (out_dir / "pylib-vendor.sbom.json").exists()
    assert (out_dir / "risk-register.csv").exists()
