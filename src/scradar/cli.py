"""Command-line entry point.

    scradar sbom --path <dir> --supplier <name> --out sbom.json
    scradar scan --config suppliers.json --out-dir out/
    scradar diff-baseline --baseline docs/baseline.json --current out/register.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scradar.concentration import find_concentration_risk
from scradar.cyclonedx import build_sbom
from scradar.discover import discover_components
from scradar.models import Supplier
from scradar.osv import OsvClient
from scradar.risk_register import build_risk_register, to_csv, to_json


def _load_suppliers(config_path: str) -> list[Supplier]:
    raw = json.loads(Path(config_path).read_text())
    suppliers = []
    for entry in raw["suppliers"]:
        components, _kind = discover_components(entry["path"])
        suppliers.append(Supplier(name=entry["name"], path=entry["path"], components=components))
    return suppliers


def cmd_sbom(args: argparse.Namespace) -> int:
    components, kind = discover_components(args.path)
    sbom = build_sbom(args.supplier, components)
    Path(args.out).write_text(json.dumps(sbom, indent=2))
    print(f"Parsed {len(components)} components via {kind}; wrote {args.out}", file=sys.stderr)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    suppliers = _load_suppliers(args.config)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_components = {c.purl: c for s in suppliers for c in s.components}
    unique_components = list(all_components.values())
    print(
        f"Scanning {len(suppliers)} suppliers, {len(unique_components)} unique components "
        f"({sum(len(s.components) for s in suppliers)} total incl. duplicates across suppliers)",
        file=sys.stderr,
    )

    vulns_by_purl: dict[str, list] = {}
    if not args.skip_osv:
        client = OsvClient()
        matches = client.query_batch(unique_components)
        print(f"OSV querybatch: {len(matches)}/{len(unique_components)} components have known vulns", file=sys.stderr)
        vuln_id_cache: dict[str, object] = {}
        for purl, vuln_ids in matches.items():
            details = []
            for vid in vuln_ids:
                if vid not in vuln_id_cache:
                    vuln_id_cache[vid] = client.get_vulnerability(vid)
                details.append(vuln_id_cache[vid])
            vulns_by_purl[purl] = details

    for supplier in suppliers:
        sbom = build_sbom(supplier.name, supplier.components)
        (out_dir / f"{supplier.name}.sbom.json").write_text(json.dumps(sbom, indent=2))

    concentration = find_concentration_risk(suppliers, min_suppliers=args.min_concentration)
    register = build_risk_register(suppliers, vulns_by_purl, concentration)

    (out_dir / "risk-register.json").write_text(json.dumps(to_json(register), indent=2))
    (out_dir / "risk-register.csv").write_text(to_csv(register))
    (out_dir / "concentration.json").write_text(
        json.dumps(
            [
                {"component": f.component_key, "suppliers": f.suppliers, "versions": f.versions}
                for f in concentration
            ],
            indent=2,
        )
    )

    print(f"Wrote risk register + {len(suppliers)} SBOMs to {out_dir}", file=sys.stderr)
    return 0


def cmd_diff_baseline(args: argparse.Namespace) -> int:
    baseline = json.loads(Path(args.baseline).read_text())
    current = json.loads(Path(args.current).read_text())

    baseline_by_supplier = {e["supplier"]: e for e in baseline}
    new_criticals = []
    for entry in current:
        supplier = entry["supplier"]
        prev = baseline_by_supplier.get(supplier)
        prev_critical = prev["vuln_counts_by_severity"].get("CRITICAL", 0) if prev else 0
        cur_critical = entry["vuln_counts_by_severity"].get("CRITICAL", 0)
        if cur_critical > prev_critical:
            new_criticals.append((supplier, prev_critical, cur_critical))

    if new_criticals:
        print("NEW CRITICAL vulnerabilities detected since baseline:", file=sys.stderr)
        for supplier, before, after in new_criticals:
            print(f"  {supplier}: {before} -> {after} critical", file=sys.stderr)
        return 1

    print("No new critical vulnerabilities vs. baseline.", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scradar")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sbom = sub.add_parser("sbom", help="Generate a CycloneDX SBOM for one repo")
    p_sbom.add_argument("--path", required=True)
    p_sbom.add_argument("--supplier", required=True)
    p_sbom.add_argument("--out", required=True)
    p_sbom.set_defaults(func=cmd_sbom)

    p_scan = sub.add_parser("scan", help="Full scan: SBOMs + OSV + concentration + risk register")
    p_scan.add_argument("--config", required=True)
    p_scan.add_argument("--out-dir", required=True)
    p_scan.add_argument("--skip-osv", action="store_true", help="Skip live OSV.dev calls (for offline/dry-run)")
    p_scan.add_argument("--min-concentration", type=int, default=2)
    p_scan.set_defaults(func=cmd_scan)

    p_diff = sub.add_parser("diff-baseline", help="Fail if a new CRITICAL vuln appeared vs. baseline")
    p_diff.add_argument("--baseline", required=True)
    p_diff.add_argument("--current", required=True)
    p_diff.set_defaults(func=cmd_diff_baseline)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
