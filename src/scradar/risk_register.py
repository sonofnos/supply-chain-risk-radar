"""Aggregate SBOM + OSV + concentration data into a per-supplier risk
register — the artifact a TPRM analyst would actually consume, as JSON
and CSV.

The composite score is deliberately simple and documented, not a
calibrated actuarial model: it is a weighted count of severities plus a
concentration bonus, capped at 100. It is meant to *rank* suppliers for
triage, not to stand in for a real risk quantification methodology (see
README limitations).
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass

from scradar.concentration import ConcentrationFinding
from scradar.models import Supplier
from scradar.osv import Vulnerability

SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
CONCENTRATION_BONUS_PER_FINDING = 5


@dataclass
class SupplierRiskEntry:
    supplier: str
    component_count: int
    direct_count: int
    transitive_count: int
    vuln_counts_by_severity: dict[str, int]
    total_vulnerabilities: int
    max_severity: str
    concentration_flags: list[str]
    composite_score: int


def build_risk_register(
    suppliers: list[Supplier],
    vulns_by_purl: dict[str, list[Vulnerability]],
    concentration_findings: list[ConcentrationFinding],
) -> list[SupplierRiskEntry]:
    concentration_by_supplier: dict[str, list[str]] = {}
    for finding in concentration_findings:
        for supplier_name in finding.suppliers:
            concentration_by_supplier.setdefault(supplier_name, []).append(finding.component_key)

    entries: list[SupplierRiskEntry] = []
    for supplier in suppliers:
        direct = sum(1 for c in supplier.components if c.direct)
        transitive = len(supplier.components) - direct

        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for component in supplier.components:
            for vuln in vulns_by_purl.get(component.purl, []):
                counts[vuln.severity] = counts.get(vuln.severity, 0) + 1

        total_vulns = sum(counts.values())
        max_sev = next((sev for sev in SEVERITY_ORDER if counts.get(sev, 0) > 0), "NONE")

        flags = concentration_by_supplier.get(supplier.name, [])

        score = sum(SEVERITY_WEIGHT[sev] * n for sev, n in counts.items())
        score += CONCENTRATION_BONUS_PER_FINDING * len(flags)
        score = min(score, 100)

        entries.append(
            SupplierRiskEntry(
                supplier=supplier.name,
                component_count=len(supplier.components),
                direct_count=direct,
                transitive_count=transitive,
                vuln_counts_by_severity=counts,
                total_vulnerabilities=total_vulns,
                max_severity=max_sev,
                concentration_flags=sorted(flags),
                composite_score=score,
            )
        )
    entries.sort(key=lambda e: -e.composite_score)
    return entries


def to_json(entries: list[SupplierRiskEntry]) -> list[dict]:
    return [
        {
            "supplier": e.supplier,
            "component_count": e.component_count,
            "direct_count": e.direct_count,
            "transitive_count": e.transitive_count,
            "vuln_counts_by_severity": e.vuln_counts_by_severity,
            "total_vulnerabilities": e.total_vulnerabilities,
            "max_severity": e.max_severity,
            "concentration_flags": e.concentration_flags,
            "composite_score": e.composite_score,
        }
        for e in entries
    ]


def to_csv(entries: list[SupplierRiskEntry]) -> str:
    buf = io.StringIO()
    fieldnames = [
        "supplier",
        "component_count",
        "direct_count",
        "transitive_count",
        "critical",
        "high",
        "medium",
        "low",
        "total_vulnerabilities",
        "max_severity",
        "concentration_flag_count",
        "composite_score",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for e in entries:
        writer.writerow(
            {
                "supplier": e.supplier,
                "component_count": e.component_count,
                "direct_count": e.direct_count,
                "transitive_count": e.transitive_count,
                "critical": e.vuln_counts_by_severity.get("CRITICAL", 0),
                "high": e.vuln_counts_by_severity.get("HIGH", 0),
                "medium": e.vuln_counts_by_severity.get("MEDIUM", 0),
                "low": e.vuln_counts_by_severity.get("LOW", 0),
                "total_vulnerabilities": e.total_vulnerabilities,
                "max_severity": e.max_severity,
                "concentration_flag_count": len(e.concentration_flags),
                "composite_score": e.composite_score,
            }
        )
    return buf.getvalue()
