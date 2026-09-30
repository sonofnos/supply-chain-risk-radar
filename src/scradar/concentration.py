"""Supplier concentration risk: which components appear across multiple
suppliers' SBOMs, regardless of exact version. Models the log4j-shaped
question — "if this one library is compromised or has a critical CVE
disclosed tomorrow, how many of our vendors are simultaneously
exposed?" — which is a real, distinct risk from any single supplier's
own vulnerability count.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from scradar.models import Component, Supplier


@dataclass
class ConcentrationFinding:
    component_key: str  # "ecosystem:name"
    suppliers: list[str]
    versions: dict[str, str]  # supplier name -> version used


def find_concentration_risk(
    suppliers: list[Supplier], min_suppliers: int = 2
) -> list[ConcentrationFinding]:
    """Group components by (ecosystem, name) across all suppliers, and
    flag any group present in at least ``min_suppliers`` distinct
    suppliers."""
    by_key: dict[str, dict[str, Component]] = defaultdict(dict)
    for supplier in suppliers:
        for component in supplier.components:
            # first component of this key wins per-supplier (dedupe multiple versions)
            by_key[component.key].setdefault(supplier.name, component)

    findings: list[ConcentrationFinding] = []
    for key, supplier_map in by_key.items():
        if len(supplier_map) >= min_suppliers:
            findings.append(
                ConcentrationFinding(
                    component_key=key,
                    suppliers=sorted(supplier_map.keys()),
                    versions={name: c.version for name, c in supplier_map.items()},
                )
            )
    findings.sort(key=lambda f: (-len(f.suppliers), f.component_key))
    return findings
