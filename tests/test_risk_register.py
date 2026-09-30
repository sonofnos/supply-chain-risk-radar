from scradar.concentration import ConcentrationFinding
from scradar.models import Component, Supplier
from scradar.osv import Vulnerability
from scradar.risk_register import build_risk_register, to_csv, to_json


def _c(name, version, direct=True, depth=1):
    return Component(name=name, version=version, ecosystem="npm", direct=direct, depth=depth)


def test_supplier_with_no_vulns_scores_zero():
    suppliers = [Supplier(name="clean-vendor", path=".", components=[_c("axios", "1.2.0")])]
    register = build_risk_register(suppliers, vulns_by_purl={}, concentration_findings=[])
    assert register[0].composite_score == 0
    assert register[0].max_severity == "NONE"
    assert register[0].total_vulnerabilities == 0


def test_critical_vuln_dominates_score():
    comp = _c("lodash", "4.17.15")
    suppliers = [Supplier(name="risky-vendor", path=".", components=[comp])]
    vulns = {comp.purl: [Vulnerability(id="GHSA-x", summary="bad", severity="CRITICAL", score=9.8)]}
    register = build_risk_register(suppliers, vulns_by_purl=vulns, concentration_findings=[])
    assert register[0].max_severity == "CRITICAL"
    assert register[0].vuln_counts_by_severity["CRITICAL"] == 1
    assert register[0].composite_score == 25


def test_direct_vs_transitive_counts():
    suppliers = [
        Supplier(
            name="v",
            path=".",
            components=[_c("a", "1", direct=True, depth=1), _c("b", "1", direct=False, depth=2)],
        )
    ]
    register = build_risk_register(suppliers, vulns_by_purl={}, concentration_findings=[])
    assert register[0].direct_count == 1
    assert register[0].transitive_count == 1
    assert register[0].component_count == 2


def test_concentration_flags_attached_and_scored():
    comp = _c("lodash", "4.17.15")
    suppliers = [Supplier(name="v1", path=".", components=[comp])]
    finding = ConcentrationFinding(component_key="npm:lodash", suppliers=["v1", "v2"], versions={})
    register = build_risk_register(suppliers, vulns_by_purl={}, concentration_findings=[finding])
    assert register[0].concentration_flags == ["npm:lodash"]
    assert register[0].composite_score == 5


def test_score_capped_at_100():
    comps = [_c(f"pkg{i}", "1") for i in range(10)]
    suppliers = [Supplier(name="v", path=".", components=comps)]
    vulns = {c.purl: [Vulnerability(id=f"id{i}", summary="", severity="CRITICAL", score=9.9)] for i, c in enumerate(comps)}
    register = build_risk_register(suppliers, vulns_by_purl=vulns, concentration_findings=[])
    assert register[0].composite_score == 100


def test_register_sorted_highest_risk_first():
    low = Supplier(name="low", path=".", components=[_c("a", "1")])
    comp = _c("b", "1")
    high = Supplier(name="high", path=".", components=[comp])
    vulns = {comp.purl: [Vulnerability(id="x", summary="", severity="CRITICAL", score=9.8)]}
    register = build_risk_register([low, high], vulns_by_purl=vulns, concentration_findings=[])
    assert [e.supplier for e in register] == ["high", "low"]


def test_to_json_roundtrip_shape():
    suppliers = [Supplier(name="v", path=".", components=[_c("a", "1")])]
    register = build_risk_register(suppliers, vulns_by_purl={}, concentration_findings=[])
    data = to_json(register)
    assert data[0]["supplier"] == "v"
    assert "composite_score" in data[0]


def test_to_csv_has_header_and_row():
    suppliers = [Supplier(name="v", path=".", components=[_c("a", "1")])]
    register = build_risk_register(suppliers, vulns_by_purl={}, concentration_findings=[])
    csv_text = to_csv(register)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("supplier,")
    assert lines[1].startswith("v,")
