from scradar.concentration import find_concentration_risk
from scradar.models import Component, Supplier


def _c(name, version, ecosystem="npm", direct=True, depth=1):
    return Component(name=name, version=version, ecosystem=ecosystem, direct=direct, depth=depth)


def test_shared_component_across_suppliers_flagged():
    suppliers = [
        Supplier(name="vendor-a", path=".", components=[_c("lodash", "4.17.15"), _c("axios", "1.2.0")]),
        Supplier(name="vendor-b", path=".", components=[_c("lodash", "4.17.21")]),
        Supplier(name="vendor-c", path=".", components=[_c("left-pad", "1.0.0")]),
    ]
    findings = find_concentration_risk(suppliers, min_suppliers=2)
    assert len(findings) == 1
    assert findings[0].component_key == "npm:lodash"
    assert findings[0].suppliers == ["vendor-a", "vendor-b"]
    assert findings[0].versions == {"vendor-a": "4.17.15", "vendor-b": "4.17.21"}


def test_no_findings_below_threshold():
    suppliers = [
        Supplier(name="vendor-a", path=".", components=[_c("axios", "1.2.0")]),
        Supplier(name="vendor-b", path=".", components=[_c("left-pad", "1.0.0")]),
    ]
    assert find_concentration_risk(suppliers, min_suppliers=2) == []


def test_sorted_by_supplier_count_descending():
    suppliers = [
        Supplier(name="a", path=".", components=[_c("x", "1"), _c("y", "1")]),
        Supplier(name="b", path=".", components=[_c("x", "1"), _c("y", "1")]),
        Supplier(name="c", path=".", components=[_c("x", "1")]),
    ]
    findings = find_concentration_risk(suppliers, min_suppliers=2)
    assert [f.component_key for f in findings] == ["npm:x", "npm:y"]
    assert len(findings[0].suppliers) == 3
    assert len(findings[1].suppliers) == 2


def test_different_ecosystems_same_name_not_conflated():
    suppliers = [
        Supplier(name="a", path=".", components=[_c("requests", "1", ecosystem="PyPI")]),
        Supplier(name="b", path=".", components=[_c("requests", "1", ecosystem="npm")]),
    ]
    assert find_concentration_risk(suppliers, min_suppliers=2) == []
