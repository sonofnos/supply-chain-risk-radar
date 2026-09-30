"""Validate generated SBOMs against the real, vendored CycloneDX 1.5 JSON
schema (schemas/bom-1.5.schema.json, fetched from
github.com/CycloneDX/specification) using jsonschema's Draft7Validator —
not a hand-rolled shape check."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from scradar.cyclonedx import build_sbom
from scradar.models import Component

SCHEMA_DIR = Path(__file__).parent.parent / "schemas"


@pytest.fixture(scope="module")
def validator():
    bom_schema = json.loads((SCHEMA_DIR / "bom-1.5.schema.json").read_text())
    spdx_schema = json.loads((SCHEMA_DIR / "spdx.schema.json").read_text())
    jsf_schema = json.loads((SCHEMA_DIR / "jsf-0.82.schema.json").read_text())

    registry = Registry().with_resources(
        [
            (bom_schema["$id"], Resource.from_contents(bom_schema)),
            (spdx_schema["$id"], Resource.from_contents(spdx_schema)),
            (jsf_schema["$id"], Resource.from_contents(jsf_schema)),
        ]
    )
    return jsonschema.Draft7Validator(bom_schema, registry=registry)


def test_empty_sbom_validates(validator):
    sbom = build_sbom("empty-supplier", [])
    validator.validate(sbom)


def test_sbom_with_components_validates(validator):
    components = [
        Component(name="requests", version="2.31.0", ecosystem="PyPI", direct=True, depth=1),
        Component(name="lodash", version="4.17.21", ecosystem="npm", direct=False, depth=2),
        Component(name="@vue/test-utils", version="2.5.1", ecosystem="npm", direct=True, depth=1),
    ]
    sbom = build_sbom("demo-supplier", components)
    validator.validate(sbom)


def test_sbom_has_required_top_level_fields():
    sbom = build_sbom("x", [])
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")


def test_invalid_bom_format_is_rejected_by_schema(validator):
    """Sanity check that the schema is actually doing work, not just
    passing everything: an obviously wrong bomFormat must fail."""
    sbom = build_sbom("x", [])
    sbom["bomFormat"] = "NOT-CYCLONEDX"
    with pytest.raises(jsonschema.exceptions.ValidationError):
        validator.validate(sbom)


def test_component_missing_type_is_rejected_by_schema(validator):
    sbom = build_sbom(
        "x", [Component(name="requests", version="2.31.0", ecosystem="PyPI", direct=True, depth=1)]
    )
    del sbom["components"][0]["type"]
    with pytest.raises(jsonschema.exceptions.ValidationError):
        validator.validate(sbom)
