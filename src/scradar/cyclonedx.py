"""Build a real CycloneDX 1.5 JSON SBOM from parsed components.

Fields follow the CycloneDX JSON schema (bomFormat, specVersion,
components[].type/name/version/purl). The schema is vendored at
schemas/bom-1.5.schema.json and every SBOM this module produces is
validated against it in tests/test_cyclonedx_schema.py using the real
`jsonschema` Draft7Validator — not a hand-rolled check.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from scradar.models import Component

SPEC_VERSION = "1.5"


def build_sbom(supplier_name: str, components: list[Component]) -> dict:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom_components = []
    for c in components:
        bom_components.append(
            {
                "type": "library",
                "bom-ref": c.purl,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "scope": "required" if c.direct else "optional",
                "properties": [
                    {"name": "scradar:depth", "value": str(c.depth)},
                    {"name": "scradar:direct", "value": "true" if c.direct else "false"},
                ],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "component": {
                "type": "application",
                "name": supplier_name,
                "bom-ref": f"supplier:{supplier_name}",
            },
        },
        "components": bom_components,
    }
