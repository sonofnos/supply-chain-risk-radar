"""Real integration test against the live OSV.dev API. No mocking, no
VCR fixture — this actually hits https://api.osv.dev over the network.
Marked `integration` so it can be skipped in restricted/offline CI
environments with `pytest -m "not integration"`, but it runs by default
and is what actually proves the OSV client works against the real
service, not a stub of it."""
from __future__ import annotations

import pytest

from scradar.models import Component
from scradar.osv import OsvClient

pytestmark = pytest.mark.integration


def test_known_vulnerable_lodash_version_has_findings():
    client = OsvClient()
    comp = Component(name="lodash", version="4.17.15", ecosystem="npm", direct=True, depth=1)
    matches = client.query_batch([comp])
    assert comp.purl in matches
    assert len(matches[comp.purl]) > 0


def test_vuln_detail_has_real_fields():
    client = OsvClient()
    comp = Component(name="lodash", version="4.17.15", ecosystem="npm", direct=True, depth=1)
    matches = client.query_batch([comp])
    vuln_id = matches[comp.purl][0]
    vuln = client.get_vulnerability(vuln_id)
    assert vuln.id == vuln_id
    assert vuln.summary
    assert vuln.severity in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}


def test_clean_package_has_no_findings():
    client = OsvClient()
    # a trivial, actively maintained package pinned to a recent version
    comp = Component(name="is-odd", version="3.0.1", ecosystem="npm", direct=True, depth=1)
    matches = client.query_batch([comp])
    assert comp.purl not in matches
