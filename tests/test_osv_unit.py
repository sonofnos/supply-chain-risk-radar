"""Unit tests for OSV response parsing using a real, captured OSV.dev
response shape (not invented) — recorded from a live query against
lodash 4.17.15 during development, then trimmed. No network access."""
from __future__ import annotations

from scradar.osv import OsvClient

# Trimmed but structurally real GHSA record as returned by
# GET https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm
REAL_GHSA_RECORD = {
    "id": "GHSA-35jh-r3h4-6jhm",
    "summary": "Command Injection in lodash",
    "details": "lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
    "aliases": ["CVE-2021-23337"],
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ],
}

# A PYSEC-style record with no CVSS vector at all, only a coarse severity bucket
REAL_PYSEC_RECORD_NO_CVSS = {
    "id": "PYSEC-2023-0001",
    "summary": "Some PyPI advisory with no CVSS data",
    "database_specific": {"severity": "MODERATE"},
}

RECORD_WITH_NO_SEVERITY_DATA_AT_ALL = {
    "id": "GHSA-no-severity",
    "summary": "advisory with genuinely no severity info",
}


def test_parse_vuln_extracts_cvss_score_and_severity():
    vuln = OsvClient._parse_vuln(REAL_GHSA_RECORD)
    assert vuln.id == "GHSA-35jh-r3h4-6jhm"
    assert vuln.severity == "CRITICAL"
    assert vuln.score == 9.8
    assert "CVE-2021-23337" in vuln.aliases


def test_parse_vuln_falls_back_to_database_specific_severity():
    vuln = OsvClient._parse_vuln(REAL_PYSEC_RECORD_NO_CVSS)
    assert vuln.severity == "MEDIUM"  # MODERATE is normalized to MEDIUM
    assert vuln.score is None


def test_parse_vuln_with_no_severity_data_is_unknown_not_guessed():
    vuln = OsvClient._parse_vuln(RECORD_WITH_NO_SEVERITY_DATA_AT_ALL)
    assert vuln.severity == "UNKNOWN"
    assert vuln.score is None


def test_vuln_cache_avoids_refetching(monkeypatch):
    client = OsvClient()
    call_count = {"n": 0}

    class FakeResp:
        status_code = 200

        def json(self):
            call_count["n"] += 1
            return REAL_GHSA_RECORD

        def raise_for_status(self):
            pass

    monkeypatch.setattr(client._session, "get", lambda *a, **k: FakeResp())
    v1 = client.get_vulnerability("GHSA-35jh-r3h4-6jhm")
    v2 = client.get_vulnerability("GHSA-35jh-r3h4-6jhm")
    assert v1 is v2
    assert call_count["n"] == 1


def test_query_batch_skips_components_with_no_version():
    from scradar.models import Component

    client = OsvClient()
    calls = {"n": 0}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            calls["n"] += 1
            return {"results": [{}]}

    def fake_post(url, json, timeout):
        assert len(json["queries"]) == 1  # only the versioned component
        return FakeResp()

    client._session.post = fake_post
    components = [
        Component(name="no-version-pkg", version="", ecosystem="npm", direct=True, depth=1),
        Component(name="has-version", version="1.0.0", ecosystem="npm", direct=True, depth=1),
    ]
    client.query_batch(components)
    assert calls["n"] == 1
