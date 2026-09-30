"""Query the real OSV.dev API (https://osv.dev) for known vulnerabilities
matching SBOM components, by package name + ecosystem + version.

OSV's ``querybatch`` endpoint (POST /v1/querybatch) is deliberately
cheap: for each queried package it returns only vulnerability *ids*, not
severity or summary. To get anything usable for a risk register you
must follow up with a GET to ``/v1/vulns/{id}`` per id. This module does
both, with:

- an in-process cache keyed by vuln id (so the same CVE/GHSA referenced
  by components across multiple suppliers is only fetched once), and
- a naive but real rate limiter (fixed delay between HTTP calls) because
  hammering /v1/vulns/{id} in a tight loop for a large SBOM gets you
  429s from OSV — see README "real bugs found" section.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from scradar.cvss import InvalidCvssVector, score_vector
from scradar.models import Component

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
BATCH_SIZE = 100  # OSV's documented max queries per querybatch request


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str  # NONE/LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN
    score: float | None
    aliases: list[str] = field(default_factory=list)


class OsvClient:
    def __init__(
        self,
        session: requests.Session | None = None,
        rate_limit_seconds: float = 0.1,
        max_retries: int = 3,
    ) -> None:
        self._session = session or requests.Session()
        self._rate_limit_seconds = rate_limit_seconds
        self._max_retries = max_retries
        self._vuln_cache: dict[str, Vulnerability] = {}
        self._last_call = 0.0

    def _throttled_get(self, url: str) -> requests.Response:
        elapsed = time.monotonic() - self._last_call
        if elapsed < self._rate_limit_seconds:
            time.sleep(self._rate_limit_seconds - elapsed)
        for attempt in range(self._max_retries):
            resp = self._session.get(url, timeout=15)
            self._last_call = time.monotonic()
            if resp.status_code == 429 and attempt < self._max_retries - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
            return resp
        return resp

    def query_batch(self, components: list[Component]) -> dict[str, list[str]]:
        """Returns {component.purl: [vuln_id, ...]} for components that
        have at least one match. Skips components with no version info.
        Handles OSV's batch page limit by chunking into groups of
        BATCH_SIZE, and follows querybatch's ``next_page_token`` for
        results that don't fit on one page."""
        results: dict[str, list[str]] = {}
        queryable = [c for c in components if c.version]
        for i in range(0, len(queryable), BATCH_SIZE):
            chunk = queryable[i : i + BATCH_SIZE]
            queries = [
                {"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version}
                for c in chunk
            ]
            page_token = None
            merged: list[dict] = []
            while True:
                body: dict = {"queries": queries}
                if page_token:
                    body["query"] = {"page_token": page_token}
                resp = self._session.post(OSV_QUERYBATCH_URL, json=body, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                page_results = data.get("results", [])
                if not merged:
                    merged = page_results
                else:
                    for j, r in enumerate(page_results):
                        merged[j].setdefault("vulns", []).extend(r.get("vulns", []))
                page_token = data.get("next_page_token")
                if not page_token:
                    break
            for component, result in zip(chunk, merged):
                vulns = result.get("vulns", [])
                if vulns:
                    results[component.purl] = [v["id"] for v in vulns]
        return results

    def get_vulnerability(self, vuln_id: str) -> Vulnerability:
        if vuln_id in self._vuln_cache:
            return self._vuln_cache[vuln_id]
        resp = self._throttled_get(OSV_VULN_URL.format(id=vuln_id))
        resp.raise_for_status()
        data = resp.json()
        vuln = self._parse_vuln(data)
        self._vuln_cache[vuln_id] = vuln
        return vuln

    @staticmethod
    def _parse_vuln(data: dict) -> Vulnerability:
        vuln_id = data.get("id", "UNKNOWN")
        summary = data.get("summary") or data.get("details", "")[:200] or ""
        severity = "UNKNOWN"
        score: float | None = None

        db_severity = (data.get("database_specific") or {}).get("severity")
        if isinstance(db_severity, str) and db_severity.upper() in {
            "LOW",
            "MEDIUM",
            "MODERATE",
            "HIGH",
            "CRITICAL",
        }:
            severity = "MEDIUM" if db_severity.upper() == "MODERATE" else db_severity.upper()

        for sev_entry in data.get("severity") or []:
            if sev_entry.get("type", "").startswith("CVSS_V3"):
                try:
                    result = score_vector(sev_entry["score"])
                except (InvalidCvssVector, KeyError):
                    continue
                score = result.score
                severity = result.severity  # CVSS score, when present, is authoritative
                break

        aliases = data.get("aliases") or []
        return Vulnerability(id=vuln_id, summary=summary, severity=severity, score=score, aliases=aliases)
