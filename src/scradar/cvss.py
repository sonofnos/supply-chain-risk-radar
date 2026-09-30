"""Minimal CVSS v3.1 base-score calculator.

OSV.dev vulnerability records that carry a CVSS score store it as the
*vector string* (e.g. ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``),
not a precomputed number, and plenty of records — especially PyPI/PYSEC
advisories — carry no CVSS data at all, only a GHSA-style
``database_specific.severity`` bucket. This module implements the
official CVSS v3.1 base-score formula (FIRST.org spec section 7.3) so we
can turn a vector string into a numeric score and severity bucket
ourselves, rather than pretending every finding has a score when it
doesn't.

This is intentionally scoped to CVSS v3.0/3.1 base metrics only — no
temporal/environmental metrics, no CVSS v2 or v4. See README
limitations.
"""
from __future__ import annotations

from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


class InvalidCvssVector(ValueError):
    pass


@dataclass(frozen=True)
class CvssResult:
    score: float
    severity: str  # NONE/LOW/MEDIUM/HIGH/CRITICAL per FIRST.org rating scale


def _severity_for(score: float) -> str:
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _round_up(value: float) -> float:
    """CVSS 'round up' per spec: round to nearest 0.1, always upward."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (int_value // 10000 + 1) / 10.0


def parse_cvss_v3_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3."):
        raise InvalidCvssVector(f"not a CVSS v3.x vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise InvalidCvssVector(f"malformed metric segment: {part!r} in {vector!r}")
        key, _, value = part.partition(":")
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - metrics.keys()
    if missing:
        raise InvalidCvssVector(f"vector missing required metrics {sorted(missing)}: {vector!r}")
    return metrics


def score_vector(vector: str) -> CvssResult:
    """Compute the CVSS v3.1 base score for a vector string."""
    m = parse_cvss_v3_vector(vector)
    scope_changed = m["S"] == "C"

    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        ui = _UI[m["UI"]]
        c = _CIA[m["C"]]
        i = _CIA[m["I"]]
        a = _CIA[m["A"]]
    except KeyError as exc:
        raise InvalidCvssVector(f"unknown metric value {exc} in vector {vector!r}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if not scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif not scope_changed:
        base_score = _round_up(min(impact + exploitability, 10.0))
    else:
        base_score = _round_up(min(1.08 * (impact + exploitability), 10.0))

    return CvssResult(score=base_score, severity=_severity_for(base_score))
