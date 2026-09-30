import pytest

from scradar.cvss import InvalidCvssVector, score_vector


def test_known_critical_vector():
    # textbook CVSS v3.1 example, widely published base score 9.8
    result = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result.score == 9.8
    assert result.severity == "CRITICAL"


def test_known_medium_scope_changed_vector():
    result = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert result.score == 6.1
    assert result.severity == "MEDIUM"


def test_no_impact_scores_zero():
    result = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert result.score == 0.0
    assert result.severity == "NONE"


def test_rejects_non_cvss3_vector():
    with pytest.raises(InvalidCvssVector):
        score_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C")  # CVSS v2 style, no "CVSS:3.x" prefix


def test_rejects_incomplete_vector():
    with pytest.raises(InvalidCvssVector):
        score_vector("CVSS:3.1/AV:N/AC:L")
