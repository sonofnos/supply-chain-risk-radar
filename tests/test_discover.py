from pathlib import Path

import pytest

from scradar.discover import discover_components

FIXTURES = Path(__file__).parent / "fixtures"


def test_discovers_node_lockfile():
    components, kind = discover_components(FIXTURES / "nodelib")
    assert kind == "package-lock.json"
    assert len(components) == 8


def test_discovers_python_requirements():
    components, kind = discover_components(FIXTURES / "pylib")
    assert kind == "requirements.txt"
    names = {c.name for c in components}
    assert "requests" in names


def test_raises_when_nothing_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        discover_components(tmp_path)
