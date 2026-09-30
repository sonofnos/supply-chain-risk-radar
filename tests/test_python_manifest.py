from pathlib import Path

from scradar.manifests.python_manifest import parse_pyproject_toml, parse_requirements_txt

FIXTURES = Path(__file__).parent / "fixtures" / "pylib"


def test_requirements_txt_only_pins_are_kept():
    components = parse_requirements_txt(FIXTURES / "requirements.txt")
    names = {c.name for c in components}
    assert names == {"requests", "click", "django-cors-headers"}
    assert "flask" not in names  # unpinned (>=2.0), correctly skipped


def test_requirements_txt_all_direct_depth_1():
    components = parse_requirements_txt(FIXTURES / "requirements.txt")
    assert all(c.direct and c.depth == 1 for c in components)
    assert all(c.ecosystem == "PyPI" for c in components)


def test_requirements_txt_versions():
    components = {c.name: c.version for c in parse_requirements_txt(FIXTURES / "requirements.txt")}
    assert components["requests"] == "2.31.0"
    assert components["click"] == "8.1.7"


def test_pyproject_toml_pinned_only():
    components = {c.name: c.version for c in parse_pyproject_toml(FIXTURES / "pyproject.toml")}
    # "click>=8.0" is unpinned and should be skipped; pytest==8.2.0 comes from optional-deps
    assert components == {"requests": "2.31.0", "pytest": "8.2.0"}
