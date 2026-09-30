"""Given a directory, figure out which manifest parser applies."""
from __future__ import annotations

from pathlib import Path

from scradar.manifests.node_manifest import parse_package_json, parse_package_lock
from scradar.manifests.python_manifest import parse_pyproject_toml, parse_requirements_txt
from scradar.models import Component


def discover_components(repo_path: str | Path) -> tuple[list[Component], str]:
    """Returns (components, manifest_kind). Preference order per
    ecosystem: a real lockfile beats a manifest with no resolved
    versions/tree. If both a Python and Node manifest exist in the same
    directory, both are included (a repo can have a backend and a
    frontend manifest side by side)."""
    p = Path(repo_path)
    components: list[Component] = []
    kinds: list[str] = []

    lock = p / "package-lock.json"
    pkg_json = p / "package.json"
    if lock.exists():
        components += parse_package_lock(lock)
        kinds.append("package-lock.json")
    elif pkg_json.exists():
        components += parse_package_json(pkg_json)
        kinds.append("package.json (no lockfile — direct deps only)")

    req_txt = p / "requirements.txt"
    pyproject = p / "pyproject.toml"
    if req_txt.exists():
        components += parse_requirements_txt(req_txt)
        kinds.append("requirements.txt")
    elif pyproject.exists():
        components += parse_pyproject_toml(pyproject)
        kinds.append("pyproject.toml")

    if not kinds:
        raise FileNotFoundError(
            f"No supported manifest found under {p} "
            "(looked for package-lock.json, package.json, requirements.txt, pyproject.toml)"
        )
    return components, "+".join(kinds)
