"""Parse Python dependency manifests.

Honest limitation (see README): neither ``requirements.txt`` nor a plain
PEP 621 ``pyproject.toml`` records a resolved dependency *tree* — only
pip-compile output with ``# via`` annotations or a lockfile (poetry.lock,
uv.lock) would. We do not parse those lock formats yet, so every Python
component is reported as a **direct** dependency at depth 1. This is a
real, stated gap, not a bug we're hiding: transitive Python risk is
under-counted compared to the npm path, which resolves a real tree from
package-lock.json.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from scradar.models import Component

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+-]*)\s*(?:;.*)?$"
)

# PEP 508 dependency specifier, e.g. "requests>=2.31,<3" or "click==8.1.7"
_PEP508 = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$"
)
_PINNED_VERSION = re.compile(r"==\s*([A-Za-z0-9][A-Za-z0-9._+-]*)")


def parse_requirements_txt(path: str | Path) -> list[Component]:
    """Parse a pip ``requirements.txt``. Only exact pins (``==``) yield a
    component we can look up in OSV — unpinned/range requirements are
    skipped because OSV needs a concrete version to match against."""
    text = Path(path).read_text(encoding="utf-8")
    components: list[Component] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # strip inline comments
        line = line.split(" #", 1)[0].strip()
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        components.append(
            Component(name=name, version=version, ecosystem="PyPI", direct=True, depth=1, path=name)
        )
    return components


def parse_pyproject_toml(path: str | Path) -> list[Component]:
    """Parse PEP 621 ``[project.dependencies]`` (and optional-dependencies)
    from pyproject.toml. Only pinned (``==``) entries resolve to a
    component; ranged/unpinned deps are skipped (same reasoning as
    requirements.txt — see module docstring)."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    project = data.get("project", {})
    specs: list[str] = list(project.get("dependencies", []) or [])
    for extra_deps in (project.get("optional-dependencies", {}) or {}).values():
        specs.extend(extra_deps)

    components: list[Component] = []
    seen: set[str] = set()
    for spec in specs:
        m = _PEP508.match(spec.strip())
        if not m:
            continue
        name = m.group(1)
        rest = m.group(3) or ""
        vm = _PINNED_VERSION.search(rest)
        if not vm:
            continue
        version = vm.group(1)
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        components.append(
            Component(name=name, version=version, ecosystem="PyPI", direct=True, depth=1, path=name)
        )
    return components
