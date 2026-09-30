"""Parse npm dependency manifests.

``package-lock.json`` (lockfile version 2 or 3, i.e. npm >= 7) gives us a
real resolved dependency tree: every installed package's on-disk
``node_modules`` path, plus each package's own declared
``dependencies``/``devDependencies``. We reconstruct the real dependency
graph by replaying Node's module resolution algorithm (walk up
node_modules directories looking for the nearest match) rather than
guessing depth from path nesting alone — path nesting is unreliable once
npm hoists a package to a shared ancestor node_modules directory.

Lockfile version 1 (npm <= 6, tree-shaped ``dependencies``) is **not**
supported — see README limitations.

When only ``package.json`` is available (no lockfile), we can only report
declared direct dependencies with their semver *range*, not a resolved
version or any transitive tree. OSV lookups are skipped for those
because OSV needs a concrete version.
"""
from __future__ import annotations

import json
from pathlib import Path

from scradar.models import Component


def parse_package_json(path: str | Path) -> list[Component]:
    """Fallback parser when no package-lock.json is present. Declared
    direct deps only; version is whatever range string is in
    package.json, which is often not a real installable version (e.g.
    ``^1.2.0``) so these components are best-effort and typically will
    not resolve cleanly against OSV's exact-version matching."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    components: list[Component] = []
    for section in ("dependencies", "devDependencies"):
        for name, version_range in (data.get(section) or {}).items():
            version = version_range.lstrip("^~>=< ")
            components.append(
                Component(name=name, version=version, ecosystem="npm", direct=True, depth=1, path=name)
            )
    return components


def _resolve(entries: dict, from_path: str, name: str) -> str | None:
    """Replay Node's module resolution: from ``from_path``, look for
    ``node_modules/<name>`` at this level, then walk up one
    node_modules segment at a time until the root."""
    cur = from_path
    while True:
        candidate = f"{cur}/node_modules/{name}" if cur else f"node_modules/{name}"
        if candidate in entries:
            return candidate
        if cur == "":
            return None
        idx = cur.rfind("/node_modules/")
        if idx == -1:
            # cur is itself "node_modules/xxx" (top-level) -> go to root
            cur = ""
        else:
            cur = cur[:idx]


def parse_package_lock(path: str | Path) -> list[Component]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    lockfile_version = data.get("lockfileVersion")
    if lockfile_version not in (2, 3):
        raise ValueError(
            f"Unsupported package-lock.json lockfileVersion={lockfile_version!r}; "
            "only npm lockfile v2/v3 (npm >= 7) is supported. See README limitations."
        )
    packages: dict = data.get("packages") or {}
    if "" not in packages:
        raise ValueError("package-lock.json has no root '' entry (unexpected format)")

    root = packages[""]
    direct_names = set((root.get("dependencies") or {}).keys()) | set(
        (root.get("devDependencies") or {}).keys()
    )

    # BFS from root over the *declared* dependency names of each package,
    # resolving each declared name to its real installed path via Node's
    # resolution algorithm. This gives real depth (shortest path from the
    # supplier root) and correctly marks a name as transitive even if npm
    # happened to hoist it to the top-level node_modules directory.
    from collections import deque

    best_depth: dict[str, int] = {"": 0}
    queue: deque[str] = deque([""])
    visited_edges: set[tuple[str, str]] = set()

    while queue:
        cur_path = queue.popleft()
        cur_depth = best_depth[cur_path]
        cur_entry = packages.get(cur_path, {})
        # Real bug found while running this against docwise/frontend's actual
        # lockfile: vite declares fsevents only under optionalDependencies
        # (it's a macOS-only native watcher), never under dependencies. Only
        # walking "dependencies" left fsevents unreachable by any BFS edge,
        # so it silently fell back to the conservative default depth (2)
        # instead of its real graph depth — which happened to also be 2
        # here only because vite itself sits at depth 1, masking the bug
        # until a deeper optional-only chain is scanned. Fixed by walking
        # optionalDependencies too.
        declared = dict(cur_entry.get("dependencies") or {})
        declared.update(cur_entry.get("optionalDependencies") or {})
        if cur_path == "":
            declared.update(root.get("devDependencies") or {})
        for dep_name in declared:
            target = _resolve(packages, cur_path, dep_name)
            if target is None or target not in packages:
                continue  # optional/peer dep not actually installed
            edge = (cur_path, target)
            if edge in visited_edges:
                continue
            visited_edges.add(edge)
            new_depth = cur_depth + 1
            if target not in best_depth or new_depth < best_depth[target]:
                best_depth[target] = new_depth
                queue.append(target)

    components: list[Component] = []
    for pkg_path, entry in packages.items():
        if pkg_path == "":
            continue
        if entry.get("link"):
            continue  # symlinked local workspace package, not a real dependency
        name = entry.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        if not version:
            continue  # e.g. a git/file dependency with no resolvable semver
        depth = best_depth.get(pkg_path)
        if depth is None:
            # Reachable in node_modules on disk but not via any declared
            # dependency edge we could resolve (e.g. npm optional-dep
            # quirks). Treat conservatively as transitive at unknown depth.
            depth = 2
        is_direct = depth == 1 and name in direct_names
        components.append(
            Component(
                name=name,
                version=version,
                ecosystem="npm",
                direct=is_direct,
                depth=depth,
                path=pkg_path,
            )
        )
    return components
