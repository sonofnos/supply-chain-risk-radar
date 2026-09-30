from pathlib import Path

import pytest

from scradar.manifests.node_manifest import parse_package_lock

FIXTURES = Path(__file__).parent / "fixtures" / "nodelib"


def _by_path(components):
    return {c.path: c for c in components}


def test_direct_deps_are_depth_1():
    components = _by_path(parse_package_lock(FIXTURES / "package-lock.json"))
    assert components["node_modules/a"].direct is True
    assert components["node_modules/a"].depth == 1
    assert components["node_modules/b"].direct is True
    assert components["node_modules/b"].depth == 1


def test_dev_dependency_counts_as_direct():
    components = _by_path(parse_package_lock(FIXTURES / "package-lock.json"))
    assert components["node_modules/dev-only"].direct is True
    assert components["node_modules/dev-only"].depth == 1


def test_nested_transitive_dep_gets_real_depth():
    components = _by_path(parse_package_lock(FIXTURES / "package-lock.json"))
    # a depends on c@^1.0.0, which only resolves at a/node_modules/c (nested, not hoisted)
    nested_c = components["node_modules/a/node_modules/c"]
    assert nested_c.direct is False
    assert nested_c.depth == 2
    assert nested_c.version == "1.5.0"


def test_hoisted_transitive_dep_via_b_gets_real_depth_not_path_depth():
    """This is the case that a naive "depth = node_modules path nesting count"
    heuristic gets wrong: top-level node_modules/c looks like depth 1 by path
    nesting, but it is only reachable as a dependency of b (depth 1), so its
    real graph depth is 2, and it must NOT be marked direct even though it
    sits at the top level of node_modules."""
    components = _by_path(parse_package_lock(FIXTURES / "package-lock.json"))
    hoisted_c = components["node_modules/c"]
    assert hoisted_c.direct is False
    assert hoisted_c.depth == 2
    assert hoisted_c.version == "2.0.0"


def test_orphan_package_not_reachable_from_any_declared_edge_is_conservative():
    components = _by_path(parse_package_lock(FIXTURES / "package-lock.json"))
    orphan = components["node_modules/orphan"]
    assert orphan.direct is False
    assert orphan.depth == 2  # conservative fallback, see node_manifest.py docstring


def test_component_count():
    components = parse_package_lock(FIXTURES / "package-lock.json")
    # a, b, c(hoisted), c(nested), dev-only, orphan, optchain, leafopt
    assert len(components) == 8


def test_optional_dependency_chain_gets_real_depth_not_fallback():
    """Regression test for a real bug: vite in docwise/frontend's actual
    package-lock.json declares fsevents only under optionalDependencies,
    never under dependencies. The BFS originally only walked
    "dependencies" (+devDependencies at the root), so anything only
    reachable via optionalDependencies was invisible to it and silently
    got the conservative fallback depth (2) instead of its real graph
    depth. Fixed by also walking optionalDependencies. This fixture
    reproduces it with a 3-deep chain (a -> optchain [optional] ->
    leafopt) where the fallback default (2) and the real depth (3)
    actually disagree, unlike the original fsevents case where they
    coincidentally matched."""
    components = _by_path(parse_package_lock(FIXTURES / "package-lock.json"))
    optchain = components["node_modules/a/node_modules/optchain"]
    leafopt = components["node_modules/a/node_modules/optchain/node_modules/leafopt"]
    assert optchain.direct is False
    assert optchain.depth == 2
    assert leafopt.direct is False
    assert leafopt.depth == 3  # would be 2 (wrong) under the pre-fix fallback


def test_rejects_lockfile_v1():
    import json
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"lockfileVersion": 1, "dependencies": {}}, f)
        path = f.name
    with pytest.raises(ValueError, match="lockfileVersion"):
        parse_package_lock(path)
