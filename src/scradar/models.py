"""Core data model shared across manifest parsing, SBOM generation, OSV
matching and risk scoring.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote


@dataclass(frozen=True)
class Component:
    """A single resolved dependency, direct or transitive.

    ``path`` is the resolution path used to build the dependency graph
    (for npm: the node_modules path used in package-lock.json; for
    Python manifests we do not currently reconstruct a real tree, so
    ``path`` is just the component name and ``depth`` is always 1 —
    see README limitations).
    """

    name: str
    version: str
    ecosystem: str  # "PyPI" or "npm" (matches OSV.dev ecosystem names)
    direct: bool
    depth: int
    path: str = ""

    @property
    def purl(self) -> str:
        if self.ecosystem == "PyPI":
            # PyPI purls are lowercased / normalized per PEP 503
            norm = self.name.lower().replace("_", "-").replace(".", "-")
            return f"pkg:pypi/{norm}@{self.version}"
        if self.ecosystem == "npm":
            if self.name.startswith("@"):
                scope, _, rest = self.name.partition("/")
                return f"pkg:npm/{quote(scope)}/{rest}@{self.version}"
            return f"pkg:npm/{quote(self.name)}@{self.version}"
        return f"pkg:generic/{quote(self.name)}@{self.version}"

    @property
    def key(self) -> str:
        """Identity key ignoring version, used for concentration-risk
        grouping (same library across suppliers, any version)."""
        return f"{self.ecosystem}:{self.name.lower()}"


@dataclass
class Supplier:
    name: str
    path: str
    components: list[Component] = field(default_factory=list)
