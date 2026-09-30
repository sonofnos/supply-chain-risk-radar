# supply-chain-risk-radar

SBOM generation, real OSV.dev vulnerability matching, Nth-party (transitive) dependency depth mapping, and cross-supplier concentration-risk scoring — the technical infrastructure layer under third-party/supply-chain cyber risk work, not a simulation of the GRC process around it (no fake questionnaires, no fake contracts, no fake committees — those aren't code).

Given a set of "suppliers" (each just a path to a real repo), it:

1. Parses real dependency manifests (npm `package-lock.json`/`package.json`, Python `requirements.txt`/`pyproject.toml`) into a **CycloneDX 1.5 JSON SBOM** — real schema fields (`bomFormat`, `specVersion`, `components[].type/name/version/purl`), validated against the actual vendored CycloneDX schema in tests, not a hand-rolled format.
2. Queries the real **OSV.dev API** (`api.osv.dev`, no auth) to find known vulnerabilities per component, with its own **CVSS v3.1 base-score calculator** (OSV gives you a vector string, not a number) and severity bucketing.
3. Reconstructs the **real transitive dependency graph** from `package-lock.json` by replaying Node's module resolution algorithm, so "depth" (hops from the supplier to a vulnerable component) is computed from an actual resolved graph, not guessed from `node_modules/` path nesting (which hoisting makes unreliable — see [bugs](#real-bugs-found-while-building-this) below).
4. Computes **concentration risk**: which components appear across ≥N suppliers, regardless of version — the log4j-shaped question of "if this one library is compromised, how many vendors are exposed at once."
5. Produces a **per-supplier risk register** (JSON + CSV): component counts, direct vs. transitive split, vulnerability counts by severity, max severity, concentration flags, and a composite score.
6. Runs as a **scheduled GitHub Actions job** against real public target repos and fails the build if a NEW critical vulnerability appears versus a committed baseline.

## Why this exists

A UK bank's third-party/supply-chain cyber risk team needs to answer, for every supplier: what's actually in their software, is any of it known-vulnerable, how deep does the risk go (a vendor's vendor's library), and are we over-concentrated on any one component. That's a data-pipeline problem — parse manifests, hit a vuln database, walk a graph, aggregate — and this repo is a working version of that pipeline, built and run against real repos, not a mockup.

## Running it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# one repo -> one SBOM
python -m scradar.cli sbom --path /path/to/some/repo --supplier acme-vendor --out sbom.json

# full scan: SBOMs + OSV + concentration + risk register, for a set of suppliers
python -m scradar.cli scan --config demo_configs/suppliers.json --out-dir out/
cat out/risk-register.json
cat out/risk-register.csv

# monitoring: fail if a NEW critical vuln appeared since a committed baseline
python -m scradar.cli diff-baseline --baseline docs/baseline-risk-register.json --current out/risk-register.json
```

`demo_configs/suppliers.json` is a plain JSON list of `{"name": ..., "path": ...}`. Point `path` at any directory with a supported manifest.

## Architecture

```
src/scradar/
  manifests/
    node_manifest.py     # package-lock.json (v2/v3) -> real resolved dependency graph
    python_manifest.py   # requirements.txt / pyproject.toml -> direct deps only
  discover.py             # picks the right parser(s) for a repo
  models.py                # Component/Supplier + purl generation
  cyclonedx.py             # builds a real CycloneDX 1.5 JSON SBOM
  cvss.py                  # CVSS v3.1 base-score calculator (FIRST.org formula)
  osv.py                   # OSV.dev querybatch + per-vuln detail, cached + rate-limited
  concentration.py         # shared-component-across-suppliers detection
  risk_register.py         # aggregates everything into the JSON/CSV register
  cli.py                    # sbom / scan / diff-baseline commands
schemas/                   # vendored real CycloneDX 1.5 JSON schema (validated against in tests)
docs/sample-risk-register.json|.csv  # real output from a real scan (see below)
docs/demo-scan/                       # full SBOMs + concentration.json from that same real scan
.github/workflows/ci.yml              # lint + type-check + unit tests + real OSV.dev integration tests
.github/workflows/monitor.yml         # daily cron: scan real public repos, diff vs. baseline, fail on new critical
```

## The sample risk register is from a real run

`docs/sample-risk-register.json` / `.csv` and `docs/demo-scan/*.sbom.json` are the **actual, unedited output** of `scradar scan` run against three real repos on 2026-09-30:

| supplier | components | direct | transitive | vulns (C/H/M/L) | max severity | concentration flags | score |
|---|---|---|---|---|---|---|---|
| docwise-frontend | 265 | 20 | 245 | 0/0/0/0 | NONE | 71 | 100 |
| ledger-api | 814 | 46 | 768 | 0/63/24/6 | HIGH | 71 | 100 |
| docwise-backend | 54 | 54 | 0 | 1/2/3/4 | **CRITICAL** | 0 | 58 |

The CRITICAL finding is real: `docwise-backend`'s pinned `Django==5.0.14` matches [GHSA-frmv-pr5f-9mcr](https://github.com/advisories/GHSA-frmv-pr5f-9mcr) (SQL injection via the `_connector` keyword argument, CVSS 9.1), returned live by OSV.dev, not fabricated for this README. `ledger-api`'s 93 findings and `docwise-frontend`/`ledger-api`'s 71 shared npm packages (Vite/Vitest/Babel toolchain — real concentration risk, not a security bug in themselves) are likewise from the live scan. `docwise-backend` has 0 transitive dependencies only because `requirements.txt` doesn't record a dependency tree — see limitations below, this is not a claim that the backend has no transitive deps in reality.

## Real bugs found while building this

- **jsonschema's `Registry`/`Resource` API moved.** My first pass at `tests/test_cyclonedx_schema.py` called `jsonschema.validators.Registry()` — that's the pre-4.18 API. Against the installed `jsonschema==4.26.0` it raised `AttributeError: module jsonschema.validators has no attribute Registry` because `Registry`/`Resource` were split out into the separate `referencing` package. Fixed by importing from `referencing` directly and adding it as an explicit dependency instead of relying on it transitively.

- **`optionalDependencies` weren't walked when building the transitive graph, so packages only reachable through them silently got the wrong depth.** Running the tool against `docwise/frontend`'s real `package-lock.json`, I noticed `vite` declares `fsevents` only under `optionalDependencies` (it's the macOS-only native file watcher), never under `dependencies`. My BFS only walked `dependencies` (+ `devDependencies` at the root), so `fsevents` was never reached by any graph edge and silently fell back to the conservative default depth (2) instead of a real computed depth. In this specific case the fallback happened to match the true depth by coincidence (`vite` itself sits at depth 1), which is exactly why it didn't show up as an obvious wrong number — I only caught it by tracing `fsevents` by hand and checking the lockfile for how it was actually declared. Fixed by also walking `optionalDependencies`, and added a regression test (`test_optional_dependency_chain_gets_real_depth_not_fallback`) with a synthetic 3-deep optional-only chain where the fallback and the real depth actually disagree (2 vs. 3), so a future regression here fails loudly instead of coincidentally passing.

## Tests

```bash
pytest -v                      # 54 tests
pytest -v -m "not integration"  # 51 tests, no network
pytest -v -m integration        # 3 tests, real calls to api.osv.dev
ruff check src tests
mypy src
```

Covers: purl generation (incl. scoped npm packages), pinned-vs-unpinned Python manifest parsing, the npm lockfile v2/v3 resolution algorithm (direct/transitive/depth, hoisting, the optionalDependencies regression above, rejecting unsupported lockfile v1), CVSS v3.1 scoring against known textbook vectors, CycloneDX SBOM generation validated against the real vendored schema (including that the schema actually rejects malformed input, not just accepts everything), OSV response parsing (CVSS vector vs. `database_specific.severity` vs. no severity data at all), OSV client caching, concentration-risk detection and sorting, composite risk scoring, and the CLI end to end.

## CI

`.github/workflows/ci.yml`: ruff + mypy + unit tests + the real OSV.dev integration tests, on every push/PR.

`.github/workflows/monitor.yml`: daily cron job that checks out `sonofnos/docwise` and `sonofnos/ledger-api` fresh, runs a full scan, and fails the build (`scradar diff-baseline`) if any supplier's CRITICAL count has gone up since `docs/baseline-risk-register.json`. This is the "continuous vendor security-posture monitoring" piece — a real scheduled check against real repos, not a diagram of one.

## Limitations (stated plainly)

- **Two ecosystems only: npm and PyPI.** No Maven/Gradle (Java), no NuGet (.NET), no Go modules, no Rust/cargo. `ledger-api-spring`'s Java dependencies (`pom.xml`) are not scanned — only its `web/` npm frontend would be.
- **Python has no real transitive dependency tree.** `requirements.txt` and plain PEP 621 `pyproject.toml` only record direct pins with no resolved graph (unlike a `poetry.lock`/`uv.lock`, which this tool does not parse). Every Python component is reported as direct at depth 1 — Nth-party depth mapping is npm-only in this version. This is why `docwise-backend` shows 0 transitive dependencies above; it almost certainly has some in reality.
- **npm lockfile v1 (npm ≤ 6) is not supported**, only v2/v3 (npm ≥ 7). A v1 lockfile raises rather than silently producing wrong depths.
- **No exact version resolution when there's no lockfile.** A bare `package.json` gives semver ranges (`^1.2.0`), not installed versions, so OSV matching against those is unreliable; the tool prefers a lockfile when one exists.
- **OSV.dev only — no NVD cross-reference, no GitHub Advisory Database direct query, no commercial feed (Snyk/Mend/etc.).** OSV aggregates several of these already, but it is one source, not a consensus view, and its severity data is inconsistent in coverage (some records have a CVSS vector, some only a coarse GHSA severity bucket, some have neither — handled explicitly as `UNKNOWN` rather than guessed).
- **CVSS v3.1 base score only.** No temporal or environmental metrics, no CVSS v2 or v4 support.
- **The composite risk score is an illustrative triage heuristic, not a calibrated actuarial model.** It's a documented weighted sum (`risk_register.py`) meant to rank suppliers for attention, not a substitute for a real risk quantification methodology.
- **No live vendor security-rating platform integration** (BitSight/SecurityScorecard/etc.) — this tool covers what you can verify from the artifact itself (the dependency manifest), not an external attack-surface rating.
- **`querybatch` pagination (`next_page_token`) is implemented per OSV's documented API but was never exercised against a real paginated response** in testing — none of the real scans run so far produced enough results per chunk to trigger a second page, so that code path is implemented against the spec but not proven against live pagination.
