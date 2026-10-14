# AI Security Evaluation Lab

Created by **Jason Stys**. A reproducible, offline lab testing security boundaries around AI agents: narrow tool capabilities, tenant isolation, exact single-use approvals, response contracts, synthetic-canary disclosure and evidence integrity.

This is a defensive portfolio project, not a jailbreak service or model-security certification. Supplied responses are authored fixtures, not outputs from a live LLM. The permissive baseline never executes a tool. The enforced broker validates proposals and updates only in-memory dummy counters.

## Quick start

Use Python 3.12+ from the repository root. Runtime dependencies are empty: no account, API key, Docker, GPU, service or installation.

```console
python -m aisec.cli evaluate --out out/first-evaluation
```

Open `out/first-evaluation/evaluation.html` in a browser. The same directory contains JSON and `evidence.sqlite`. Choose a **new** output directory each time; existing outputs are never overwritten. POSIX modes are restrictive; Windows inherits directory ACLs. Files are not encrypted.

## Features

- **Authority outside prompts:** model proposals cannot change trusted tenant, user, scopes or session. Retrieved documents and tool results remain untrusted scenario data.
- **Complete mediation:** only `read_document` and `draft_note` exist. Foreign resources, stale revisions, extra arguments, unsupported tools and multiple-action responses are rejected.
- **Exact approvals:** ephemeral HMAC approvals bind every action argument and caller/context dimension. Atomic consumption and revision checks prevent replay and competing dummy writes in one process.
- **Output controls:** bounded strict JSON, duplicate-key/numeric-overflow rejection, known synthetic-canary checks, citation scope and inert HTML.
- **Honest grading:** 42 reviewed synthetic cases (33 attacks, 9 other/benign controls), paired policy outcomes, objective-specific numerators/denominators, explicit review and inconclusive outcomes.
- **Data-only adapters:** case-digest-bound JSONL snapshot imports. No plugin execution, arbitrary code, network calls or paid provider requests.
- **Evidence:** metadata-only JSON, escaped script-free HTML and parameterized append-only SQL. Raw messages, responses, tokens and approval keys are excluded from reports.
- **DevOps:** Linux/Python 3.12 and 3.14, Windows and macOS tests, hash-locked tooling, dependency audit, Gitleaks, actionlint and CodeQL security-extended. No Actions artifacts or caches.

Accepted text is **not** evidence of factual correctness or task success. Only instrumented dummy tool execution is counted as completed. This lab does not test inference, multimodal attacks, training-data poisoning or real downstream services.

## Documentation

- [Usage and troubleshooting](docs/usage.md)
- [Architecture and decisions](docs/architecture.md)
- [Threat model and limits](docs/security.md)
- [Data contracts](docs/contracts.md)
- [Testing and grading strategy](docs/testing.md)
- [Complexity and performance](docs/performance.md)
- [Primary-source research](docs/research.md)
- [Coding and contribution rules](docs/contributing.md)
- [Actual validation evidence](docs/validation.md)

## Development

Activate your virtual environment before running these commands, or explicitly use its Python executable.

```console
python -m venv .venv
python -m pip install --require-hashes -r requirements-dev.lock
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest --cov=aisec --cov-report=term-missing:skip-covered
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/validate_repo.py
python scripts/benchmark.py
```

Regenerate source-line headers with `python scripts/code_map.py`, stage reviewed files, then regenerate `python scripts/file_guide.py`. CI checks both for drift.

## Author and license

Jason Stys · [GitHub / contact](https://github.com/JasonStys) · [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/). MIT-licensed authored code and synthetic fixtures. External research retains its own licensing. No affiliation, certification, clearance or production approval is implied.

## Validated evidence

51 tests; 100% combined statement/branch coverage across all six runtime modules; 42 synthetic policy oracles matched. All six accepted-source CI jobs passed. [Measured evidence and scope](docs/validation.md) preserve exact run/source identities, outcomes and limits. Check [current Actions](https://github.com/JasonStys/ai-security-evaluation-lab/actions) for the current commit.

## Complete file inventory

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text checkouts across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: cross-platform tests, bounded replay evaluation, performance and locked security gates; no artifacts/caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: security-extended Python analysis; disable all CodeQL trap/dependency cache and database uploads. |
| [.gitignore](.gitignore) | Exclude private diagnostics, builds, environments and generated fuzz artifacts. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | AI Security Evaluation Lab. |
| [aisec/\_\_init\_\_.py](aisec/__init__.py) | Jason Stys: offline security evaluation package; importing it performs no I/O. |
| [aisec/boundary.py](aisec/boundary.py) | Jason Stys: fail-closed in-memory tool broker, exact single-use approvals and bounded output validation. |
| [aisec/cli.py](aisec/cli.py) | Jason Stys: offline evaluate and snapshot-template commands; no network, API key, service or arbitrary code execution. |
| [aisec/contracts.py](aisec/contracts.py) | Jason Stys: bounded strict JSON contracts for synthetic cases and untrusted response snapshots. |
| [aisec/evaluate.py](aisec/evaluate.py) | Jason Stys: paired response-replay evaluation with per-objective rates and honest inconclusive outcomes. |
| [aisec/evidence.py](aisec/evidence.py) | Jason Stys: private exclusive evidence outputs, inert escaped HTML and parameterized append-only SQL. |
| [data/cases.jsonl](data/cases.jsonl) | Authored synthetic contexts, untrusted messages, proposed responses and policy oracles. |
| [data/manifest.json](data/manifest.json) | Exact corpus bytes, SHA256 and authorship metadata. |
| [docs/architecture.md](docs/architecture.md) | Architecture and technology decisions. |
| [docs/contracts.md](docs/contracts.md) | Case, response and snapshot contracts. |
| [docs/contributing.md](docs/contributing.md) | Coding and contribution rules. |
| [docs/performance.md](docs/performance.md) | Complexity and performance methodology. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded offline evaluation timing and memory, not model latency. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source CI snapshot, not a future guarantee. |
| [docs/reports/evaluation.json](docs/reports/evaluation.json) | Actual baseline versus enforced-policy synthetic outcomes with denominators. |
| [docs/research.md](docs/research.md) | Primary-source research and control mapping. |
| [docs/security.md](docs/security.md) | Threat model and security limits. |
| [docs/testing.md](docs/testing.md) | Testing and grading strategy. |
| [docs/usage.md](docs/usage.md) | Usage and troubleshooting. |
| [docs/validation.md](docs/validation.md) | Validation evidence. |
| [pyproject.toml](pyproject.toml) | Jason Stys: strict all-runtime-module checks with branch coverage; no runtime dependencies. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: exact development-only tools; Python runtime uses only the standard library. |
| [requirements-dev.lock](requirements-dev.lock) | Universal full hash-locked Python development graph. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: measure reproducible offline boundary-evaluation latency and Python allocation peaks, not model throughput. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and SQL/workflow declaration line indexes. |
| [scripts/corpus.py](scripts/corpus.py) | Jason Stys: regenerate the authored synthetic replay corpus and exact byte manifest; never collect external data. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: tracked-source privacy, dependency/pin/cache policy, exact links and synthetic corpus provenance gates. |
| [sql/schema.sql](sql/schema.sql) | Jason Stys: metadata-only append-only evaluation ledger, constrained outcomes and objective lookup. |
| [tests/test\_boundary.py](tests/test_boundary.py) | Jason Stys: real broker state, exact approval integrity, replay, concurrency and output-shape regressions. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: strict ingestion, byte/record bounds, duplicate-key rejection and snapshot provenance tests. |
| [tests/test\_evaluation.py](tests/test_evaluation.py) | Jason Stys: paired grading, missing telemetry, imported-response approval substitution and metric denominator tests. |
| [tests/test\_evidence\_cli.py](tests/test_evidence_cli.py) | Jason Stys: end-to-end CLI, no-overwrite privacy, inert HTML, SQLite constraints and immutable ledger tests. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |

<!-- END FILE GUIDE -->
