# AI Security Evaluation Lab

## Native Windows workbench

The complete portable graphical app now accepts your supported authorized inputs and project parameters, runs the actual engines, preserves original findings, searches literal evidence, exports exact files and restores durable SQLite history. Prepared fictional cases are inside this same app. [Usage, privacy, workflow meanings and native validation](docs/native-workbench.md). No live model, host collection, enforcement or background upload is available. Created by Jason Stys; no release/installation is implied by a local candidate build.

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

## Compare response snapshots

```console
python -m aisec.cli snapshot-template --out out/baseline.jsonl
python -m aisec.cli compare --baseline out/baseline.jsonl --candidate out/candidate.jsonl --out out/paired-review
```

Start with a private copy of the template for an explicitly labeled candidate snapshot. Both sides must bind every submitted record to the exact same reviewed case digest. The current broker evaluates each side independently with fresh dummy approval state. `comparison.html` and JSON show case-level decision changes, unsafe-allow increases, benign availability/tool-completion losses, oracle recovery/regression and observation loss. Objective denominators count only cases observed on **both** sides; missing/error/timeout/unsupported records remain inconclusive and enter the review queue.

Original per-objective metrics for each full snapshot remain alongside paired counts. No aggregate model ranking is inferred. Labels are asserted metadata, not authenticated provider identity; raw responses/messages and approval keys never appear in reports. This compares authored/imported data only and makes no model, paid API or real downstream tool call. Output must be new and unlinked; context drift cannot be accepted by changing a candidate's case digest.

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

The original accepted-source baseline recorded 51 tests and 42 matching synthetic policy oracles. The November 9 paired-review update locally passes 54 tests at 100% combined statement/branch coverage across all runtime modules; hosted acceptance remains separate. [Paired-review validation](docs/reports/paired-review-2026-11-09.md). [Measured evidence and scope](docs/validation.md) preserve exact run/source identities, outcomes and limits. Check [current Actions](https://github.com/JasonStys/ai-security-evaluation-lab/actions) for the current commit.

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
| [aisec/compare.py](aisec/compare.py) | Jason Stys: case-digest-bound paired response snapshot review with explicit benign and telemetry regressions. |
| [aisec/contracts.py](aisec/contracts.py) | Jason Stys: bounded strict JSON contracts for synthetic cases and untrusted response snapshots. |
| [aisec/desktop.py](aisec/desktop.py) | Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys. |
| [aisec/desktop\_io.py](aisec/desktop_io.py) | Bounded regular descriptor reads and strict finite JSON for owner-local desktop state. Jason Stys. |
| [aisec/desktop\_project.py](aisec/desktop_project.py) | Actual data-only broker evaluation, response-template and paired-review graphical workflows. Jason Stys. |
| [aisec/desktop\_state.py](aisec/desktop_state.py) | Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys. |
| [aisec/evaluate.py](aisec/evaluate.py) | Jason Stys: paired response-replay evaluation with per-objective rates and honest inconclusive outcomes. |
| [aisec/evidence.py](aisec/evidence.py) | Jason Stys: private exclusive evidence outputs, inert escaped HTML and parameterized append-only SQL. |
| [data/cases.jsonl](data/cases.jsonl) | Authored synthetic contexts, untrusted messages, proposed responses and policy oracles. |
| [data/manifest.json](data/manifest.json) | Exact corpus bytes, SHA256 and authorship metadata. |
| [docs/architecture.md](docs/architecture.md) | Architecture and technology decisions. |
| [docs/contracts.md](docs/contracts.md) | Case, response and snapshot contracts. |
| [docs/contributing.md](docs/contributing.md) | Coding and contribution rules. |
| [docs/handbook.md](docs/handbook.md) | AI Security Evaluation Lab handbook. |
| [docs/licenses/tcl-9.0.4.txt](docs/licenses/tcl-9.0.4.txt) | Verbatim Tcl9.0.4 notice read from the actual verified Windows runtime zipfs. |
| [docs/licenses/tk-9.0.4.txt](docs/licenses/tk-9.0.4.txt) | Verbatim Tk9.0.4 notice read from the actual verified Windows runtime zipfs. |
| [docs/native-workbench.md](docs/native-workbench.md) | Native offline workbench. |
| [docs/performance.md](docs/performance.md) | Complexity and performance methodology. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded offline evaluation timing and memory, not model latency. |
| [docs/reports/ci.json](docs/reports/ci.json) | Immutable accepted-source CI snapshot, not a future guarantee. |
| [docs/reports/documentation-refresh-2026-11-09.md](docs/reports/documentation-refresh-2026-11-09.md) | Documentation refresh — 2026-11-09. |
| [docs/reports/evaluation.json](docs/reports/evaluation.json) | Actual baseline versus enforced-policy synthetic outcomes with denominators. |
| [docs/reports/native-workbench-2026-11-10.md](docs/reports/native-workbench-2026-11-10.md) | Native AI security workbench validation. |
| [docs/reports/paired-review-2026-11-09.md](docs/reports/paired-review-2026-11-09.md) | Paired response snapshot validation — November 9, 2026. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/project-guide.docx](docs/reports/project-guide.docx) | Reviewed source-bound Word guide with dated validation observations and practical limits. |
| [docs/reports/publications.json](docs/reports/publications.json) | Exact publication hashes, reviewed page identities and source/evidence baselines. |
| [docs/research.md](docs/research.md) | Primary-source research and control mapping. |
| [docs/security.md](docs/security.md) | Threat model and security limits. |
| [docs/testing.md](docs/testing.md) | Testing and grading strategy. |
| [docs/usage.md](docs/usage.md) | Usage and troubleshooting. |
| [docs/validation.md](docs/validation.md) | Validation evidence. |
| [examples/desktop/baseline.jsonl](examples/desktop/baseline.jsonl) | Authored same-case baseline responses; fictional identity, not outputs from a live model. |
| [examples/desktop/candidate.jsonl](examples/desktop/candidate.jsonl) | Authored same-case unsafe-allow and benign-completion regression responses, data only. |
| [examples/desktop/partial.jsonl](examples/desktop/partial.jsonl) | Authored missing/timeout observations that lower paired denominators and remain inconclusive. |
| [pyproject.toml](pyproject.toml) | Jason Stys: strict all-runtime-module checks with branch coverage; no runtime dependencies. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: exact development-only tools; Python runtime uses only the standard library. |
| [requirements-dev.lock](requirements-dev.lock) | Universal full hash-locked Python development graph. |
| [requirements-native.lock](requirements-native.lock) | Exact hash-locked Windows portable build graph; no runtime setup/download on user launch. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: measure reproducible offline boundary-evaluation latency and Python allocation peaks, not model throughput. |
| [scripts/build\_native.py](scripts/build_native.py) | Build the complete real offline workbench as one Windows portable executable. Jason Stys. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and SQL/workflow declaration line indexes. |
| [scripts/corpus.py](scripts/corpus.py) | Jason Stys: regenerate the authored synthetic replay corpus and exact byte manifest; never collect external data. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native\_acceptance.py](scripts/native_acceptance.py) | Real frozen widget/core/history/export and honest failure-evidence acceptance. Jason Stys. |
| [scripts/native\_entry.py](scripts/native_entry.py) | Launch the actual bundled offline project workbench; no setup shell commands. Jason Stys. |
| [scripts/publication\_text.py](scripts/publication_text.py) | Jason Stys: inspect only named reviewed Office editions without hiding their XML. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/test\_native\_app.py](scripts/test_native_app.py) | Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: tracked-source privacy, dependency/pin/cache policy, exact links and synthetic corpus provenance gates. |
| [sql/schema.sql](sql/schema.sql) | Jason Stys: metadata-only append-only evaluation ledger, constrained outcomes and objective lookup. |
| [tests/test\_boundary.py](tests/test_boundary.py) | Jason Stys: real broker state, exact approval integrity, replay, concurrency and output-shape regressions. |
| [tests/test\_compare.py](tests/test_compare.py) | Jason Stys: same-case paired snapshot policy/availability/telemetry review oracles. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: strict ingestion, byte/record bounds, duplicate-key rejection and snapshot provenance tests. |
| [tests/test\_desktop\_gui.py](tests/test_desktop_gui.py) | Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys. |
| [tests/test\_desktop\_project.py](tests/test_desktop_project.py) | Independent metadata/privacy, exact paired-denominator and real custom-case adapter tests. Jason Stys. |
| [tests/test\_desktop\_state.py](tests/test_desktop_state.py) | Independent offline desktop ownership, byte-bound, SQLite and non-overwrite regressions. Jason Stys. |
| [tests/test\_evaluation.py](tests/test_evaluation.py) | Jason Stys: paired grading, missing telemetry, imported-response approval substitution and metric denominator tests. |
| [tests/test\_evidence\_cli.py](tests/test_evidence_cli.py) | Jason Stys: end-to-end CLI, no-overwrite privacy, inert HTML, SQLite constraints and immutable ledger tests. |
| [tests/test\_publication\_text.py](tests/test_publication_text.py) | Jason Stys: actual Office ZIP fixtures retain text scanning and reject unknown content. |
| [tests/test\_reader\_races.py](tests/test_reader_races.py) | Actual opened-device and POSIX regular-to-FIFO replacement regressions for bounded readers. Jason Stys. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |

<!-- END FILE GUIDE -->

## Documentation editions

Start with the [organized handbook](docs/handbook.md) for current usage, design, security and test guidance. Reviewed downloadable editions: [project-guide.docx](docs/reports/project-guide.docx).

[Publication identities and source scope](docs/reports/publications.json) · [Documentation validation record](docs/reports/documentation-refresh-2026-11-09.md). Historical results retain their own tested revision and date.
