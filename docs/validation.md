# Validation evidence

Author: Jason Stys. Validated 2026-10-14. Accepted implementation source: [8b911602d00fa9a83f5f49634fbf79bfd1d8dca5](https://github.com/JasonStys/ai-security-evaluation-lab/commit/8b911602d00fa9a83f5f49634fbf79bfd1d8dca5).

- Windows/Python 3.14.6: 51 tests passed, 100% combined runtime statement/branch coverage (367 statements / 106 branches, six modules).
- Two actual parser/broker Hypothesis tests: 200 examples each per suite, not exhaustive proof.
- Forty-two synthetic cases, 33 attacks and 9 other/benign controls; all policy oracles matched.
- Ruff lint/format and strict mypy passed.
- Actual CLI JSON/HTML/SQLite output and synthetic snapshot import passed. No real model, provider, private account, paid API, Docker or arbitrary tool ran.

Tests caught an unclosed SQLite connection: explicit closing now releases it without warnings. The approval-substitution regression verifies imported changed text cannot inherit the original reviewed approval. Exponent overflow is rejected along with nonfinite constants.

[Performance methodology](performance.md) describes actual observations. Only measured public synthetic reports will be preserved in docs/reports; account storage/billing evidence stays local.

## Completed hosted validation

- [Validate run 38593927252](https://github.com/JasonStys/ai-security-evaluation-lab/actions/runs/38593927252): all five jobs passed. Linux/Python 3.12 and 3.14, Windows/Python 3.14, macOS/Python 3.14 and locked dependency/secret/workflow checks.
- [CodeQL run 38593927207](https://github.com/JasonStys/ai-security-evaluation-lab/actions/runs/38593927207): Python security-extended analysis passed; zero open alerts when inspected.
- Hosted Linux/Python 3.14 test log confirmed 51 passed and 100% combined runtime coverage.
- Completed workflows stored zero artifacts and zero Actions caches. CodeQL trap/dependency caching and database uploads are explicitly disabled; no artifact/cache actions are used.

## Preserved public synthetic evidence

- [Immutable CI snapshot](reports/ci.json): accepted source SHA, run/job identities, timestamps, actual conclusions and scoped local/browser checks.
- [Actual paired evaluation](reports/evaluation.json): all 42 policy oracles match; 33 attack proposals have no enforced unsafe allows. This is finite synthetic response replay, not observed model robustness.
- [Hosted measured benchmark](reports/benchmark.json): twenty samples, Linux/Python 3.14.6, median about 1.144 ms for 42-case evaluation, peak Python allocation 41,969 bytes. Extracted from the successful Linux job; excludes inference/network/disk and is not a speed guarantee.

Local browser smoke check confirmed all 42 report rows, seven scoped column headers, zero scripts, zero external assets and the restrictive meta CSP. This is a local content/structure check, not a comprehensive accessibility or cross-browser audit. The temporary preview server was stopped afterward.

No hosted failure was hidden or deleted; the initial implementation workflows passed. Account billing/storage counters are intentionally not published. Coverage excludes scripts/tests and is not a security proof. Inspect CI for the exact current commit. The immutable snapshot describes the accepted implementation, not success promised for the subsequent documentation commit or future changes.
