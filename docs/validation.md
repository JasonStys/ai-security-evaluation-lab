# Validation evidence

Author: Jason Stys. Initial local validation 2026-10-14. Hosted evidence will be recorded only after successful runs.

- Windows/Python 3.14.6: 51 tests passed, 100% combined runtime statement/branch coverage (367 statements / 106 branches, six modules).
- Two actual parser/broker Hypothesis tests: 200 examples each per suite, not exhaustive proof.
- Forty-two synthetic cases, 33 attacks and 9 other/benign controls; all policy oracles matched.
- Ruff lint/format and strict mypy passed.
- Actual CLI JSON/HTML/SQLite output and synthetic snapshot import passed. No real model, provider, private account, paid API, Docker or arbitrary tool ran.

Tests caught an unclosed SQLite connection: explicit closing now releases it without warnings. The approval-substitution regression verifies imported changed text cannot inherit the original reviewed approval. Exponent overflow is rejected along with nonfinite constants.

[Performance methodology](performance.md) describes actual observations. Only measured public synthetic reports will be preserved in docs/reports; account storage/billing evidence stays local.

Coverage excludes scripts/tests and is not a security proof. Inspect CI for the exact current commit. An accepted-source snapshot records immutable historical evidence, not success promised for future changes.
