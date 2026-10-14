# Complexity and performance methodology

Author: Jason Stys. N = cases, B = total input bytes, K = objectives, R = report size.

- Bounded JSONL reading/hash/parse: O(B), capped at 2 MiB / 1,000 records.
- Exact schemas/capability checks: O(1) under fixed limits. Canary/text scans: O(text bytes) with four fixed representations.
- Approval digest/MAC: O(action bytes). Nonce lookup O(1) average; ledger caps at 1,000 spends and never evicts replay protection.
- Evaluation: O(B + N). Metrics group once, then sort objectives: O(N + K log K), avoiding repeated full scans.
- JSON/HTML generation: O(R), metadata only; table construction uses joins.
- SQLite: typical O(N log N) B-tree maintenance, batched parameters/one transaction. Objective/verdict index supports grouping/filtering.

`python scripts/benchmark.py` warms up once, times twenty full paired evaluations with perf_counter, verifies correctness every sample, then measures Python peak allocations separately with tracemalloc. It records all samples, median/max, environment and corpus SHA256 in out/benchmark.json.

Excludes model inference, network, report serialization/disk and SQL insertion. Allocation peak is not process RSS. Observations are not portable latency guarantees. CI has bounded timeouts but no shared-runner speed gate.
