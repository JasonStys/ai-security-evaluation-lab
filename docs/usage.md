# Usage and troubleshooting

Author: Jason Stys.

Run the README command from the repository root. HTML opens directly in a browser without a server; JSON contains objective metrics; evidence.sqlite supports ordinary SQL queries.

Exit: 0 = all observed decisions match the reviewed oracle; 1 = mismatch or inconclusive; 2 = invalid input/I/O failure. Zero does not certify a secure model/application.

```sql
SELECT objective, verdict, COUNT(*) AS cases
FROM observation
GROUP BY objective, verdict
ORDER BY objective, verdict;
```

Block means rejected proposal; review means pending investigation without completion; inconclusive means absent/error/unsupported telemetry, never a blocked attack. Allow can mean structurally accepted but semantically ungraded text.

## Extend

Add synthetic cases in scripts/corpus.py: intended violation, trusted context, origin and observable oracle. Regenerate corpus/manifest, then tests. Do not relabel outcomes to make a badge green. Extend broker policy and tests together; no generic shell, arbitrary SQL or URL fetch.

This project trains no model. Authorized external response collectors can use [data-only snapshots](contracts.md). Repeated inference trials, verified version/settings provenance, semantic task grading and instrumented isolated side effects are separate work before claiming actual model results.

## Troubleshoot

- Existing path: choose a new output directory or template filename; old evidence is preserved.
- Missing file: use repo root or explicit --cases.
- Contract error: check [contracts](contracts.md), UTF-8, duplicate keys, exact fields/statuses, case digests and byte caps. Errors deliberately omit submitted values.
- Approval required: valid review state; do not bypass it.
- SQLite: Python must include STRICT table/JSON function support.
- Partial outputs: I/O errors may leave already-created files. Inspect privately and use another directory; the app never silently deletes evidence.
- Windows temp restrictions: create out/temp and set shell TEMP/TMP to that exact directory before venv/testing.

Help: [Jason Stys](https://github.com/JasonStys). Do not publish private inputs/credentials with support requests.
