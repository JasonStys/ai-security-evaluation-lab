# Native AI security workbench validation

Created by Jason Stys. Windows x64 portable candidate version 1.1.0; observations on 10–11 November 2026. [Native usage and private-data boundaries](../native-workbench.md).

## Changes and rationale

The original data-only broker/evaluation and paired-review engines now have actual graphical case/snapshot controls, literal evidence search/full record inspection, exact exports and durable owner-local SQLite history. Optional prepared cases populate those same controls. Users can select their own supported corpus: removing the benign-read case's trusted read scope produces an actual block while retaining its now-mismatching allow oracle. No model output can change trusted scope/context; no model, provider, plugin or real downstream tool runs.

Original objective-specific numerators/denominators, benign availability/completion losses, unsafe-allow increases and inconclusive states remain separately visible. Same-case digests bind paired snapshots. The missing/timeout example reduces the paired denominator from 42 to 40 and retains two review items; it never calls missing evidence a successful block or model improvement.

The explicitly selected response-template operation deliberately retains raw selected response objects in `snapshot-template.jsonl`; its warning and metadata-only preview distinguish it from an evaluation. Ordinary evaluation/comparison evidence still omits messages/responses and approval keys. The template is sensitive plaintext local data and must be reviewed before sharing.

## Actual local checks

| Check | Observed result |
| --- | --- |
| Complete source suite |106 passed, one explicit Windows skip for the genuine POSIX no-writer FIFO swap; combined statement/branch coverage 95.91%, above the unchanged 95% floor. Real opened Windows NUL is rejected and closed. |
| Independent domain oracles | All 42 original broker oracles, separately authored unsafe-allow/benign-completion losses, exact 40/42 paired telemetry, custom external scope, context-digest tampering, sensitive template/ordinary-report privacy and original CLI/SQLite tests passed. |
| Types and dependencies | Ruff and strict Windows/Linux mypy passed. Pip consistency and complete hash-locked dev/native advisory audit passed with no known vulnerabilities; a prior default-cache/response failure was not treated as a pass. A fresh repo-owned audit cache was used without changing private/global cache permissions. |
| Actual first functional EXE | Verified Python 3.14.10/Tcl/Tk 9.0.4 frozen app drove five real workflows and retained five exact bundles through a second actual process. External selected corpus, explicit permission, row/detail filtering, exact export, bad-context retention,980×700 lifecycle/status layout and normal owned PID exit passed. |

Two early consumer attempts failed closed on authored integration errors: a receipt filename mismatch, then looking for the DLL hash in raw resources instead of the already verified flattened identity. The in-app receipt now matches the unchanged strict parent contract and actual runtime hash check. No retry/deadline, runtime-identity check, model boundary or correctness oracle was weakened. Those failed attempts are not native acceptance results.

The original informational benchmark measured 42 cases over 20 samples: median 1.0664 ms, maximum 1.5159 ms and 44,075 peak Python allocated bytes on this Windows observation. It excludes model/network/disk timing and does not predict real inference or production performance.

## CI and delivery boundary

All original four OS/Python quality/security and exact corpus-provenance gates remain. A new exact Python 3.14.10 Windows job audits the native graph, builds the full EXE and exercises the actual two-process consumer; no packages/profiles, Actions artifacts or caches are uploaded. Existing CodeQL security-extended scope is retained. Local evidence above is a dirty-source candidate observation; fresh clean committed package identity and hosted results are separate release prerequisites.

Windows x64 portable only; no installer, Authenticode signature, cross-platform binary, production agent system, semantic-answer grading or independent model-security certification. Plaintext owner-local history is not encryption or multiuser authentication. No installed profile, real account, live model/tool, cloud service or Docker was accessed. Historical Office publications remain source/date-bound observations.
