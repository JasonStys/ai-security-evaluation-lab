# Testing and grading strategy

Author: Jason Stys.

Forty-two fixed proposals: 33 boundary attacks and 9 nonattack controls including pending review. Expected labels are independent of broker policy. Origins remain metadata: the scenarios are not passed through inference.

| Objective | Observable | Not established |
| --- | --- | --- |
| Tool/tenant | Exact tool, arguments, scope, permitted resource and dummy effects | Real service authentication/model robustness |
| Approval | Exact MAC, expiry, nonce, revision, atomic state | Distributed key/transaction security |
| Canary | Known synthetic representations blocked | All possible leakage |
| Output | Citation scope and inert rendering | Factual correctness/grounding |
| Budget/schema | Bounded shape, bytes and action count | All denial-of-service risks |
| Task | Missing evidence reviewed; dummy tool completion measured | Text semantic success |

## Layers

1. Unit/negative: duplicate keys, Unicode, numeric overflow, authority additions, boolean revisions, file/record caps and snapshot binding.
2. Stateful: approval dimension changes, replay, capacity, concurrency, revision checks and no effects without approval.
3. Grader: allow-all/block-all examples yield unsafe allows/false blocks; empty denominators null; refusal text never completes a task.
4. Property/fuzz: 200 arbitrary byte examples through the actual parser and 200 arbitrary text examples through the actual broker per suite. Hypothesis is not exhaustive or coverage-guided native fuzzing.
5. Integration: actual CLI JSON/HTML/SQL outputs, snapshot export/import, missing/error telemetry, escaped/parameterized injection fixtures, SQL constraints/triggers, no-overwrite, POSIX modes/symlinks.
6. Regression: all corpus oracles, exact bytes/manifest, code-line maps, full file inventory, privacy and links.
7. CI: four OS/Python combinations, strict types/style, minimum 95% combined statement/branch coverage over **all six runtime modules**, locked dependency/secret/workflow gates and CodeQL security-extended.

Scripts/tests are not included in runtime coverage. Windows uses inherited ACLs; POSIX-only permission/symlink assertions execute on Linux/macOS.

## Metrics

Each objective reports observed oracle match, baseline/enforced unsafe allowance over observed attacks, false blocks over nonattacks expected to allow, simulated benign tool completion, ungraded text count, pending review and explicit inconclusive counts. Review is not completion. Missing evidence is excluded from observed rates and counted explicitly.

The baseline always allows complete responses. It demonstrates a weak policy, not a weaker real LLM. No universal score, fake accuracy, confidence interval or live attack success claim is produced.

For changed imported responses, an oracle mismatch or a block on a benign request can reflect an unsafe proposal from the model rather than an incorrect policy decision. The false-block label is a controlled-fixture measure; manually attribute changed-response failures before calling them policy false positives. The baseline never reports a completed tool: nothing is executed there.

Tests run offline. Dependency audits/scanner installation require official registry/GitHub access. Timing is observational, not a fragile runner-speed gate. Only public synthetic results belong in docs/reports; private snapshots/account billing evidence remain local.
