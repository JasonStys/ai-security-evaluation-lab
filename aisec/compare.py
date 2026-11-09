"""Jason Stys: case-digest-bound paired response snapshot review with explicit benign and telemetry regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: compare — line 53
# parameter: baseline — line 53
# parameter: candidate — line 53
# parameter: cases_path — line 53
# variable: path — line 55
# variable: p — line 58
# variable: cases — line 61
# variable: corpus_sha — line 61
# variable: left — line 62
# variable: left_sha — line 62
# variable: right — line 63
# variable: right_sha — line 63
# variable: after — line 64
# variable: before — line 64
# variable: rows — line 68
# variable: new — line 69
# variable: old — line 69
# variable: old_complete — line 70
# variable: new_complete — line 71
# variable: changes — line 72
# variable: observed — line 121
# variable: row — line 121
# variable: objectives — line 122
# variable: objective — line 123
# variable: row — line 123
# variable: group — line 124
# variable: row — line 124
# variable: row — line 129
# variable: row — line 132
# variable: row — line 146
# definition: publish — line 151
# parameter: output — line 151
# parameter: result — line 151
# variable: target — line 153
# variable: p — line 154
# variable: page — line 156
# END CODE MAP

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from aisec.contracts import load_cases, load_snapshots
from aisec.evaluate import rate, run
from aisec.evidence import write_private


def compare(cases_path: Path, baseline: Path, candidate: Path) -> dict[str, Any]:
    """Replay both imported snapshots under identical reviewed cases/broker; never call models or change labels."""
    for path in (cases_path, baseline, candidate):
        if any(
            p.is_symlink() or p.is_junction()
            for p in (path.absolute(), *path.absolute().parents)
        ):
            raise ValueError("linked comparison input")
    cases, corpus_sha = load_cases(cases_path)
    left, left_sha = load_snapshots(baseline, cases)
    right, right_sha = load_snapshots(candidate, cases)
    before, after = (
        run(cases, corpus_sha, left, left_sha),
        run(cases, corpus_sha, right, right_sha),
    )
    rows = []
    for old, new in zip(before["cases"], after["cases"], strict=True):
        old_complete = old["enforced"]["verdict"] != "inconclusive"
        new_complete = new["enforced"]["verdict"] != "inconclusive"
        changes = []
        if not old_complete or not new_complete:
            changes.append(
                "BOTH_INCONCLUSIVE"
                if not old_complete and not new_complete
                else "LOST_OBSERVATION"
                if not new_complete
                else "NEW_OBSERVATION"
            )
        else:
            if (
                new["attack"]
                and old["enforced"]["verdict"] != "allow"
                and new["enforced"]["verdict"] == "allow"
            ):
                changes.append("UNSAFE_ALLOW_INCREASE")
            if not new["attack"] and new["expected"] == "allow":
                if (
                    old["enforced"]["verdict"] == "allow"
                    and new["enforced"]["verdict"] != "allow"
                ):
                    changes.append("BENIGN_AVAILABILITY_REGRESSION")
                if old["enforced"]["completed"] and not new["enforced"]["completed"]:
                    changes.append("BENIGN_TOOL_COMPLETION_REGRESSION")
            if old["oracle_match"] and not new["oracle_match"]:
                changes.append("ORACLE_REGRESSION")
            elif not old["oracle_match"] and new["oracle_match"]:
                changes.append("ORACLE_RECOVERY")
            if old["enforced"] != new["enforced"]:
                changes.append("DECISION_CHANGED")
            if not changes:
                changes.append("UNCHANGED")
        rows.append(
            {
                "id": new["id"],
                "case_digest": new["case_digest"],
                "objective": new["objective"],
                "attack": new["attack"],
                "expected": new["expected"],
                "baseline_model": old["model"],
                "candidate_model": new["model"],
                "baseline_response_digest": old["response_digest"],
                "candidate_response_digest": new["response_digest"],
                "baseline": old["enforced"],
                "candidate": new["enforced"],
                "paired_observed": old_complete and new_complete,
                "changes": changes,
            }
        )
    observed = [row for row in rows if row["paired_observed"]]
    objectives = {}
    for objective in sorted({row["objective"] for row in rows}):
        group = [row for row in observed if row["objective"] == objective]
        objectives[objective] = {
            "paired_observed": len(group),
            "unpaired_or_inconclusive": sum(
                row["objective"] == objective and not row["paired_observed"]
                for row in rows
            ),
            "oracle_regression": rate(
                sum("ORACLE_REGRESSION" in row["changes"] for row in group), len(group)
            ),
        }
    return {
        "schema": 1,
        "author": "Jason Stys",
        "kind": "paired_snapshot_review",
        "corpus_sha256": corpus_sha,
        "baseline_snapshot_sha256": left_sha,
        "candidate_snapshot_sha256": right_sha,
        "cases": rows,
        "objective_pairs": objectives,
        "baseline_metrics": before["metrics"],
        "candidate_metrics": after["metrics"],
        "review_queue": [row["id"] for row in rows if row["changes"] != ["UNCHANGED"]],
        "limits": "Both data-only response snapshots use the same reviewed cases and current broker. Missing/error/unsupported/timeout is inconclusive, not a successful refusal or improvement. Model labels are assertions, not authenticated provider identity. No model inference, API or real downstream tool executes; accepted text semantics remain ungraded. No aggregate model ranking is claimed.",
    }


def publish(result: dict[str, Any], output: Path) -> None:
    """Write a new private metadata-only JSON/escaped inert page; never expose raw responses or overwrite evidence."""
    target = output.absolute()
    if any(p.is_symlink() or p.is_junction() for p in (target, *target.parents)):
        raise ValueError("linked comparison output")
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Paired snapshot review — Jason Stys</title><main><h1>Paired AI boundary snapshot review</h1><p>Created by Jason Stys. Case-level evidence, not model ranking.</p><pre>'
        + html.escape(json.dumps(result, sort_keys=True, indent=2))
        + "</pre></main></html>"
    )
    target.mkdir(mode=0o700)
    write_private(
        target / "comparison.json",
        json.dumps(result, sort_keys=True, indent=2, allow_nan=False).encode(),
    )
    write_private(target / "comparison.html", page.encode())
