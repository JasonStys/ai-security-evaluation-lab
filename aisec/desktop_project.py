"""Actual data-only broker evaluation, response-template and paired-review graphical workflows. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 88
# variable: PRODUCT — line 89
# variable: PROFILE — line 89
# variable: TITLE — line 90
# variable: VERSION — line 90
# variable: COLUMNS — line 91
# variable: RESOURCES — line 97
# variable: MODES — line 108
# variable: REVIEW_MODE — line 113
# variable: CHOICES — line 114
# variable: FIELDS — line 115
# variable: ACTIVE_FIELDS — line 129
# variable: SCENARIOS — line 134
# variable: HELP — line 141
# definition: scenario — line 144
# parameter: name — line 144
# variable: index — line 148
# definition: text_bundle — line 167
# parameter: title — line 167
# parameter: value — line 167
# variable: raw — line 169
# variable: page — line 170
# definition: analyze — line 182
# parameter: parameters — line 183
# parameter: stage — line 183
# parameter: state — line 183
# variable: cases_path — line 186
# variable: mode — line 186
# variable: result — line 188
# variable: output — line 191
# variable: observed — line 193
# variable: row — line 193
# variable: summary — line 194
# variable: path — line 200
# variable: cases — line 205
# variable: corpus_sha — line 205
# variable: rows — line 207
# variable: case — line 215
# variable: metadata — line 217
# variable: key — line 221
# variable: value — line 221
# variable: row — line 222
# variable: files — line 226
# variable: row — line 228
# variable: snapshot_sha — line 235
# variable: snapshots — line 235
# variable: result — line 240
# variable: output — line 241
# variable: inconclusive — line 243
# variable: row — line 244
# variable: mismatches — line 246
# variable: row — line 246
# variable: summary — line 247
# variable: path — line 251
# definition: views — line 255
# parameter: files — line 255
# variable: report — line 258
# variable: key — line 262
# variable: row — line 262
# variable: row — line 266
# variable: report — line 271
# variable: queued — line 272
# variable: row — line 275
# variable: key — line 278
# variable: row — line 278
# variable: report — line 281
# definition: cells — line 287
# parameter: row — line 287
# variable: decision — line 289
# END CODE MAP

from __future__ import annotations

import html
import sys
from pathlib import Path
from typing import Any

from .compare import compare, publish
from .contracts import canonical, digest, load_cases, load_snapshots
from .desktop_io import Rejected, json_value, read_bytes
from .desktop_state import Workspace
from .evaluate import run
from .evidence import save

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "ai-security-evaluation-lab", "AiSecurityEvaluationLab"
TITLE, VERSION = "AI Security Evaluation Workbench", "1.1.1"
COLUMNS = (
    "Case / objective",
    "Policy / observation",
    "Evidence reason",
    "Decision / change",
)
RESOURCES = (
    "data/cases.jsonl",
    "data/manifest.json",
    "sql/schema.sql",
    "examples/desktop/baseline.jsonl",
    "examples/desktop/candidate.jsonl",
    "examples/desktop/partial.jsonl",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
MODES = (
    "Evaluate supplied response replay",
    "Compare data-only response snapshots",
    "Build response snapshot template",
)
REVIEW_MODE = None
CHOICES: dict[str, tuple[str, ...]] = {}
FIELDS = (
    (
        "cases",
        "Authorized reviewed case corpus JSONL (contexts, scopes, expected decisions)",
        "file",
    ),
    (
        "snapshots",
        "Optional response snapshot JSONL (blank uses authored responses)",
        "file",
    ),
    ("baseline", "Earlier data-only response snapshot JSONL", "file"),
    ("candidate", "Candidate data-only response snapshot JSONL", "file"),
)
ACTIVE_FIELDS = {
    MODES[0]: ("cases", "snapshots"),
    MODES[1]: ("cases", "baseline", "candidate"),
    MODES[2]: ("cases",),
}
SCENARIOS = (
    "Fictional 42-case broker replay",
    "Fictional changed response replay",
    "Fictional paired unsafe-allow and benign regression",
    "Fictional missing/timeout observation review",
    "Fictional response snapshot template",
)
HELP = "Select your authorized closed-schema JSONL cases and optional data-only snapshots. Case context/scopes/approvals and policy oracles are trusted authored inputs, not authority from model responses. Actual current in-memory broker evaluates the supplied responses; no LLM, provider/API, plugin, command or downstream service executes. Compare requires exact same case digests, preserving per-objective paired denominators and inconclusive telemetry; accepted text semantics are ungraded. A mismatching oracle or denied proposal is evidence to inspect, not a crashed app. Ordinary evaluation/comparison reports omit raw messages/responses and approval keys. IMPORTANT: explicitly choosing Build response snapshot template deliberately retains/exports the selected raw response objects in snapshot-template.jsonl; keep that file private and review it before sharing. Model labels are assertions, not authenticated identity. Prepared fictional scenarios use the same controls. History and exports are plaintext OS-owner data; no automatic upload."


def scenario(name: str) -> dict[str, str]:
    """Populate actual controls from public authored fixtures without automatically running or approving anything."""
    if name not in SCENARIOS:
        raise Rejected("unknown prepared scenario")
    index = SCENARIOS.index(name)
    return {
        "mode": MODES[0] if index < 2 else MODES[1] if index < 4 else MODES[2],
        "cases": str(ROOT / "data/cases.jsonl"),
        "snapshots": str(ROOT / "examples/desktop/candidate.jsonl")
        if index == 1
        else "",
        "baseline": str(ROOT / "examples/desktop/baseline.jsonl"),
        "candidate": str(
            ROOT
            / (
                "examples/desktop/partial.jsonl"
                if index == 3
                else "examples/desktop/candidate.jsonl"
            )
        ),
    }


def text_bundle(value: dict[str, Any], title: str) -> dict[str, bytes]:
    """Render only escaped metadata as finite JSON and inert HTML, never executable response contents."""
    raw = canonical(value) + b"\n"
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;"><title>'
        + html.escape(title)
        + "</title><main><h1>"
        + html.escape(title)
        + "</h1><p>Jason Stys. Offline authored data, not a model/API execution.</p><pre>"
        + html.escape(raw.decode())
        + "</pre></main></html>"
    )
    return {"result.json": raw, "result.html": page.encode()}


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Call the original real data-only engines and retain outcomes without turning oracle/telemetry failures into passes."""
    mode, cases_path = parameters["mode"], Path(parameters["cases"])
    if mode == MODES[1]:
        result = compare(
            cases_path, Path(parameters["baseline"]), Path(parameters["candidate"])
        )
        output = stage / "paired-review"
        publish(result, output)
        observed = sum(row["paired_observed"] for row in result["cases"])
        summary = f"{observed}/{len(result['cases'])} paired observed; {len(result['review_queue'])} review items; no model execution"
        return (
            mode,
            summary,
            {
                path.name: read_bytes(path, 32 * 1024 * 1024)
                for path in output.iterdir()
            },
        )
    if mode not in (MODES[0], MODES[2]):
        raise Rejected("unsupported data-only evaluation operation")
    cases, corpus_sha = load_cases(cases_path)
    if mode == MODES[2]:
        rows = [
            {
                "case_id": case.id,
                "case_digest": digest(case.__dict__),
                "model": "authored-response-fixture",
                "status": "complete",
                "response": case.response,
            }
            for case in cases
        ]
        metadata = {
            "kind": "sensitive_response_template",
            "corpus_sha256": corpus_sha,
            "records": [
                {key: value for key, value in row.items() if key != "response"}
                for row in rows
            ],
            "warning": "The separate snapshot-template.jsonl deliberately contains raw selected response objects. It is private data, not an evaluation result or proof of model execution.",
        }
        files = text_bundle(metadata, "Response snapshot template metadata")
        files["snapshot-template.jsonl"] = (
            b"\n".join(canonical(row) for row in rows) + b"\n"
        )
        return (
            mode,
            f"{len(rows)} data-only template records; raw responses included — keep private; not an evaluation",
            files,
        )
    snapshots, snapshot_sha = (
        load_snapshots(Path(parameters["snapshots"]), cases)
        if parameters["snapshots"].strip()
        else (None, None)
    )
    result = run(cases, corpus_sha, snapshots, snapshot_sha)
    output = stage / "evaluation"
    save(output, result)
    inconclusive = sum(
        row["enforced"]["verdict"] == "inconclusive" for row in result["cases"]
    )
    mismatches = sum(not row["oracle_match"] for row in result["cases"])
    summary = f"{len(cases)} supplied cases; {mismatches} oracle mismatches; {inconclusive} inconclusive; no model execution"
    return (
        mode,
        summary,
        {path.name: read_bytes(path, 32 * 1024 * 1024) for path in output.iterdir()},
    )


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Expose original outcomes/denominators and raw-response-free detail views; templates have explicit sensitivity metadata."""
    if "evaluation.json" in files:
        report = json_value(files["evaluation.json"])
        return {
            "Original case decisions": report["cases"],
            "Objective counts and rates": [
                {"objective": key, **row} for key, row in report["metrics"].items()
            ],
            "Pending and inconclusive": [
                row
                for row in report["cases"]
                if row["enforced"]["verdict"] in {"review", "inconclusive"}
            ],
        }
    if "comparison.json" in files:
        report = json_value(files["comparison.json"])
        queued = set(report["review_queue"])
        return {
            "Paired case transitions": report["cases"],
            "Review queue": [row for row in report["cases"] if row["id"] in queued],
            "Objective paired denominators": [
                {"objective": key, **row}
                for key, row in report["objective_pairs"].items()
            ],
        }
    report = json_value(files["result.json"])
    return {
        "Sensitive template metadata — raw responses in export only": report["records"]
    }


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Keep table summaries compact while full original policy/metric evidence remains selectable."""
    decision = row.get("enforced", row.get("candidate", {}))
    return (
        str(row.get("id", row.get("case_id", row.get("objective", "scope")))),
        str(row.get("objective", row.get("model", "paired denominators"))),
        str(decision.get("reason", row.get("case_digest", "inspect exact counts"))),
        ", ".join(row["changes"])
        if "changes" in row
        else str(decision.get("verdict", row.get("status", "inspect exact counts"))),
    )
