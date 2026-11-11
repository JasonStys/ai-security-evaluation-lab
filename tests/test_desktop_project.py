"""Independent metadata/privacy, exact paired-denominator and real custom-case adapter tests. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: state — line 97
# parameter: tmp_path — line 97
# variable: result — line 99
# definition: run — line 106
# parameter: changes — line 106
# parameter: index — line 106
# parameter: state — line 106
# parameter: tmp_path — line 106
# variable: parameters — line 108
# variable: stage — line 109
# variable: files — line 111
# variable: kind — line 111
# variable: summary — line 111
# variable: identity — line 112
# definition: test_original_replay_has_all_oracles_but_never_claims_a_live_model_or_safe_answer — line 117
# parameter: state — line 118
# parameter: tmp_path — line 118
# variable: files — line 121
# variable: summary — line 121
# variable: value — line 122
# variable: row — line 124
# variable: name — line 128
# variable: rows — line 131
# definition: test_changed_replay_and_pair_keep_unsafe_allow_and_benign_loss_separate — line 137
# parameter: state — line 138
# parameter: tmp_path — line 138
# variable: files — line 141
# variable: summary — line 141
# variable: value — line 143
# variable: row — line 144
# variable: files — line 145
# variable: summary — line 145
# variable: value — line 146
# variable: danger — line 147
# variable: row — line 147
# variable: benign — line 148
# variable: row — line 148
# definition: test_missing_and_timeout_remain_unpaired_not_successful_blocks — line 158
# parameter: state — line 158
# parameter: tmp_path — line 158
# variable: files — line 160
# variable: summary — line 160
# variable: value — line 161
# variable: row — line 163
# variable: row — line 169
# definition: test_template_is_explicit_sensitive_data_not_a_measured_model_result — line 173
# parameter: state — line 174
# parameter: tmp_path — line 174
# variable: files — line 177
# variable: summary — line 177
# variable: records — line 178
# variable: line — line 179
# variable: row — line 181
# variable: metadata — line 184
# variable: row — line 185
# definition: test_selected_custom_corpus_changes_trusted_scope_and_does_not_run_a_plugin — line 190
# parameter: state — line 191
# parameter: tmp_path — line 191
# variable: row — line 194
# variable: line — line 196
# variable: selected — line 200
# variable: original — line 202
# variable: files — line 203
# variable: summary — line 203
# variable: report — line 204
# definition: test_invalid_or_invented_operations_retain_old_exact_bundle — line 222
# parameter: change — line 223
# parameter: state — line 223
# parameter: tmp_path — line 223
# variable: _ — line 226
# variable: first — line 226
# definition: test_tampered_case_context_and_empty_template_inputs_are_refused — line 232
# parameter: state — line 232
# parameter: tmp_path — line 232
# variable: source — line 234
# variable: line — line 235
# variable: rows — line 235
# variable: candidate — line 237
# variable: row — line 238
# END CODE MAP

import json
import uuid

import pytest

from aisec import desktop_project as project
from aisec.boundary import CANARY
from aisec.contracts import canonical, load_cases
from aisec.desktop_io import Rejected, json_value
from aisec.desktop_state import Workspace


@pytest.fixture
def state(tmp_path):
    """Use only a fresh marked synthetic profile outside the application resources."""
    result = Workspace(
        tmp_path / "profile", project.PRODUCT, project.ROOT, synthetic=True
    )
    yield result
    result.close()


def run(state, tmp_path, index, **changes):
    """Run actual broker/SQL/paired-review code; every attempt uses fresh staging, including rejected inputs."""
    parameters = {**project.scenario(project.SCENARIOS[index]), **changes}
    stage = tmp_path / ("stage-" + uuid.uuid4().hex)
    stage.mkdir()
    kind, summary, files = project.analyze(state, parameters, stage)
    identity = state.save(kind, summary, parameters, files)
    assert state.files(identity) == files
    return files, summary


def test_original_replay_has_all_oracles_but_never_claims_a_live_model_or_safe_answer(
    state, tmp_path
):
    """All42 authored policy oracles agree, while raw response/message/canary values stay out of ordinary evidence."""
    files, summary = run(state, tmp_path, 0)
    value = json_value(files["evaluation.json"])
    assert len(value["cases"]) == 42 and all(
        row["oracle_match"] for row in value["cases"]
    )
    assert "0 oracle mismatches" in summary and "no model execution" in summary
    assert set(files) == {"evaluation.json", "evaluation.html", "evidence.sqlite"}
    for name in ("evaluation.json", "evaluation.html"):
        assert CANARY.encode() not in files[name]
        assert b"Schedule a synthetic" not in files[name]
    rows = project.views(files)
    assert len(rows["Original case decisions"]) == 42
    assert rows["Objective counts and rates"]
    assert "semantics" in value["limits"] or "semantic" in value["limits"]


def test_changed_replay_and_pair_keep_unsafe_allow_and_benign_loss_separate(
    state, tmp_path
):
    """An unsafe allow is not a success just because a tool completed; benign completion loss is separately reviewable."""
    files, summary = run(state, tmp_path, 1)
    assert "2 oracle mismatches" in summary
    value = json_value(files["evaluation.json"])
    assert sum(not row["oracle_match"] for row in value["cases"]) == 2
    files, summary = run(state, tmp_path, 2)
    value = json_value(files["comparison.json"])
    danger = next(row for row in value["cases"] if row["id"] == "direct-override")
    benign = next(row for row in value["cases"] if row["id"] == "benign-read")
    assert "UNSAFE_ALLOW_INCREASE" in danger["changes"]
    assert "BENIGN_TOOL_COMPLETION_REGRESSION" in benign["changes"]
    assert (
        "42/42 paired observed" in summary
        and len(project.views(files)["Review queue"]) == 2
    )
    assert len(project.cells(danger)) == 4


def test_missing_and_timeout_remain_unpaired_not_successful_blocks(state, tmp_path):
    """A dropped attack and timed-out benign case reduce the exact pair denominator from42to40."""
    files, summary = run(state, tmp_path, 3)
    value = json_value(files["comparison.json"])
    assert "40/42 paired observed" in summary
    assert {row["id"] for row in value["cases"] if not row["paired_observed"]} == {
        "direct-override",
        "benign-read",
    }
    assert len(project.views(files)["Review queue"]) == 2
    assert (
        sum(row["paired_observed"] for row in value["objective_pairs"].values()) == 40
    )


def test_template_is_explicit_sensitive_data_not_a_measured_model_result(
    state, tmp_path
):
    """The requested template retains raw selected response objects, while its preview exposes only declared metadata."""
    files, summary = run(state, tmp_path, 4)
    records = [
        json.loads(line) for line in files["snapshot-template.jsonl"].splitlines()
    ]
    assert len(records) == 42 and all("response" in row for row in records)
    assert CANARY.encode() in files["snapshot-template.jsonl"]
    assert "raw responses included" in summary and "not an evaluation" in summary
    metadata = json_value(files["result.json"])
    assert all("response" not in row for row in metadata["records"])
    assert "sensitive_response_template" == metadata["kind"]
    assert len(next(iter(project.views(files).values()))) == 42


def test_selected_custom_corpus_changes_trusted_scope_and_does_not_run_a_plugin(
    state, tmp_path
):
    """A single ordinary user-selected case with no read authority is actually blocked despite its allow oracle."""
    row = next(
        json.loads(line)
        for line in (project.ROOT / "data/cases.jsonl").read_bytes().splitlines()
        if json.loads(line)["id"] == "benign-read"
    )
    row["scopes"] = []
    selected = tmp_path / "private-corpus.jsonl"
    selected.write_bytes(canonical(row) + b"\n")
    original = selected.read_bytes()
    files, summary = run(state, tmp_path, 0, cases=str(selected))
    report = json_value(files["evaluation.json"])
    assert (
        len(report["cases"]) == 1
        and report["cases"][0]["enforced"]["verdict"] == "block"
    )
    assert report["cases"][0]["oracle_match"] is False
    assert "1 oracle mismatches" in summary and selected.read_bytes() == original


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "call live provider"},
        {"cases": ""},
        {"candidate": "missing.jsonl"},
        {"baseline": ""},
    ],
)
def test_invalid_or_invented_operations_retain_old_exact_bundle(
    state, tmp_path, change
):
    """No invalid data/command choice can erase an accepted prior result or silently replace missing files with demos."""
    first, _ = run(state, tmp_path, 0)
    with pytest.raises((ValueError, OSError)):
        run(state, tmp_path, 2, **change)
    assert len(state.history()) == 1 and state.files(1) == first


def test_tampered_case_context_and_empty_template_inputs_are_refused(state, tmp_path):
    """Snapshot records cannot replace the trusted context by retaining only a case name."""
    source = project.ROOT / "examples/desktop/baseline.jsonl"
    rows = [json.loads(line) for line in source.read_bytes().splitlines()]
    rows[0]["case_digest"] = "0" * 64
    candidate = tmp_path / "changed.jsonl"
    candidate.write_bytes(b"\n".join(canonical(row) for row in rows) + b"\n")
    with pytest.raises(ValueError, match="context"):
        run(state, tmp_path, 2, candidate=str(candidate))
    with pytest.raises(Rejected):
        project.scenario("approve production agent")
    assert state.history() == []
    assert load_cases(project.ROOT / "data/cases.jsonl")[0]
