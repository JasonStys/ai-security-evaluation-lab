"""Jason Stys: same-case paired snapshot policy/availability/telemetry review oracles."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: snapshots — line 67
# parameter: tmp_path — line 67
# variable: _ — line 69
# variable: cases — line 69
# variable: records — line 70
# variable: c — line 78
# variable: a — line 80
# variable: b — line 80
# variable: r — line 81
# definition: write — line 85
# parameter: path — line 85
# parameter: records — line 85
# variable: r — line 87
# definition: test_policy_and_benign_regressions — line 90
# parameter: tmp_path — line 90
# variable: a — line 92
# variable: b — line 92
# variable: records — line 92
# variable: changed — line 93
# variable: benign — line 94
# variable: r — line 94
# variable: safe — line 95
# variable: attack — line 97
# variable: r — line 97
# variable: before — line 100
# variable: result — line 101
# variable: r — line 102
# variable: row — line 102
# variable: danger — line 109
# variable: r — line 109
# variable: recovered — line 118
# variable: r — line 121
# definition: test_inconclusive_denominators_and_unpaired — line 125
# parameter: tmp_path — line 125
# variable: a — line 127
# variable: b — line 127
# variable: records — line 127
# variable: result — line 131
# variable: r — line 132
# variable: reverse — line 136
# variable: both — line 138
# variable: g — line 140
# definition: test_validation_cli_and_new_safe_output — line 143
# parameter: tmp_path — line 143
# variable: a — line 145
# variable: b — line 145
# variable: records — line 145
# variable: out — line 147
# variable: result — line 154
# variable: old — line 156
# END CODE MAP

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from aisec.cli import main
from aisec.compare import compare, publish
from aisec.contracts import canonical, digest, load_cases


def snapshots(tmp_path):
    """Use reviewed case digests and explicit fictional model labels; never call an AI provider."""
    cases, _ = load_cases(Path("data/cases.jsonl"))
    records = [
        {
            "case_id": c.id,
            "case_digest": digest(c.__dict__),
            "model": "fictional-baseline",
            "status": "complete",
            "response": c.response,
        }
        for c in cases
    ]
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    a.write_bytes(b"\n".join(canonical(r) for r in records) + b"\n")
    return a, b, records


def write(path, records):
    """Save explicit private fictional replay records with no executable adapter."""
    path.write_bytes(b"\n".join(canonical(r) for r in records) + b"\n")


def test_policy_and_benign_regressions(tmp_path: Path):
    """Increased unsafe allow and lost benign task completion are separate from a misleading aggregate score."""
    a, b, records = snapshots(tmp_path)
    changed = copy.deepcopy(records)
    benign = next(r for r in changed if r["case_id"] == "benign-read")
    safe = copy.deepcopy(benign["response"])
    benign["response"] = {}
    attack = next(r for r in changed if r["case_id"] == "direct-override")
    attack["response"] = safe
    write(b, changed)
    before = a.read_bytes()
    result = compare(Path("data/cases.jsonl"), a, b)
    row = next(r for r in result["cases"] if r["id"] == "benign-read")
    assert set(row["changes"]) == {
        "BENIGN_AVAILABILITY_REGRESSION",
        "BENIGN_TOOL_COMPLETION_REGRESSION",
        "ORACLE_REGRESSION",
        "DECISION_CHANGED",
    }
    danger = next(r for r in result["cases"] if r["id"] == attack["case_id"])
    assert (
        "UNSAFE_ALLOW_INCREASE" in danger["changes"]
        and "ORACLE_REGRESSION" in danger["changes"]
    )
    assert len(result["review_queue"]) == 2 and a.read_bytes() == before
    assert "Schedule a synthetic" not in json.dumps(
        result
    ) and "Summarize the guide" not in json.dumps(result)
    recovered = compare(Path("data/cases.jsonl"), b, a)
    assert (
        "ORACLE_RECOVERY"
        in next(r for r in recovered["cases"] if r["id"] == "benign-read")["changes"]
    )


def test_inconclusive_denominators_and_unpaired(tmp_path: Path):
    """Missing/timeouts cannot become perfect refusal scores or benign regressions; paired denominators are explicit."""
    a, b, records = snapshots(tmp_path)
    records.pop(0)
    records[0]["status"] = "timeout"
    write(b, records)
    result = compare(Path("data/cases.jsonl"), a, b)
    assert sum(r["paired_observed"] for r in result["cases"]) == 40
    assert result["cases"][0]["changes"] == ["LOST_OBSERVATION"] and result["cases"][1][
        "changes"
    ] == ["LOST_OBSERVATION"]
    reverse = compare(Path("data/cases.jsonl"), b, a)
    assert reverse["cases"][0]["changes"] == ["NEW_OBSERVATION"]
    both = compare(Path("data/cases.jsonl"), b, b)
    assert both["cases"][0]["changes"] == ["BOTH_INCONCLUSIVE"]
    assert sum(g["paired_observed"] for g in both["objective_pairs"].values()) == 40


def test_validation_cli_and_new_safe_output(tmp_path: Path):
    """Actual compare command writes42 unchanged pairs, rejects context drift and preserves previous evidence."""
    a, b, records = snapshots(tmp_path)
    write(b, records)
    out = tmp_path / "review"
    assert (
        main(
            ["compare", "--baseline", str(a), "--candidate", str(b), "--out", str(out)]
        )
        == 0
    )
    result = json.loads((out / "comparison.json").read_text())
    assert len(result["cases"]) == 42 and result["review_queue"] == []
    old = (out / "comparison.json").read_bytes()
    assert (
        main(
            ["compare", "--baseline", str(a), "--candidate", str(b), "--out", str(out)]
        )
        == 2
    )
    assert (out / "comparison.json").read_bytes() == old
    result["limits"] = "<script>bad</script>"
    publish(result, tmp_path / "escaped")
    assert "<script>" not in (tmp_path / "escaped/comparison.html").read_text(
        encoding="utf-8"
    )
    records[0]["case_digest"] = "0" * 64
    write(b, records)
    with pytest.raises(ValueError):
        compare(Path("data/cases.jsonl"), a, b)
    with patch.object(Path, "is_symlink", return_value=True), pytest.raises(ValueError):
        compare(Path("data/cases.jsonl"), a, b)
    with (
        patch.object(Path, "is_junction", return_value=True),
        pytest.raises(ValueError),
    ):
        publish(result, tmp_path / "linked")
