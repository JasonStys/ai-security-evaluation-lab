"""Jason Stys: strict ingestion, byte/record bounds, duplicate-key rejection and snapshot provenance tests."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_invalid_json — line 83
# parameter: raw — line 83
# definition: test_arbitrary_bytes — line 91
# parameter: raw — line 91
# variable: value — line 94
# definition: test_identifiers — line 101
# parameter: value — line 101
# definition: test_text — line 110
# parameter: value — line 110
# definition: test_invalid_case — line 132
# parameter: change — line 132
# definition: test_file_bounds — line 139
# parameter: kind — line 139
# parameter: tmp_path — line 139
# variable: path — line 141
# variable: row — line 142
# variable: raw — line 143
# definition: test_snapshot_contract — line 155
# parameter: tmp_path — line 155
# variable: case — line 157
# variable: path — line 158
# variable: good — line 159
# variable: sha — line 167
# variable: snapshots — line 167
# variable: change — line 169
# END CODE MAP

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aisec.contracts import (
    MAX_CASES,
    MAX_FILE,
    MAX_RECORD,
    Case,
    ContractError,
    bounded_text,
    canonical,
    digest,
    identifier,
    load_cases,
    load_snapshots,
    parse,
    records,
)
from scripts.corpus import build


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b"NaN",
        b"Infinity",
        b"1e999",
        b"9" * 5000,
        b'{"x":',
        b"\xff",
        b"[" * 129,
        b'"' + b"x" * MAX_RECORD + b'"',
    ],
    ids=[
        "duplicates",
        "nan",
        "infinity",
        "float-overflow",
        "integer-overflow",
        "syntax",
        "utf8",
        "structure",
        "oversize",
    ],
)
def test_invalid_json(raw: bytes) -> None:
    """Invalid and ambiguous encodings must return contract errors without input contents."""
    with pytest.raises(ContractError):
        parse(raw)


@given(st.binary(max_size=1024))
@settings(max_examples=200, deadline=None)
def test_arbitrary_bytes(raw: bytes) -> None:
    """Fuzz the actual strict parser; arbitrary byte strings either parse or fail with bounded contract errors."""
    try:
        value = parse(raw)
    except ContractError:
        return
    assert parse(canonical(value)) == value


@pytest.mark.parametrize("value", ["A", "../doc-a", "dοc-a", "", "a" * 65, 1])
def test_identifiers(value: Any) -> None:
    """Paths, non-ASCII lookalikes, wrong types and overlong identifiers are not accepted."""
    with pytest.raises(ContractError):
        identifier(value)


@pytest.mark.parametrize(
    "value", [1, "x" * 8193, "\ud800"], ids=["type", "bytes", "surrogate"]
)
def test_text(value: Any) -> None:
    """Enforce UTF-8 byte limits and exclude ill-formed Unicode before rendering or hashing."""
    with pytest.raises(ContractError):
        bounded_text(value)
    assert bounded_text("é" * 4096) == "é" * 4096


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"scopes": "read"},
        {"scopes": ["read", "read"]},
        {"scopes": ["execute"]},
        {"scopes": ["read", "draft", "read"]},
        {"attack": 1},
        {"origin": "system"},
        {"approval": "self"},
        {"expected": "secure"},
        {"response": []},
    ],
)
def test_invalid_case(change: dict[str, Any]) -> None:
    """Unknown authority fields and values cannot silently alter reviewed fixture context."""
    with pytest.raises(ContractError):
        Case.from_json({**build()[0], **change})


@pytest.mark.parametrize("kind", ["empty", "blank", "count", "bytes", "duplicate"])
def test_file_bounds(tmp_path: Path, kind: str) -> None:
    """Read bounded files and fail duplicate case IDs; large failure payloads use short pytest IDs."""
    path = tmp_path / "cases.jsonl"
    row = canonical(build()[0])
    raw = {
        "empty": b"",
        "blank": b"{}\n\n",
        "count": b"{}\n" * (MAX_CASES + 1),
        "bytes": b"x" * (MAX_FILE + 1),
        "duplicate": row + b"\n" + row,
    }[kind]
    path.write_bytes(raw)
    with pytest.raises(ContractError):
        load_cases(path)


def test_snapshot_contract(tmp_path: Path) -> None:
    """Require exact case context and statuses; a data-only snapshot cannot add authority or executable adapters."""
    case = Case.from_json(build()[0])
    path = tmp_path / "snapshot.jsonl"
    good = {
        "case_id": case.id,
        "case_digest": digest(asdict(case)),
        "model": "test-model",
        "status": "complete",
        "response": case.response,
    }
    path.write_bytes(canonical(good))
    snapshots, sha = load_snapshots(path, [case])
    assert snapshots[case.id]["model"] == "test-model" and len(sha) == 64
    for change in [
        {"case_id": "unknown"},
        {"case_digest": "0" * 64},
        {"status": "okay"},
        {"response": []},
        {"approved": True},
        {"model": "<script>"},
    ]:
        path.write_bytes(canonical({**good, **change}))
        with pytest.raises(ContractError):
            load_snapshots(path, [case])
    path.write_bytes(canonical(good) + b"\n" + canonical(good))
    with pytest.raises(ContractError):
        load_snapshots(path, [case])
    assert parse(b'{"nested":[1,true,null]}') == {"nested": [1, True, None]}
    assert parse(b"0.5") == 0.5
    assert records(path)[0]
    with pytest.raises(ValueError):
        canonical({"x": float("nan")})
