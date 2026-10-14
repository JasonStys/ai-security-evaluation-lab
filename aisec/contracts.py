"""Jason Stys: bounded strict JSON contracts for synthetic cases and untrusted response snapshots."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_FILE — line 85
# variable: MAX_RECORD — line 86
# variable: MAX_CASES — line 87
# variable: MAX_TEXT — line 88
# definition: ContractError — line 91
# definition: object_pairs — line 95
# parameter: pairs — line 95
# variable: result — line 97
# variable: key — line 98
# variable: value — line 98
# definition: nonfinite — line 105
# parameter: value — line 105
# definition: finite_float — line 110
# parameter: value — line 110
# variable: number — line 112
# definition: parse — line 118
# parameter: raw — line 118
# variable: text — line 123
# definition: canonical — line 137
# parameter: value — line 137
# definition: digest — line 144
# parameter: value — line 144
# definition: fields — line 149
# parameter: expected — line 149
# parameter: value — line 149
# definition: identifier — line 156
# parameter: value — line 156
# definition: bounded_text — line 163
# parameter: value — line 163
# definition: records — line 175
# parameter: path — line 175
# variable: stream — line 177
# variable: raw — line 178
# variable: lines — line 181
# variable: line — line 182
# variable: line — line 184
# definition: Case — line 188
# variable: id — line 191
# variable: objective — line 192
# variable: attack — line 193
# variable: origin — line 194
# variable: message — line 195
# variable: scopes — line 196
# variable: approval — line 197
# variable: expected — line 198
# variable: response — line 199
# definition: from_json — line 202
# parameter: cls — line 202
# parameter: value — line 202
# variable: data — line 204
# variable: scopes — line 218
# variable: scope — line 225
# definition: load_cases — line 256
# parameter: path — line 256
# variable: data — line 258
# variable: sha — line 258
# variable: cases — line 259
# variable: value — line 259
# variable: case — line 260
# definition: load_snapshots — line 265
# parameter: cases — line 266
# parameter: path — line 266
# variable: data — line 269
# variable: sha — line 269
# variable: case — line 270
# variable: known — line 270
# variable: snapshots — line 271
# variable: value — line 272
# variable: record — line 273
# variable: case_id — line 276
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_FILE = 2 * 1024 * 1024
MAX_RECORD = 32 * 1024
MAX_CASES = 1000
MAX_TEXT = 8192


class ContractError(ValueError):
    """Reject ambiguous or oversized inputs without including their potentially sensitive contents."""


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object from parser pairs; repeated keys cannot silently replace authority fields."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def nonfinite(value: str) -> None:
    """Reject JSON extensions such as NaN and Infinity rather than accepting nonportable numbers."""
    raise ContractError("nonfinite JSON constant")


def finite_float(value: str) -> float:
    """Reject numeric overflow written as standard JSON exponents, not just NaN/Infinity extensions."""
    number = float(value)
    if not math.isfinite(number):
        raise ContractError("floating point overflow")
    return number


def parse(raw: bytes) -> Any:
    """Decode a bounded UTF-8 record; cap nesting before using the standard-library JSON parser."""
    if len(raw) > MAX_RECORD:
        raise ContractError("record too large")
    try:
        text = raw.decode("utf-8")
        # Preflight counts structural delimiters even inside strings: conservative, not permissive.
        if text.count("{") + text.count("[") > 128:
            raise ContractError("structure budget exceeded")
        return json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=nonfinite,
            parse_float=finite_float,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ContractError("invalid UTF-8 JSON") from error


def canonical(value: Any) -> bytes:
    """Serialize stable compact JSON; callers must provide JSON-compatible, finite values."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    """Return a content identifier for provenance; a digest is not anonymization or authentication."""
    return hashlib.sha256(canonical(value)).hexdigest()


def fields(value: Any, expected: set[str]) -> dict[str, Any]:
    """Require an exact object schema; additional fields are not treated as trusted extensions."""
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError("object fields do not match contract")
    return value


def identifier(value: Any) -> str:
    """Accept bounded ASCII identifiers only; paths, URLs and Unicode lookalikes are not resource IDs."""
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value):
        raise ContractError("invalid identifier")
    return value


def bounded_text(value: Any) -> str:
    """Accept finite UTF-8 text under the byte cap; reject surrogate code points."""
    if not isinstance(value, str):
        raise ContractError("text required")
    try:
        if len(value.encode("utf-8")) > MAX_TEXT:
            raise ContractError("text too large")
    except UnicodeError as error:
        raise ContractError("invalid Unicode text") from error
    return value


def records(path: Path) -> tuple[list[Any], str]:
    """Read at most MAX_FILE+1 bytes and MAX_CASES JSONL records; return exact input SHA256."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ContractError("file too large")
    lines = raw.splitlines()
    if not lines or len(lines) > MAX_CASES or any(not line.strip() for line in lines):
        raise ContractError("empty or excessive record count")
    return [parse(line) for line in lines], hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Case:
    """Reviewed fixture context and observable oracle; neither is accepted from model responses."""

    id: str
    objective: str
    attack: bool
    origin: str
    message: str
    scopes: tuple[str, ...]
    approval: str
    expected: str
    response: dict[str, Any]

    @classmethod
    def from_json(cls, value: Any) -> Case:
        """Validate complete fixture fields; approval modes belong solely to this offline harness."""
        data = fields(
            value,
            {
                "id",
                "objective",
                "attack",
                "origin",
                "message",
                "scopes",
                "approval",
                "expected",
                "response",
            },
        )
        scopes = data["scopes"]
        if (
            not isinstance(scopes, list)
            or len(scopes) > 2
            or len(set(map(str, scopes))) != len(scopes)
        ):
            raise ContractError("invalid scopes")
        if any(scope not in ("read", "draft") for scope in scopes):
            raise ContractError("unknown scope")
        if type(data["attack"]) is not bool:
            raise ContractError("boolean attack label required")
        if data["origin"] not in ("user", "retrieved-document", "tool-result"):
            raise ContractError("unknown origin")
        if data["approval"] not in (
            "none",
            "valid",
            "expired",
            "changed-action",
            "changed-session",
        ):
            raise ContractError("unknown approval fixture")
        if data["expected"] not in ("allow", "block", "review"):
            raise ContractError("invalid expected decision")
        if not isinstance(data["response"], dict):
            raise ContractError("response object required")
        return cls(
            identifier(data["id"]),
            identifier(data["objective"]),
            data["attack"],
            data["origin"],
            bounded_text(data["message"]),
            tuple(scopes),
            data["approval"],
            data["expected"],
            data["response"],
        )


def load_cases(path: Path) -> tuple[list[Case], str]:
    """Load unique reviewed cases; preserve input order for reproducible case-by-case comparisons."""
    data, sha = records(path)
    cases = [Case.from_json(value) for value in data]
    if len({case.id for case in cases}) != len(cases):
        raise ContractError("duplicate case ID")
    return cases, sha


def load_snapshots(
    path: Path, cases: list[Case]
) -> tuple[dict[str, dict[str, Any]], str]:
    """Import data-only responses; require exact case digests and explicit completion telemetry."""
    data, sha = records(path)
    known = {case.id: case for case in cases}
    snapshots: dict[str, dict[str, Any]] = {}
    for value in data:
        record = fields(
            value, {"case_id", "case_digest", "model", "status", "response"}
        )
        case_id = identifier(record["case_id"])
        if case_id not in known or case_id in snapshots:
            raise ContractError("unknown or duplicate snapshot ID")
        if record["case_digest"] != digest(known[case_id].__dict__):
            raise ContractError("snapshot context mismatch")
        identifier(record["model"])
        if record["status"] not in ("complete", "error", "timeout", "unsupported"):
            raise ContractError("invalid snapshot status")
        if not isinstance(record["response"], dict):
            raise ContractError("snapshot response object required")
        snapshots[case_id] = record
    return snapshots, sha
