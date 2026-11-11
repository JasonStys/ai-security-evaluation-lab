"""Jason Stys: bounded strict JSON contracts for synthetic cases and untrusted response snapshots."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_FILE — line 97
# variable: MAX_RECORD — line 98
# variable: MAX_CASES — line 99
# variable: MAX_TEXT — line 100
# definition: ContractError — line 103
# definition: object_pairs — line 107
# parameter: pairs — line 107
# variable: result — line 109
# variable: key — line 110
# variable: value — line 110
# definition: nonfinite — line 117
# parameter: value — line 117
# definition: finite_float — line 122
# parameter: value — line 122
# variable: number — line 124
# definition: parse — line 130
# parameter: raw — line 130
# variable: text — line 135
# definition: canonical — line 149
# parameter: value — line 149
# definition: digest — line 156
# parameter: value — line 156
# definition: fields — line 161
# parameter: expected — line 161
# parameter: value — line 161
# definition: identifier — line 168
# parameter: value — line 168
# definition: bounded_text — line 175
# parameter: value — line 175
# definition: read_source — line 187
# parameter: limit — line 187
# parameter: path — line 187
# variable: absolute — line 189
# variable: item — line 192
# variable: flags — line 195
# variable: descriptor — line 201
# variable: stream — line 202
# variable: info — line 203
# variable: named — line 204
# variable: raw — line 212
# definition: records — line 218
# parameter: path — line 218
# variable: raw — line 220
# variable: lines — line 223
# variable: line — line 224
# variable: line — line 226
# definition: Case — line 230
# variable: id — line 233
# variable: objective — line 234
# variable: attack — line 235
# variable: origin — line 236
# variable: message — line 237
# variable: scopes — line 238
# variable: approval — line 239
# variable: expected — line 240
# variable: response — line 241
# definition: from_json — line 244
# parameter: cls — line 244
# parameter: value — line 244
# variable: data — line 246
# variable: scopes — line 260
# variable: scope — line 267
# definition: load_cases — line 298
# parameter: path — line 298
# variable: data — line 300
# variable: sha — line 300
# variable: cases — line 301
# variable: value — line 301
# variable: case — line 302
# definition: load_snapshots — line 307
# parameter: cases — line 308
# parameter: path — line 308
# variable: data — line 311
# variable: sha — line 311
# variable: case — line 312
# variable: known — line 312
# variable: snapshots — line 313
# variable: value — line 314
# variable: record — line 315
# variable: case_id — line 318
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
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


def read_source(path: Path, limit: int) -> bytes:
    """Read only bounded ordinary one-link bytes from one nonblocking descriptor; refuse reparse paths and replacements."""
    absolute = path.absolute()
    if any(
        item.is_symlink() or item.is_junction()
        for item in (absolute, *absolute.parents)
    ):
        raise ContractError("linked input path")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(absolute, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        named = absolute.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > limit
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise ContractError("bounded ordinary unchanged input required")
        raw = stream.read(limit + 1)
        if len(raw) != info.st_size or len(raw) > limit:
            raise ContractError("input changed or exceeded byte limit")
    return raw


def records(path: Path) -> tuple[list[Any], str]:
    """Read at most MAX_FILE+1 bytes and MAX_CASES JSONL records; return exact input SHA256."""
    raw = read_source(path, MAX_FILE)
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
