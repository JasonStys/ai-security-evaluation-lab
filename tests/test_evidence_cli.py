"""Jason Stys: end-to-end CLI, no-overwrite privacy, inert HTML, SQLite constraints and immutable ledger tests."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 49
# definition: test_cli_end_to_end — line 52
# parameter: capsys — line 52
# parameter: tmp_path — line 52
# variable: source — line 54
# variable: output — line 55
# variable: report — line 57
# variable: template — line 61
# variable: first — line 82
# variable: malformed — line 111
# variable: exited — line 132
# definition: test_evidence_escaping_sql_and_permissions — line 138
# parameter: tmp_path — line 138
# variable: cases — line 140
# variable: sha — line 140
# variable: report — line 141
# variable: payload — line 142
# variable: html — line 144
# variable: directory — line 148
# variable: report_id — line 149
# variable: connection — line 150
# variable: table — line 163
# variable: verb — line 164
# variable: query — line 165
# variable: existing — line 189
# variable: link — line 195
# END CODE MAP

from __future__ import annotations

import json
import os
import runpy
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from aisec.cli import main
from aisec.contracts import canonical, load_cases, parse
from aisec.evaluate import run
from aisec.evidence import render, save, write_private

ROOT = Path(__file__).resolve().parents[1]


def test_cli_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Produce actual paired evidence, import synthetic snapshots and reject output overwrites."""
    source = ROOT / "data/cases.jsonl"
    output = tmp_path / "run"
    assert main(["evaluate", "--cases", str(source), "--out", str(output)]) == 0
    report = json.loads((output / "evaluation.json").read_text())
    assert report["author"] == "Jason Stys" and len(report["cases"]) == 42
    assert main(["evaluate", "--cases", str(source), "--out", str(output)]) == 2
    assert "FileExistsError" in capsys.readouterr().err
    template = tmp_path / "snapshot.jsonl"
    assert (
        main(["snapshot-template", "--cases", str(source), "--out", str(template)]) == 0
    )
    assert (
        main(["snapshot-template", "--cases", str(source), "--out", str(template)]) == 2
    )
    assert (
        main(
            [
                "evaluate",
                "--cases",
                str(source),
                "--snapshots",
                str(template),
                "--out",
                str(tmp_path / "imported"),
            ]
        )
        == 0
    )
    first = parse(template.read_bytes().splitlines()[0])
    first["status"] = "timeout"
    template.write_bytes(canonical(first))
    assert (
        main(
            [
                "evaluate",
                "--cases",
                str(source),
                "--snapshots",
                str(template),
                "--out",
                str(tmp_path / "missing"),
            ]
        )
        == 1
    )
    assert (
        main(
            [
                "evaluate",
                "--cases",
                str(tmp_path / "missing-file"),
                "--out",
                str(tmp_path / "unused"),
            ]
        )
        == 2
    )
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_bytes(b"{}")
    assert (
        main(["evaluate", "--cases", str(malformed), "--out", str(tmp_path / "bad")])
        == 2
    )
    with (
        patch.dict(sys.modules),
        patch.object(
            sys,
            "argv",
            [
                "aisec.cli",
                "evaluate",
                "--cases",
                str(source),
                "--out",
                str(tmp_path / "module"),
            ],
        ),
    ):
        with pytest.raises(SystemExit) as exited:
            sys.modules.pop("aisec.cli", None)
            runpy.run_module("aisec.cli", run_name="__main__")
    assert exited.value.code == 0


def test_evidence_escaping_sql_and_permissions(tmp_path: Path) -> None:
    """HTML is inert and escaped; report values are SQL parameters and existing outputs cannot be replaced."""
    cases, sha = load_cases(ROOT / "data/cases.jsonl")
    report = run(cases, sha)
    payload = "<script>alert('x')</script>"
    report["cases"][0]["id"] = payload
    html = render(report)
    assert payload not in html and "&lt;script&gt;" in html and "default-src" in html
    assert 'scope="col"' in html and "<caption>" in html
    assert "LAB-CANARY-DO-NOT-USE-42" not in html
    directory = tmp_path / "ledger"
    report_id = save(directory, report)
    with closing(sqlite3.connect(directory / "evidence.sqlite")) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        assert (
            connection.execute("SELECT count(*) FROM observation").fetchone()[0] == 42
        )
        assert (
            connection.execute(
                "SELECT case_id FROM observation WHERE case_id = ?", (payload,)
            ).fetchone()[0]
            == payload
        )
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        for table in ("evaluation", "observation"):
            for verb in ("DELETE FROM", "UPDATE"):
                query = f"{verb} {table}" + (
                    " SET id='different'"
                    if table == "evaluation" and verb == "UPDATE"
                    else " SET case_id='different'"
                    if verb == "UPDATE"
                    else ""
                )
                with pytest.raises(sqlite3.IntegrityError):
                    connection.execute(query)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO observation VALUES (?, ?, ?, ?, ?, ?)",
                ("0" * 64, "new", "scope", "allow", "allow", "1" * 64),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO observation VALUES (?, ?, ?, ?, ?, ?)",
                (report_id, "new", "scope", "allow", "wrong", "1" * 64),
            )
    with pytest.raises(FileExistsError):
        save(directory, report)
    if os.name != "nt":
        assert directory.stat().st_mode & 0o777 == 0o700
        assert (directory / "evaluation.json").stat().st_mode & 0o777 == 0o600
    existing = tmp_path / "existing"
    existing.write_text("preserve")
    with pytest.raises(FileExistsError):
        write_private(existing, b"replace")
    assert existing.read_text() == "preserve"
    if os.name != "nt":
        link = tmp_path / "symlink"
        link.symlink_to(existing)
        with pytest.raises(FileExistsError):
            write_private(link, b"replace")
        assert existing.read_text() == "preserve"
