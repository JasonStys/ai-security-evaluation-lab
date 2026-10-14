"""Jason Stys: private exclusive evidence outputs, inert escaped HTML and parameterized append-only SQL."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 35
# definition: render — line 38
# parameter: report — line 38
# variable: rows — line 40
# variable: value — line 44
# variable: row — line 55
# definition: write_private — line 80
# parameter: content — line 80
# parameter: path — line 80
# variable: descriptor — line 82
# variable: stream — line 83
# definition: save — line 87
# parameter: directory — line 87
# parameter: report — line 87
# variable: database — line 95
# variable: connection — line 97
# variable: report_id — line 100
# variable: row — line 121
# END CODE MAP

from __future__ import annotations

import html
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from aisec.contracts import canonical, digest

ROOT = Path(__file__).resolve().parents[1]


def render(report: dict[str, Any]) -> str:
    """Render metadata as inert text; no response text, script, external assets or untrusted HTML is inserted."""
    rows = "".join(
        "<tr>"
        + "".join(
            "<td>" + html.escape(str(value), quote=True) + "</td>"
            for value in (
                row["id"],
                row["objective"],
                row["origin"],
                row["baseline"]["verdict"],
                row["enforced"]["verdict"],
                row["enforced"]["reason"],
                row["oracle_match"],
            )
        )
        + "</tr>"
        for row in report["cases"]
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        "<title>AI security evaluation — Jason Stys</title></head><body><main>"
        "<h1>AI security evaluation lab</h1><p>Created by Jason Stys. Offline metadata-only evidence.</p>"
        "<p>"
        + html.escape(report["limits"])
        + "</p><p>Corpus SHA256: "
        + html.escape(report["corpus_sha256"])
        + "</p>"
        "<table><caption>Paired policy outcomes; allow/block is not a model-security score.</caption>"
        '<thead><tr><th scope="col">Case</th><th scope="col">Objective</th><th scope="col">Origin</th>'
        '<th scope="col">Baseline</th><th scope="col">Enforced</th><th scope="col">Reason</th>'
        '<th scope="col">Oracle match</th></tr></thead><tbody>'
        + rows
        + "</tbody></table>"
        "<h2>Help</h2><p>Review inconclusive and pending cases manually. See docs/testing.md and docs/usage.md in the repository.</p>"
        '<p>Contact: <a href="https://github.com/JasonStys" rel="noreferrer">Jason Stys on GitHub</a></p>'
        "</main></body></html>"
    )


def write_private(path: Path, content: bytes) -> None:
    """Exclusively create an output using mode 0600; never overwrite an existing file or follow its symlink."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def save(directory: Path, report: dict[str, Any]) -> str:
    """Create a new evidence directory and append-only SQLite snapshot; partial failures are left for inspection."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_private(
        directory / "evaluation.json",
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n",
    )
    write_private(directory / "evaluation.html", render(report).encode())
    database = directory / "evidence.sqlite"
    write_private(database, b"")
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript((ROOT / "sql/schema.sql").read_text(encoding="utf-8"))
        report_id = digest(report)
        connection.execute(
            "INSERT INTO evaluation VALUES (?, ?, ?, ?)",
            (
                report_id,
                report["mode"],
                report["corpus_sha256"],
                canonical(report).decode(),
            ),
        )
        connection.executemany(
            "INSERT INTO observation VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    report_id,
                    row["id"],
                    row["objective"],
                    row["expected"],
                    row["enforced"]["verdict"],
                    row["response_digest"],
                )
                for row in report["cases"]
            ],
        )
    return report_id
