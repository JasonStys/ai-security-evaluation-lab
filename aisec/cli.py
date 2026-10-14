"""Jason Stys: offline evaluate and snapshot-template commands; no network, API key, service or arbitrary code execution."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 34
# parameter: argv — line 34
# variable: parser — line 36
# variable: commands — line 39
# variable: evaluate — line 40
# variable: template — line 46
# variable: args — line 51
# variable: cases — line 53
# variable: corpus_sha — line 53
# variable: lines — line 55
# variable: case — line 65
# variable: snapshot_sha — line 70
# variable: snapshots — line 70
# variable: report — line 73
# variable: report_id — line 74
# variable: mismatches — line 75
# variable: row — line 75
# END CODE MAP

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aisec.contracts import ContractError, canonical, digest, load_cases, load_snapshots
from aisec.evaluate import run
from aisec.evidence import save, write_private


def main(argv: list[str] | None = None) -> int:
    """Validate user-selected paths, emit only safe counts and return nonzero for drift or inconclusive evidence."""
    parser = argparse.ArgumentParser(
        description="Offline AI security evaluation lab — Jason Stys"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate = commands.add_parser(
        "evaluate", help="Write JSON, inert HTML and SQLite to a new private directory"
    )
    evaluate.add_argument("--cases", type=Path, default=Path("data/cases.jsonl"))
    evaluate.add_argument("--snapshots", type=Path)
    evaluate.add_argument("--out", type=Path, required=True)
    template = commands.add_parser(
        "snapshot-template", help="Export dummy responses, not a real model evaluation"
    )
    template.add_argument("--cases", type=Path, default=Path("data/cases.jsonl"))
    template.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        cases, corpus_sha = load_cases(args.cases)
        if args.command == "snapshot-template":
            lines = [
                canonical(
                    {
                        "case_id": case.id,
                        "case_digest": digest(case.__dict__),
                        "model": "authored-response-fixture",
                        "status": "complete",
                        "response": case.response,
                    }
                )
                for case in cases
            ]
            write_private(args.out, b"\n".join(lines) + b"\n")
            print(json.dumps({"records": len(cases), "kind": "synthetic-template"}))
            return 0
        snapshots, snapshot_sha = (
            load_snapshots(args.snapshots, cases) if args.snapshots else (None, None)
        )
        report = run(cases, corpus_sha, snapshots, snapshot_sha)
        report_id = save(args.out, report)
        mismatches = sum(not row["oracle_match"] for row in report["cases"])
        print(
            json.dumps(
                {
                    "report_id": report_id,
                    "cases": len(cases),
                    "oracle_mismatches": mismatches,
                    "mode": report["mode"],
                }
            )
        )
        return int(mismatches > 0)
    except (ContractError, OSError, ValueError) as error:
        # Do not print exception text: path/input/SQLite errors may contain private submitted values.
        print(
            json.dumps(
                {
                    "error": type(error).__name__,
                    "help": "Check docs/usage.md; outputs never overwrite existing paths.",
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
