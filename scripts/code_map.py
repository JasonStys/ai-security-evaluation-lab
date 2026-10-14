"""Jason Stys: exact Python AST definition/parameter/variable maps and SQL/workflow declaration line indexes."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 46
# definition: mapped — line 49
# parameter: source — line 49
# parameter: suffix — line 49
# variable: prefix — line 51
# variable: begin — line 52
# variable: end — line 52
# variable: source — line 53
# variable: lines — line 59
# variable: records — line 60
# variable: insertion — line 61
# variable: tree — line 63
# variable: insertion — line 66
# variable: node — line 67
# variable: insertion — line 80
# variable: line — line 81
# variable: number — line 81
# variable: name — line 84
# variable: name — line 86
# variable: name — line 88
# variable: count — line 90
# variable: header — line 91
# variable: kind — line 95
# variable: name — line 95
# variable: number — line 95
# parameter: item — line 96
# definition: main — line 105
# variable: parser — line 107
# variable: args — line 109
# variable: paths — line 110
# variable: stale — line 117
# variable: path — line 118
# variable: source — line 119
# variable: expected — line 120
# END CODE MAP

from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mapped(source: str, suffix: str) -> str:
    """Insert physical line maps without executing source; SQL/YAML indexes are lexical, Python is AST-based."""
    prefix = "--" if suffix == ".sql" else "#"
    begin, end = prefix + " BEGIN CODE MAP", prefix + " END CODE MAP"
    source = re.sub(
        r"^" + re.escape(begin) + r"[^\n]*\n.*?^" + re.escape(end) + r"\n",
        "",
        source,
        flags=re.M | re.S,
    )
    lines = source.splitlines(keepends=True)
    records: set[tuple[str, str, int]] = set()
    insertion = 0
    if suffix == ".py":
        tree = ast.parse(source)
        if not ast.get_docstring(tree):
            raise ValueError("missing file purpose header")
        insertion = tree.body[0].end_lineno or 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not ast.get_docstring(node):
                    raise ValueError("missing function/class description: " + node.name)
                records.add(("definition", node.name, node.lineno))
            elif isinstance(node, ast.arg):
                records.add(("parameter", node.arg, node.lineno))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                records.add(("variable", node.id, node.lineno))
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                records.add(("attribute", node.attr, node.lineno))
    else:
        while insertion < len(lines) and lines[insertion].startswith(prefix):
            insertion += 1
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith(prefix):
                continue
            for name in re.findall(r"CREATE (?:TABLE|TRIGGER|INDEX) (\w+)", line):
                records.add(("SQL object", name, number))
            for name in re.findall(r"\b(\w+) (?:INTEGER|TEXT|BLOB)\b", line):
                records.add(("column", name, number))
            for name in re.findall(r"^\s*(?:- )?([\w-]+):", line):
                records.add(("parameter", name, number))
    count = len(records) + 2
    header = [
        begin + " (generated; python scripts/code_map.py)",
        *[
            f"{prefix} {kind}: {name} — line {number + count if number > insertion else number}"
            for kind, name, number in sorted(
                records, key=lambda item: (item[2], item[0], item[1])
            )
        ],
        end,
    ]
    lines.insert(insertion, "\n".join(header) + "\n")
    return "".join(lines)


def main() -> int:
    """Generate or check every authored Python, SQL and workflow header; drift or missing descriptions fail CI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    paths = [
        *(ROOT / "aisec").glob("*.py"),
        *(ROOT / "scripts").glob("*.py"),
        *(ROOT / "tests").glob("*.py"),
        *(ROOT / "sql").glob("*.sql"),
        *(ROOT / ".github/workflows").glob("*.yml"),
    ]
    stale = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        expected = mapped(source, path.suffix)
        if source != expected:
            stale.append(str(path.relative_to(ROOT)))
            if not args.check:
                path.write_text(expected, encoding="utf-8", newline="\n")
    print("Code maps current" if not stale else "Code maps: " + ", ".join(stale))
    return int(args.check and bool(stale))


if __name__ == "__main__":
    raise SystemExit(main())
