"""Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 35
# variable: BEGIN — line 36
# variable: END — line 36
# variable: SPECIAL — line 37
# definition: purpose — line 61
# parameter: name — line 61
# variable: text — line 65
# variable: lines — line 70
# variable: index — line 71
# variable: line — line 71
# variable: description — line 73
# variable: continuation — line 75
# variable: description — line 81
# definition: main — line 86
# variable: parser — line 88
# variable: args — line 90
# variable: names — line 91
# variable: rows — line 99
# variable: name — line 100
# variable: label — line 101
# variable: path — line 103
# variable: original — line 104
# variable: end — line 105
# variable: start — line 105
# variable: expected — line 106
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN FILE GUIDE -->", "<!-- END FILE GUIDE -->"
SPECIAL = {
    "docs/reports/windows-application-guide-1.1.1.docx": "Reviewed current 1.1.1 installed-app guide: actual screenshots, workflow, immutable code and measured limits.",
    "docs/reports/windows-application-guide-1.1.1.json": "Current Word, screenshot, source and individually reviewed rendered-page hashes.",
    "requirements-native.lock": "Exact hash-locked Windows portable build graph; no runtime setup/download on user launch.",
    "docs/licenses/tcl-9.0.4.txt": "Verbatim Tcl9.0.4 notice read from the actual verified Windows runtime zipfs.",
    "docs/licenses/tk-9.0.4.txt": "Verbatim Tk9.0.4 notice read from the actual verified Windows runtime zipfs.",
    "examples/desktop/baseline.jsonl": "Authored same-case baseline responses; fictional identity, not outputs from a live model.",
    "examples/desktop/candidate.jsonl": "Authored same-case unsafe-allow and benign-completion regression responses, data only.",
    "examples/desktop/partial.jsonl": "Authored missing/timeout observations that lower paired denominators and remain inconclusive.",
    "docs/reports/project-guide.docx": "Reviewed source-bound Word guide with dated validation observations and practical limits.",
    "docs/reports/publications.json": "Exact publication hashes, reviewed page identities and source/evidence baselines.",
    ".gitignore": "Exclude private diagnostics, builds, environments and generated fuzz artifacts.",
    ".gitattributes": "Consistent LF text checkouts across operating systems.",
    "LICENSE": "MIT license for Jason Stys's authored code.",
    "requirements-dev.lock": "Universal full hash-locked Python development graph.",
    "data/cases.jsonl": "Authored synthetic contexts, untrusted messages, proposed responses and policy oracles.",
    "data/manifest.json": "Exact corpus bytes, SHA256 and authorship metadata.",
    "docs/reports/evaluation.json": "Actual baseline versus enforced-policy synthetic outcomes with denominators.",
    "tools.lock.json": "Official Linux scanner versions, URLs and SHA256 digests.",
    "docs/reports/ci.json": "Immutable accepted-source CI snapshot, not a future guarantee.",
    "docs/reports/benchmark.json": "Measured bounded offline evaluation timing and memory, not model latency.",
}


def purpose(name: str) -> str:
    """Read the authored module/header/title purpose or explicit noncommentable-file description."""
    if name in SPECIAL:
        return SPECIAL[name]
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".py"):
        return (ast.get_docstring(ast.parse(text)) or "").splitlines()[0]
    if name.endswith(".md"):
        return text.splitlines()[0].lstrip("# ") + "."
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "Jason Stys:" in line:
            description = line.lstrip("#!/- ")
            if name.endswith((".cpp", ".hpp", ".rs")):
                for continuation in lines[index + 1 :]:
                    if (
                        not continuation.startswith("//")
                        or "BEGIN CODE MAP" in continuation
                    ):
                        break
                    description += " " + continuation.lstrip("/! ")
            return description
    raise ValueError("Tracked-file purpose missing: " + name)


def main() -> None:
    """Generate/check an exact full tracked-file table after staging only reviewed nonprivate files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if names == [""]:
        raise ValueError("Stage reviewed files first")
    rows = ["| File | Purpose |", "| --- | --- |"]
    for name in sorted(names):
        label = name.replace("_", "\\_")
        rows.append(f"| [{label}]({name}) | {purpose(name).replace('|', '/')} |")
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    start, end = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:start] + "\n\n" + "\n".join(rows) + "\n\n" + original[end:]
    if args.check and expected != original:
        raise ValueError("README file guide stale")
    if not args.check:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README complete inventory: {len(names)}")


if __name__ == "__main__":
    main()
