"""Jason Stys: tracked-source privacy, dependency/pin/cache policy, exact links and synthetic corpus provenance gates."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 33
# definition: main — line 39
# variable: names — line 41
# variable: name — line 56
# variable: path — line 57
# variable: text — line 60
# variable: target — line 65
# variable: action — line 75
# variable: word — line 79
# variable: codeql — line 85
# variable: cases — line 95
# variable: sha — line 95
# variable: raw — line 96
# variable: case — line 97
# variable: manifest — line 98
# variable: name — line 105
# variable: source — line 106
# variable: token — line 109
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aisec.contracts import canonical, load_cases  # noqa: E402
from scripts.corpus import build  # noqa: E402


def main() -> None:
    """Validate all tracked text, no private state, SHA-pinned actions and zero Actions upload/cache configuration."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    assert names != [""]
    assert {
        "aisec/contracts.py",
        "aisec/boundary.py",
        "aisec/evaluate.py",
        "aisec/evidence.py",
        "aisec/cli.py",
        "sql/schema.sql",
    }.issubset(names)
    for name in names:
        path = ROOT / name
        assert path.is_file() and not name.startswith(("out/", ".venv/", ".tools/"))
        assert not re.search(r"\.(?:pem|key|env|sqlite)(?:$|[.-])", name)
        text = path.read_text(encoding="utf-8")
        assert not re.search(
            r"(?:ghp_|github_pat_)[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY", text
        )
        if name.endswith(".md"):
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if not target.startswith(("http:", "https:", "#", "mailto:")):
                    assert (path.parent / target.split("#")[0]).is_file(), (
                        name + ": " + target
                    )
        if name.startswith(".github/workflows/"):
            assert (
                "pull_request_target" not in text
                and "persist-credentials: false" in text
            )
            for action in re.findall(r"uses:\s*([^\s#]+)", text):
                assert re.fullmatch(r"[\w/.-]+@[a-f0-9]{40}", action)
                assert not any(
                    word in action
                    for word in (
                        "upload-artifact",
                        "download-artifact",
                        "actions/cache",
                    )
                )
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text()
    assert (
        "trap-caching: false" in codeql
        and "dependency-caching: false" in codeql
        and "upload-database: false" in codeql
    )
    assert not tomllib.loads((ROOT / "pyproject.toml").read_text())["project"][
        "dependencies"
    ]
    assert "--hash=sha256:" in (ROOT / "requirements-dev.lock").read_text()
    cases, sha = load_cases(ROOT / "data/cases.jsonl")
    raw = (ROOT / "data/cases.jsonl").read_bytes()
    assert raw == b"\n".join(canonical(case) for case in build()) + b"\n"
    manifest = json.loads((ROOT / "data/manifest.json").read_text())
    assert sha == manifest["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (
        len(cases) == manifest["cases"]
        and len(raw) == manifest["bytes"]
        and not manifest["model_executed"]
    )
    for name in ("aisec/boundary.py", "aisec/evaluate.py", "aisec/cli.py"):
        source = (ROOT / name).read_text()
        assert not any(
            token in source
            for token in (
                "import subprocess",
                "import requests",
                "import urllib",
                "eval(",
                "exec(",
            )
        )
    print(f"Privacy/pin/cache/link/corpus gates: {len(names)} tracked files passed")


if __name__ == "__main__":
    main()
