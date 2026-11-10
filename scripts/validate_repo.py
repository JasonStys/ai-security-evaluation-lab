"""Jason Stys: tracked-source privacy, dependency/pin/cache policy, exact links and synthetic corpus provenance gates."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 38
# definition: main — line 44
# variable: names — line 46
# variable: name — line 61
# variable: path — line 62
# variable: text — line 65
# variable: target — line 70
# variable: action — line 80
# variable: word — line 84
# variable: codeql — line 90
# variable: cases — line 100
# variable: sha — line 100
# variable: raw — line 101
# variable: case — line 102
# variable: manifest — line 103
# variable: name — line 110
# variable: source — line 111
# variable: token — line 114
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

if __package__:
    from .publication_text import public_text
else:
    from publication_text import public_text

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
        text = public_text(path, ROOT)
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
