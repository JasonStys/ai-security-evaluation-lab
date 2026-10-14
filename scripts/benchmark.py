"""Jason Stys: measure reproducible offline boundary-evaluation latency and Python allocation peaks, not model throughput."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 28
# definition: main — line 34
# variable: cases — line 36
# variable: sha — line 36
# variable: samples — line 38
# variable: _ — line 39
# variable: start — line 40
# variable: report — line 41
# variable: row — line 43
# variable: _ — line 47
# variable: peak — line 47
# variable: result — line 49
# variable: output — line 62
# END CODE MAP

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aisec.contracts import load_cases  # noqa: E402
from aisec.evaluate import run  # noqa: E402


def main() -> None:
    """Warm up then sample twenty complete paired evaluations; record environment and all measured samples."""
    cases, sha = load_cases(ROOT / "data/cases.jsonl")
    run(cases, sha)
    samples = []
    for _ in range(20):
        start = time.perf_counter()
        report = run(cases, sha)
        samples.append((time.perf_counter() - start) * 1000)
        if not all(row["oracle_match"] for row in report["cases"]):
            raise RuntimeError("performance result rejected: correctness drift")
    tracemalloc.start()
    run(cases, sha)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result = {
        "author": "Jason Stys",
        "scope": "synthetic replay; no model/network/disk timing",
        "corpus_sha256": sha,
        "python": platform.python_version(),
        "platform": platform.system(),
        "cases_per_sample": len(cases),
        "samples_ms": samples,
        "median_ms": statistics.median(samples),
        "max_ms": max(samples),
        "python_peak_allocated_bytes": peak,
        "correctness": "all reviewed policy oracles matched",
    }
    output = ROOT / "out"
    output.mkdir(exist_ok=True)
    (output / "benchmark.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
