#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run deterministic detector time and allocation benchmarks."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from stegguard import __version__, analyze_file


def benchmark(size: int, repeat: int) -> dict[str, object]:
    elapsed: list[float] = []
    with tempfile.TemporaryDirectory(prefix="stegguard-benchmark-") as directory:
        source = Path(directory) / f"sample-{size}.txt"
        source.write_bytes((b"ordinary benchmark text\n" * ((size // 24) + 1))[:size])
        warmup = analyze_file(source)
        if warmup.get("error"):
            raise RuntimeError(warmup["error"])
        for _ in range(repeat):
            started = time.perf_counter()
            result = analyze_file(source)
            elapsed.append(time.perf_counter() - started)
            if result.get("error"):
                raise RuntimeError(result["error"])
        tracemalloc.start()
        try:
            result = analyze_file(source)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        if result.get("error"):
            raise RuntimeError(result["error"])
    return {
        "bytes": size,
        "repeat": repeat,
        "median_seconds": round(statistics.median(elapsed), 6),
        "peak_python_bytes": peak,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[1024, 1024 * 1024])
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    if args.repeat < 1 or any(size < 1 for size in args.sizes):
        parser.error("sizes and repeat must be positive")
    report = {
        "stegguard_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "results": [benchmark(size, args.repeat) for size in args.sizes],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
