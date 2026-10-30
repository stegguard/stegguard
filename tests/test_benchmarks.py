# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
import subprocess
import sys

from stegguard import __version__


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = PROJECT_ROOT / "benchmarks" / "benchmark_scan.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BENCHMARK), *args],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=60,
    )


def test_benchmark_reports_one_result_per_requested_size():
    result = _run("--sizes", "64", "100", "--repeat", "2")

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["stegguard_version"] == __version__
    assert [entry["bytes"] for entry in report["results"]] == [64, 100]
    assert [entry["repeat"] for entry in report["results"]] == [2, 2]
    for entry in report["results"]:
        assert set(entry) == {"bytes", "repeat", "median_seconds", "peak_python_bytes"}
        assert entry["median_seconds"] >= 0
        assert entry["peak_python_bytes"] > 0


def test_benchmark_rejects_a_zero_repeat_count():
    result = _run("--sizes", "64", "--repeat", "0")

    assert result.returncode == 2
    assert "sizes and repeat must be positive" in result.stderr
    assert result.stdout == ""


def test_benchmark_rejects_a_zero_byte_size():
    result = _run("--sizes", "64", "0", "--repeat", "1")

    assert result.returncode == 2
    assert "sizes and repeat must be positive" in result.stderr
    assert result.stdout == ""
