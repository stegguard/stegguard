# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = PROJECT_ROOT / "demo"


def _run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(DEMO_ROOT / script), *args],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def test_create_samples_writes_deterministic_safe_fixtures(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_run = _run("create_samples.py", str(first))
    second_run = _run("create_samples.py", str(second))

    assert first_run.returncode == 0, first_run.stderr
    assert second_run.returncode == 0, second_run.stderr
    assert (first / "suspicious.txt").read_bytes() == (second / "suspicious.txt").read_bytes()
    assert (first / "watermarked.png").read_bytes() == (second / "watermarked.png").read_bytes()
    manifest = json.loads((first / "samples.json").read_text())
    assert manifest["safe_demo"] is True
    assert manifest["hidden_text"] == "DEMO"
    assert manifest["samples"] == ["suspicious.txt", "watermarked.png"]


def test_run_demo_exercises_real_cli_and_preserves_original(tmp_path):
    output = tmp_path / "demo-output"

    result = _run("run_demo.py", "--output", str(output), "--no-color")

    assert result.returncode == 0, result.stderr
    assert "Demo completed successfully" in result.stdout
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "PASS"
    assert summary["network_used"] is False
    assert summary["original_preserved"] is True
    assert summary["decoded_zero_width"] == "DEMO"
    assert summary["sanitized_changed"] is True
    assert summary["sanitized_zero_width_occurrences"] == 0
    assert summary["sanitized_total_hidden"] == 0

    expected_reports = {
        "detect.json",
        "detect.html",
        "decode.json",
        "sanitize.json",
        "sanitized-detect.json",
        "watermark.json",
        "watermark.html",
    }
    assert expected_reports <= {path.name for path in (output / "reports").iterdir()}
    assert "<!DOCTYPE html>" in (output / "reports" / "detect.html").read_text()
    assert "<!DOCTYPE html>" in (output / "reports" / "watermark.html").read_text()

    suspicious = output / "samples" / "suspicious.txt"
    assert hashlib.sha256(suspicious.read_bytes()).hexdigest() == summary["original_sha256"]
    assert summary["original_sha256"] != summary["sanitized_sha256"]


def test_run_demo_refuses_to_overwrite_nonempty_output(tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep me")

    result = _run("run_demo.py", "--output", str(output))

    assert result.returncode == 2
    assert "not empty" in result.stderr
    assert marker.read_text() == "keep me"
