# SPDX-License-Identifier: Apache-2.0
"""Regression tests for reliability and automation contracts."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import stegguard.detector as detector
from stegguard import __version__
from stegguard.common import use_utf8_output
from stegguard.reporting import atomic_write_text


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "stegguard", *arguments],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=30,
    )


def test_extensionless_dockerfile_is_scanned():
    assert detector.file_matches(Path("Dockerfile"), detector.TEXT_EXTENSIONS)


def test_webassembly_is_routed_to_binary_scanner(tmp_path):
    source = tmp_path / "module.wasm"
    source.write_bytes(b"\xff\xe2\x80\x8b")

    result = detector.analyze_file(source)

    assert result["file_mode"] == "binary"
    assert result["total_hidden"] == 1


def test_terminal_summary_counts_lsb_only_findings(tmp_path, monkeypatch, capsys):
    source = tmp_path / "image.png"
    source.write_bytes(b"not-used")
    result = {
        "file": str(source),
        "file_mode": "binary",
        "zero_width": [],
        "homoglyphs": [],
        "other_suspicious": [],
        "trailing_whitespace_lines": [],
        "binary_hits": [],
        "mixed_line_endings": False,
        "total_hidden": 0,
        "error": None,
        "lsb_analysis": {"suspicious_channels": ["R"]},
        "watermark": {"findings": [], "provenance": {"status": "MISSING"}},
    }
    monkeypatch.setattr(detector, "analyze_file", lambda *args, **kwargs: result)
    monkeypatch.setattr(detector, "print_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(sys, "argv", ["stegguard-detect", str(source)])

    exit_code = detector.main()

    assert exit_code == 1
    assert "1/1 file(s) flagged" in capsys.readouterr().out


def test_python_module_uses_documented_scan_exit_codes(tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_text("plain text\n", encoding="utf-8", newline="")
    suspicious = tmp_path / "suspicious.txt"
    suspicious.write_text("hidden\u200btext\n", encoding="utf-8", newline="")
    missing = tmp_path / "missing.txt"

    assert _run_cli("detect", str(clean)).returncode == 0
    assert _run_cli("detect", str(suspicious)).returncode == 1
    assert _run_cli("detect", str(missing)).returncode == 2


def test_detector_options_are_forwarded_before_the_input_path(tmp_path):
    suspicious = tmp_path / "suspicious.txt"
    suspicious.write_text("hidden\u200btext\n", encoding="utf-8", newline="")

    result = _run_cli("detect", "-r", str(suspicious))

    assert result.returncode == 1
    assert "1/1 file(s) flagged" in result.stdout
    assert "unrecognized arguments" not in result.stderr


def test_detector_subcommand_exposes_version():
    result = _run_cli("detect", "--version")

    assert result.returncode == 0
    assert result.stdout.strip() == f"stegguard {__version__}"


def test_concurrent_report_writes_leave_one_complete_document(tmp_path):
    output = tmp_path / "report.json"
    documents = [json.dumps({"writer": index, "payload": "x" * 10000}) for index in range(8)]

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda document: atomic_write_text(output, document), documents))

    observed = output.read_text(encoding="utf-8")
    assert observed in documents
    assert json.loads(observed)["writer"] in range(8)
    assert not list(tmp_path.glob(".report.json.*"))


def test_failed_atomic_report_replacement_preserves_existing_output(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    output.write_text('{"state":"old"}', encoding="utf-8")
    monkeypatch.setattr(
        "stegguard.reporting.os.replace",
        lambda *args: (_ for _ in ()).throw(OSError("replacement interrupted")),
    )

    try:
        atomic_write_text(output, '{"state":"new"}')
    except OSError as exc:
        assert "interrupted" in str(exc)
    else:
        raise AssertionError("atomic report replacement unexpectedly succeeded")

    assert output.read_text(encoding="utf-8") == '{"state":"old"}'
    assert not list(tmp_path.glob(".report.json.*"))


def test_partial_scan_is_separate_from_clean_in_every_report(tmp_path, monkeypatch, capsys):
    source = tmp_path / "partial.zip"
    source.write_bytes(b"not-used")
    result = {
        "file": str(source),
        "file_mode": "binary",
        "zero_width": [],
        "homoglyphs": [],
        "other_suspicious": [],
        "trailing_whitespace_lines": [],
        "binary_hits": [],
        "mixed_line_endings": False,
        "total_hidden": 0,
        "error": None,
        "lsb_analysis": None,
        "watermark": {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "scan_errors": [],
            "nested_scan_errors": ["Nested member limit reached."],
        },
    }
    json_report = tmp_path / "partial.json"
    html_report = tmp_path / "partial.html"

    detector.write_json_output([result], str(json_report))
    detector.generate_html_report([result], str(html_report))
    assert json.loads(json_report.read_text(encoding="utf-8"))["incomplete_files"] == 1
    assert "Incomplete Files" in html_report.read_text(encoding="utf-8")

    monkeypatch.setattr(detector, "analyze_file", lambda *args, **kwargs: result)
    monkeypatch.setattr(sys, "argv", ["stegguard-detect", str(source)])
    assert detector.main() == 2
    terminal = capsys.readouterr().out
    assert "incomplete; not clean" in terminal
    assert "All 1 file(s) clean" not in terminal


def test_cli_writes_utf8_when_the_console_encoding_is_cp1252(tmp_path):
    source = tmp_path / "hidden.txt"
    source.write_text("a\u200bb\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "stegguard", "decode", str(source)],
        cwd=PROJECT_ROOT,
        env={**os.environ, "PYTHONIOENCODING": "cp1252"},
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert b"UnicodeEncodeError" not in result.stderr
    assert json.loads(result.stdout.decode("utf-8"))["file"] == str(source)


def test_use_utf8_output_switches_non_utf8_streams_to_utf8(monkeypatch):
    stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    stderr = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    use_utf8_output()
    stdout.write("\u200b\u2713")
    stdout.flush()

    assert stdout.encoding == "utf-8"
    assert stderr.encoding == "utf-8"
    assert stdout.buffer.getvalue() == "\u200b\u2713".encode("utf-8")


def test_use_utf8_output_leaves_streams_without_reconfigure_untouched(monkeypatch):
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)

    use_utf8_output()
    print("\u200b", end="")

    assert sys.stdout is stdout
    assert stdout.getvalue() == "\u200b"


def _flaky_replace(failures: int, calls: list):
    real_replace = os.replace

    def replace(source, destination):
        calls.append(destination)
        if len(calls) <= failures:
            raise PermissionError("destination is being replaced")
        real_replace(source, destination)

    return replace


def test_atomic_write_retries_transient_windows_replace_conflicts(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    calls: list = []
    sleeps: list = []
    monkeypatch.setattr("stegguard.reporting._IS_WINDOWS", True)
    monkeypatch.setattr("stegguard.reporting.os.replace", _flaky_replace(2, calls))
    monkeypatch.setattr("stegguard.reporting.time.sleep", sleeps.append)

    atomic_write_text(output, '{"state":"new"}')

    assert output.read_text(encoding="utf-8") == '{"state":"new"}'
    assert len(calls) == 3
    assert sleeps == [0.01, 0.02]
    assert not list(tmp_path.glob(".report.json.*"))


def test_atomic_write_gives_up_after_ten_windows_replace_conflicts(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    output.write_text('{"state":"old"}', encoding="utf-8")
    calls: list = []
    monkeypatch.setattr("stegguard.reporting._IS_WINDOWS", True)
    monkeypatch.setattr("stegguard.reporting.os.replace", _flaky_replace(10, calls))
    monkeypatch.setattr("stegguard.reporting.time.sleep", lambda seconds: None)

    with pytest.raises(PermissionError):
        atomic_write_text(output, '{"state":"new"}')

    assert len(calls) == 10
    assert output.read_text(encoding="utf-8") == '{"state":"old"}'
    assert not list(tmp_path.glob(".report.json.*"))


def test_atomic_write_does_not_retry_permission_errors_off_windows(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    calls: list = []
    monkeypatch.setattr("stegguard.reporting._IS_WINDOWS", False)
    monkeypatch.setattr("stegguard.reporting.os.replace", _flaky_replace(1, calls))

    with pytest.raises(PermissionError):
        atomic_write_text(output, '{"state":"new"}')

    assert len(calls) == 1
    assert not output.exists()
