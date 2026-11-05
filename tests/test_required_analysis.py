# SPDX-License-Identifier: Apache-2.0
"""Analysis that should have run but failed must never produce a clean verdict."""

from __future__ import annotations

import io
import json
import re
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import stegguard.detector as detector
from stegguard.cli import main as cli_main
from stegguard.watermark import scan_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def _png(width: int = 32, height: int = 32, interlace: int = 0) -> bytes:
    row = b"\x00" + bytes((x * 7) % 256 for x in range(width * 3))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, interlace))
        + _png_chunk(b"IDAT", zlib.compress(row * height))
        + _png_chunk(b"IEND", b"")
    )


def _detect(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "stegguard", "detect", *arguments],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=60,
        check=False,
    )


def _html_summary_count(html: str, label: str) -> int:
    found = re.search(rf'<div class="sn">(\d+)</div><div class="sl">{label}</div>', html)
    assert found, f"HTML summary has no {label} tile"
    return int(found.group(1))


def _result(**overrides: object) -> dict:
    result = {
        "file": "sample.bin",
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
        "watermark": {"findings": [], "provenance": {"status": "NOT_CHECKED"}},
    }
    result.update(overrides)
    return result


def _raising_analyzer(_source, _raw):
    raise RuntimeError("analyzer crashed")


def test_malformed_png_exits_two_and_explains_why_in_every_report(tmp_path):
    source = tmp_path / "bad.png"
    source.write_bytes(b"not a png")
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    completed = _detect(str(source), "--json", str(json_path), "--html", str(html_path))

    report = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")
    assert completed.returncode == 2
    assert "LSB analysis: Could not decode pixel data" in completed.stdout
    assert "1/1 file(s) incomplete" in completed.stdout
    assert report["incomplete_files"] == 1
    assert report["clean_files"] == 0
    assert report["flagged_files"] == 0
    assert report["results"][0]["incomplete_reasons"][0].startswith(
        "LSB analysis: Could not decode pixel data"
    )
    assert _html_summary_count(html, "Incomplete Files") == 1
    assert "<li>LSB analysis: Could not decode pixel data" in html


def test_malformed_png_is_not_described_as_clean_in_terminal_output(tmp_path):
    source = tmp_path / "bad.png"
    source.write_bytes(b"not a png")

    completed = _detect(str(source))

    assert "✓" not in completed.stdout
    assert "All 1 file(s) clean" not in completed.stdout


def test_pixel_limit_exhaustion_exits_two_and_names_the_limit(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(_png())

    completed = _detect(str(source), "--max-image-pixels", "10")

    assert completed.returncode == 2
    assert "LSB analysis:" in completed.stdout
    assert "max_image_pixels" in completed.stdout


def test_decompression_limit_exhaustion_exits_two_and_names_the_limit(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(_png())

    completed = _detect(str(source), "--max-decompressed-bytes", "100")

    assert completed.returncode == 2
    assert "LSB analysis:" in completed.stdout
    assert "max_decompressed_bytes" in completed.stdout


def test_valid_png_with_completed_analysis_exits_zero(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(_png())
    json_path = tmp_path / "report.json"

    completed = _detect(str(source), "--json", str(json_path))

    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert completed.returncode == 0
    assert report["incomplete_files"] == 0
    assert report["results"][0]["incomplete_reasons"] == []


def test_image_format_the_builtin_decoder_cannot_read_is_incomplete_and_suggests_pillow(
    tmp_path, monkeypatch, capsys
):
    source = tmp_path / "interlaced.png"
    source.write_bytes(_png(interlace=1))
    monkeypatch.setattr(detector, "_HAS_PIL", False)
    monkeypatch.setattr(sys, "argv", ["stegguard-detect", str(source)])

    assert detector.main() == 2
    assert "install Pillow for wider support" in capsys.readouterr().out


def test_absent_optional_analyzer_exits_zero_and_is_reported_as_not_checked(tmp_path):
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom")
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    completed = _detect(str(source), "--json", str(json_path), "--html", str(html_path))

    report = json.loads(json_path.read_text(encoding="utf-8"))
    note = "Not checked: No VIDEO_ROBUST analyzer is configured for .mp4."
    assert completed.returncode == 0
    assert note in completed.stdout
    assert report["incomplete_files"] == 0
    assert report["results"][0]["watermark"]["robust_media"]["VIDEO_ROBUST"]["status"] == (
        "NOT_CHECKED"
    )
    assert note in html_path.read_text(encoding="utf-8")


def test_unconfigured_ai_text_verifier_does_not_make_a_text_scan_incomplete(tmp_path):
    source = tmp_path / "notes.txt"
    source.write_text("plain text\n", encoding="utf-8")

    completed = _detect(str(source))

    assert completed.returncode == 0
    assert "All 1 file(s) clean" in completed.stdout


def test_failing_robust_analyzer_marks_the_result_incomplete(tmp_path):
    source = tmp_path / "clip.mp4"
    source.write_bytes(b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom")

    watermark = scan_file(str(source), media_analyzers={"VIDEO_ROBUST": _raising_analyzer})
    result = _result(watermark=watermark)

    assert detector.watermark_scan_errors(watermark) == [
        "VIDEO_ROBUST analyzer failed: analyzer crashed"
    ]
    assert detector.result_is_incomplete(result) is True
    assert detector.result_is_flagged(result) is False
    assert detector.scan_exit_code([result]) == 2


def test_failing_robust_analyzer_on_a_nested_member_is_labeled_with_its_path(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("media/image.png", _png())
    source = tmp_path / "container.zip"
    source.write_bytes(buffer.getvalue())

    watermark = scan_file(str(source), media_analyzers={"IMAGE_ROBUST": _raising_analyzer})

    assert detector.watermark_scan_errors(watermark) == [
        "media/image.png: IMAGE_ROBUST analyzer failed: analyzer crashed"
    ]


def test_analyzer_error_without_a_message_still_marks_the_result_incomplete():
    watermark = {"robust_media": {"IMAGE_ROBUST": {"status": "ERROR", "errors": []}}}

    assert detector.watermark_scan_errors(watermark) == [
        "IMAGE_ROBUST analyzer failed: no reason given"
    ]


def test_failing_ai_text_verifier_marks_the_result_incomplete(tmp_path):
    source = tmp_path / "notes.txt"
    source.write_text("plain text\n", encoding="utf-8")

    def verifier(_text, path):
        raise RuntimeError("verifier crashed")

    watermark = scan_file(str(source), ai_text_verifier=verifier)

    assert detector.watermark_scan_errors(watermark) == [
        "AI text verifier failed: verifier crashed"
    ]
    assert detector.scan_exit_code([_result(watermark=watermark)]) == 2


def test_analyzer_that_reports_no_detection_does_not_mark_the_result_incomplete():
    watermark = {
        "robust_media": {"IMAGE_ROBUST": {"status": "NOT_DETECTED", "errors": []}},
        "ai_text_watermark": {"status": "NOT_CHECKED", "errors": ["No verifier."]},
    }

    assert detector.watermark_scan_errors(watermark) == []


def test_hashing_failure_for_json_report_exits_two_and_is_not_counted_as_flagged(
    tmp_path, monkeypatch, capsys
):
    source = tmp_path / "sample.txt"
    source.write_text("plain\n", encoding="utf-8")
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    missing = str(tmp_path / "removed-after-scan.txt")
    monkeypatch.setattr(detector, "analyze_file", lambda *a, **k: _result(file=missing))
    monkeypatch.setattr(
        sys,
        "argv",
        ["stegguard-detect", str(source), "--json", str(json_path), "--html", str(html_path)],
    )

    assert detector.main() == 2

    report = json.loads(json_path.read_text(encoding="utf-8"))
    terminal = capsys.readouterr().out
    assert report["incomplete_files"] == 1
    assert report["flagged_files"] == 0
    assert report["results"][0]["sha256"] == ""
    assert report["results"][0]["error"].startswith("Could not hash file for report:")
    assert "Could not hash file for report:" in terminal
    assert "All 1 file(s) clean" not in terminal
    assert _html_summary_count(html_path.read_text(encoding="utf-8"), "Incomplete Files") == 1


def test_hashing_is_not_attempted_when_the_scan_already_has_an_error():
    result = _result(file="/no/such/file", error="Permission denied")

    serialized = detector.result_to_json_dict(result)

    assert serialized["sha256"] == ""
    assert serialized["error"] == "Permission denied"
    assert serialized["incomplete_reasons"] == ["Permission denied"]


def test_json_report_records_the_sha256_of_a_readable_file(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"abc")

    serialized = detector.result_to_json_dict(_result(file=str(source)))

    assert serialized["sha256"] == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert serialized["error"] is None


def test_per_folder_mode_reports_incomplete_folders_and_exits_two(tmp_path):
    root = tmp_path / "scan"
    (root / "broken").mkdir(parents=True)
    (root / "broken" / "bad.png").write_bytes(b"not a png")
    out_dir = tmp_path / "reports"
    json_path = tmp_path / "report.json"
    combined = tmp_path / "combined.html"

    completed = _detect(
        str(root),
        "-r",
        "--html-per-folder",
        str(out_dir),
        "--json",
        str(json_path),
        "--html",
        str(combined),
    )

    assert completed.returncode == 2
    assert "1 incomplete" in completed.stdout
    assert "1 folder(s) incomplete; not clean" in completed.stdout
    assert "All folders clean" not in completed.stdout
    assert json.loads(json_path.read_text(encoding="utf-8"))["incomplete_files"] == 1
    assert _html_summary_count(combined.read_text(encoding="utf-8"), "Incomplete Files") == 1
    assert (
        _html_summary_count(
            (out_dir / "broken.html").read_text(encoding="utf-8"), "Incomplete Files"
        )
        == 1
    )


def test_per_folder_mode_scans_each_file_once_for_all_reports(tmp_path, monkeypatch):
    root = tmp_path / "scan"
    (root / "folder").mkdir(parents=True)
    source = root / "folder" / "notes.txt"
    source.write_text("plain\n", encoding="utf-8")
    calls: list[Path] = []
    original = detector.analyze_file

    def counting(path, *args, **kwargs):
        calls.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(detector, "analyze_file", counting)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "stegguard-detect",
            str(root),
            "-r",
            "--html-per-folder",
            str(tmp_path / "reports"),
            "--json",
            str(tmp_path / "report.json"),
            "--html",
            str(tmp_path / "combined.html"),
        ],
    )

    assert detector.main() == 0
    assert calls == [source]


def test_per_folder_mode_reports_clean_folders_as_clean(tmp_path):
    root = tmp_path / "scan"
    (root / "folder").mkdir(parents=True)
    (root / "folder" / "notes.txt").write_text("plain\n", encoding="utf-8")

    completed = _detect(str(root), "-r", "--html-per-folder", str(tmp_path / "reports"))

    assert completed.returncode == 0
    assert "All folders clean" in completed.stdout


def test_lsb_error_is_escaped_in_the_html_report(tmp_path):
    report = tmp_path / "report.html"
    lsb = {"error": "<script>alert(1)</script>", "verdict": "UNKNOWN", "suspicious_channels": []}

    detector.generate_html_report([_result(lsb_analysis=lsb)], str(report))

    assert "<script>alert(1)</script>" not in report.read_text(encoding="utf-8")


def test_watermark_command_exits_two_when_a_nested_scan_stops_early(tmp_path, capsys):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("page.html", b"<html></html>")
    source = tmp_path / "container.zip"
    source.write_bytes(buffer.getvalue())

    assert cli_main(["watermark", str(source), "--max-nesting-depth", "1"]) == 2
    assert "Nested depth limit reached." in capsys.readouterr().out


def test_watermark_command_exits_zero_on_a_completed_scan_with_findings(tmp_path, capsys):
    source = tmp_path / "hidden.svg"
    source.write_bytes(b'<svg><text style="display:none">hidden</text></svg>')

    assert cli_main(["watermark", str(source)]) == 0
    assert '"category": "LAYOUT"' in capsys.readouterr().out


def test_watermark_command_html_report_exits_two_when_image_analysis_fails(tmp_path, capsys):
    source = tmp_path / "bad.png"
    source.write_bytes(b"not a png")
    report = tmp_path / "report.html"

    assert cli_main(["watermark", str(source), "--html", str(report)]) == 2
    assert _html_summary_count(report.read_text(encoding="utf-8"), "Incomplete Files") == 1


def test_incomplete_text_scan_is_not_described_as_clean(capsys):
    result = _result(
        file_mode="text",
        watermark={"findings": [], "scan_errors": ["Finding limit reached."]},
    )

    detector.print_results(result)

    output = capsys.readouterr().out
    assert "No hidden characters found" in output
    assert "✓" not in output


def test_complete_text_scan_is_described_as_clean(capsys):
    detector.print_results(_result(file_mode="text"))

    assert "✓ Clean" in capsys.readouterr().out


def test_write_json_output_counts_a_hashing_failure_as_incomplete(tmp_path):
    report = tmp_path / "report.json"

    detector.write_json_output([_result(file=str(tmp_path / "missing.bin"))], str(report))

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["incomplete_files"] == 1
    assert payload["completed_files"] == 0
    assert payload["clean_files"] == 0
