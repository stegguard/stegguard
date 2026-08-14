# SPDX-License-Identifier: Apache-2.0
"""Resource-budget regressions for files controlled by an attacker."""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import time
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import pytest

from stegguard.detector import analyze_file, analyze_lsb_image
from stegguard.integrations import C2paToolValidator
from stegguard.limits import DEFAULT_SCAN_LIMITS, read_limited
from stegguard.operations import decode_file, sanitize_file
from stegguard.watermark import scan_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_bounded_reader_does_not_preallocate_the_entire_default_budget(tmp_path):
    source = tmp_path / "small.bin"
    source.write_bytes(b"small")

    tracemalloc.start()
    try:
        assert read_limited(source, DEFAULT_SCAN_LIMITS) == b"small"
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 2 * 1024 * 1024


def test_text_scan_memory_is_proportional_to_input_not_character_count(tmp_path):
    source = tmp_path / "ordinary.txt"
    source.write_bytes(b"ordinary text\n" * 8192)

    analyze_file(source)  # Warm imports before measuring parser allocations.
    tracemalloc.start()
    try:
        result = analyze_file(source)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result["error"] is None
    assert peak < 8 * 1024 * 1024


def test_text_offsets_are_raw_byte_offsets_for_utf8_and_latin1(tmp_path):
    utf8 = tmp_path / "utf8.txt"
    latin1 = tmp_path / "latin1.txt"
    utf8.write_bytes("é\u200b".encode("utf-8"))
    latin1.write_bytes(b"caf\xe9\xad")

    utf8_result = analyze_file(utf8)
    latin1_result = analyze_file(latin1)

    assert utf8_result["zero_width"][0].byte_off == 2
    assert latin1_result["zero_width"][0].byte_off == 4


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "stegguard", *arguments],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _png(width: int, height: int, decompressed: bytes) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            len(payload).to_bytes(4, "big")
            + kind
            + payload
            + (zlib.crc32(kind + payload) & 0xFFFFFFFF).to_bytes(4, "big")
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(decompressed))
        + chunk(b"IEND", b"")
    )


def test_watermark_scan_rejects_oversized_top_level_input(tmp_path):
    source = tmp_path / "oversized.bin"
    source.write_bytes(b"0123456789")

    with pytest.raises(ValueError, match="max_file_bytes"):
        scan_file(str(source), limits={"max_file_bytes": 4})


def test_detector_reports_resource_limit_as_incomplete_scan(tmp_path):
    source = tmp_path / "oversized.txt"
    source.write_bytes(b"0123456789")

    result = analyze_file(source, limits={"max_file_bytes": 4})

    assert "max_file_bytes" in result["error"]


def test_text_detector_stops_at_finding_limit(tmp_path):
    source = tmp_path / "many.txt"
    source.write_text("\u200b" * 10, encoding="utf-8", newline="")

    result = analyze_file(source, limits={"max_findings": 3})

    assert result["total_hidden"] == 3
    assert len(result["zero_width"]) == 3
    assert "max_findings" in result["error"]


def test_binary_detector_stops_at_finding_limit(tmp_path):
    source = tmp_path / "many.wasm"
    source.write_bytes("\u200b".encode("utf-8") * 10)

    result = analyze_file(source, limits={"max_findings": 3})

    assert result["total_hidden"] == 3
    assert len(result["binary_hits"]) == 3
    assert "max_findings" in result["error"]


def test_decode_and_sanitize_share_the_top_level_file_limit(tmp_path):
    source = tmp_path / "oversized.txt"
    source.write_bytes(b"0123456789")

    with pytest.raises(ValueError, match="max_file_bytes"):
        decode_file(source, limits={"max_file_bytes": 4})
    with pytest.raises(ValueError, match="max_file_bytes"):
        sanitize_file(source, limits={"max_file_bytes": 4})
    assert not (tmp_path / "oversized.sanitized.txt").exists()


@pytest.mark.parametrize("command", ["detect", "decode", "sanitize", "watermark"])
def test_cli_exposes_top_level_file_limit(command, tmp_path):
    source = tmp_path / "oversized.txt"
    source.write_bytes(b"0123456789")

    result = _run_cli(command, str(source), "--max-file-bytes", "4")

    assert result.returncode == 2
    assert "max_file_bytes exceeded" in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def test_lsb_scan_rejects_declared_pixel_count_before_allocation(tmp_path):
    source = tmp_path / "huge.png"
    source.write_bytes(_png(10, 10, b""))

    result = analyze_lsb_image(source, limits={"max_image_pixels": 10})

    assert "max_image_pixels" in result["error"]


def test_lsb_scan_uses_bounded_png_decompression(tmp_path):
    source = tmp_path / "compressed.png"
    source.write_bytes(_png(2, 2, b"\x00" + b"\x00" * 6 + b"\x00" + b"\x00" * 6))

    result = analyze_lsb_image(source, limits={"max_decompressed_bytes": 4})

    assert "max_decompressed_bytes" in result["error"]


def test_nested_archive_honors_member_and_total_byte_limits(tmp_path):
    source = tmp_path / "many.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("one.svg", "<svg/>")
        archive.writestr("two.svg", "<svg/>")

    result = scan_file(
        str(source),
        limits={"max_archive_members": 1, "max_decompressed_bytes": 1024},
    )

    assert len(result["nested_results"]) == 1
    assert any("member limit" in error.lower() for error in result["nested_scan_errors"])


def test_nested_archive_depth_is_bounded(tmp_path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("asset.svg", "<svg/>")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("inner.zip", inner.read_bytes())

    result = scan_file(str(outer), limits={"max_nesting_depth": 1})

    assert result["nested_results"][0]["path"] == "inner.zip"
    nested = result["nested_results"][0]["result"]
    assert any("depth limit" in error.lower() for error in nested["nested_scan_errors"])


def test_total_findings_are_bounded(tmp_path):
    source = tmp_path / "metadata.png"
    source.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + b"".join(
            len(payload).to_bytes(4, "big") + b"tEXt" + payload + b"\x00\x00\x00\x00"
            for payload in (b"a", b"b", b"c")
        )
    )

    result = scan_file(str(source), limits={"max_findings": 2})

    assert len(result["findings"]) == 2
    assert any("finding limit" in error.lower() for error in result["scan_errors"])


def test_scan_deadline_is_checked_after_configured_analyzer(tmp_path):
    source = tmp_path / "video.mp4"
    source.write_bytes(b"video")

    def slow_analyzer(path, content):
        time.sleep(0.01)
        return {"status": "NOT_DETECTED", "confidence": 0.0}

    with pytest.raises(ValueError, match="max_scan_seconds"):
        scan_file(
            str(source),
            media_analyzers={"VIDEO_ROBUST": slow_analyzer},
            limits={"max_scan_seconds": 0.001},
        )


def test_c2patool_launch_oserror_becomes_not_checked(tmp_path, monkeypatch):
    source = tmp_path / "asset.jpg"
    source.write_bytes(b"\xff\xd8\xff\xd9")
    monkeypatch.setattr(
        "stegguard.integrations.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("not executable")),
    )

    result = C2paToolValidator("c2patool").validate_file(source)

    assert result["status"] == "NOT_CHECKED"
    assert "not executable" in json.dumps(result["validation_errors"])
