# SPDX-License-Identifier: Apache-2.0
"""Portable filesystem contracts for unusual but valid inputs."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from stegguard.detector import analyze_file
from stegguard.operations import sanitize_file


def test_unicode_and_long_filename_round_trip(tmp_path: Path):
    source = tmp_path / (("long-name-" * 18) + "数据.txt")
    source.write_text("visible\u200btext", encoding="utf-8")

    result = analyze_file(source)
    sanitized = sanitize_file(source)

    assert result["total_hidden"] == 1
    assert Path(sanitized["sanitized_path"]).read_text(encoding="utf-8") == "visibletext"


def test_scanning_a_file_symlink_reads_the_target(tmp_path: Path):
    target = tmp_path / "target.txt"
    link = tmp_path / "alias.txt"
    target.write_text("visible\u200btext", encoding="utf-8")
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    result = analyze_file(link)

    assert result["total_hidden"] == 1
    assert result["file"] == str(link)


@pytest.mark.skipif(os.name == "nt", reason="POSIX read-only mode is not portable")
def test_read_only_input_can_be_scanned_and_sanitized_to_a_copy(tmp_path: Path):
    source = tmp_path / "readonly.txt"
    source.write_text("visible\u200btext", encoding="utf-8")
    source.chmod(0o444)

    try:
        assert analyze_file(source)["total_hidden"] == 1
        result = sanitize_file(source)
        assert Path(result["sanitized_path"]).read_text(encoding="utf-8") == "visibletext"
    finally:
        source.chmod(0o644)
