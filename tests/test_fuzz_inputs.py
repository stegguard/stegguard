# SPDX-License-Identifier: Apache-2.0
"""Property checks for malformed attacker-controlled format inputs."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from stegguard.detector import analyze_file
from stegguard.watermark import scan_file


@pytest.mark.parametrize(
    "extension",
    [".png", ".gif", ".bmp", ".zip", ".docx", ".pdf", ".wav", ".mp4", ".jpg"],
)
@settings(
    max_examples=12,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(payload=st.binary(max_size=1024))
def test_malformed_formats_do_not_escape_public_scan_apis(
    tmp_path: Path, extension: str, payload: bytes
):
    source = tmp_path / f"malformed{extension}"
    source.write_bytes(payload)

    detector = analyze_file(source, limits={"max_file_bytes": 2048})
    watermark = scan_file(str(source), limits={"max_file_bytes": 2048})

    assert detector["file"] == str(source)
    assert watermark["file"] == str(source)
    assert isinstance(watermark["findings"], list)
