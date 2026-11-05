# SPDX-License-Identifier: Apache-2.0
"""Nested container results must reach every verdict and report."""

from __future__ import annotations

import base64
import io
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import stegguard.detector as detector


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HIDDEN_SVG = b'<svg><text style="display:none">hidden</text></svg>'
BENIGN_SVG = b"<svg><text>visible</text></svg>"


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _html_embedding_svg(svg: bytes) -> bytes:
    """Nest without a zip in a zip, which is high risk at the top level on its own."""
    encoded = base64.b64encode(svg).decode()
    return f'<html><img src="data:image/svg+xml;base64,{encoded}"></html>'.encode()


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


def _reports(tmp_path: Path, source: Path) -> tuple[int, str, dict, str]:
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    completed = _detect(str(source), "--json", str(json_path), "--html", str(html_path))
    return (
        completed.returncode,
        completed.stdout,
        json.loads(json_path.read_text(encoding="utf-8")),
        html_path.read_text(encoding="utf-8"),
    )


def _html_summary_count(html: str, label: str) -> int:
    found = re.search(rf'<div class="sn">(\d+)</div><div class="sl">{label}</div>', html)
    assert found, f"HTML summary has no {label} tile"
    return int(found.group(1))


def _result_with_watermark(watermark: dict) -> dict:
    return {
        "file": "container.zip",
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
        "watermark": watermark,
    }


def _member(path: str, **result: object) -> dict:
    return {"container": "container.zip", "path": path, "result": result}


def test_nested_high_risk_finding_exits_one_and_is_flagged_in_json(tmp_path):
    source = tmp_path / "container.zip"
    source.write_bytes(_zip_bytes({"hidden.svg": HIDDEN_SVG}))

    exit_code, _, report, _ = _reports(tmp_path, source)

    assert exit_code == 1
    assert report["flagged_files"] == 1
    assert report["clean_files"] == 0
    assert report["incomplete_files"] == 0
    assert report["results"][0]["severity"] == "high"


def test_nested_high_risk_finding_is_counted_and_rendered_with_its_path_in_html(tmp_path):
    source = tmp_path / "container.zip"
    source.write_bytes(_zip_bytes({"hidden.svg": HIDDEN_SVG}))

    _, _, _, html = _reports(tmp_path, source)

    assert _html_summary_count(html, "Flagged Files") == 1
    assert 'data-sev="high"' in html
    assert "<td>hidden.svg</td>" in html
    assert "<td>LAYOUT</td>" in html


def test_nested_high_risk_finding_is_named_in_terminal_output_and_summary(tmp_path):
    source = tmp_path / "container.zip"
    source.write_bytes(_zip_bytes({"hidden.svg": HIDDEN_SVG}))

    completed = _detect(str(source))

    assert "hidden.svg: LAYOUT (high)" in completed.stdout
    assert "1/1 file(s) flagged" in completed.stdout
    assert "All 1 file(s) clean" not in completed.stdout


def test_deeply_nested_high_risk_finding_exits_one_and_reports_the_full_member_path(tmp_path):
    source = tmp_path / "container.zip"
    source.write_bytes(_zip_bytes({"page.html": _html_embedding_svg(HIDDEN_SVG)}))

    exit_code, stdout, report, html = _reports(tmp_path, source)

    member_path = "page.html > data-uri-1.svg"
    assert exit_code == 1
    assert report["flagged_files"] == 1
    assert report["results"][0]["severity"] == "high"
    assert _html_summary_count(html, "Flagged Files") == 1
    assert f"{member_path}: LAYOUT (high)" in stdout
    assert f"<td>{member_path.replace('>', '&gt;')}</td>" in html


def test_error_at_a_nested_level_exits_two_and_is_visible_in_every_report(tmp_path):
    source = tmp_path / "container.zip"
    source.write_bytes(_zip_bytes({"page.html": _html_embedding_svg(BENIGN_SVG)}))
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    completed = _detect(
        str(source),
        "--max-nesting-depth",
        "1",
        "--json",
        str(json_path),
        "--html",
        str(html_path),
    )

    report = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")
    error = "page.html: Nested depth limit reached."
    assert completed.returncode == 2
    assert error in completed.stdout
    assert "1/1 file(s) incomplete" in completed.stdout
    assert "All 1 file(s) clean" not in completed.stdout
    assert report["incomplete_files"] == 1
    assert report["completed_files"] == 0
    assert report["clean_files"] == 0
    nested = report["results"][0]["watermark"]["nested_results"][0]["result"]
    assert nested["nested_scan_errors"] == ["Nested depth limit reached."]
    assert _html_summary_count(html, "Incomplete Files") == 1
    assert f"<li>{error}</li>" in html


def test_incomplete_nested_scan_takes_precedence_over_a_nested_finding(tmp_path):
    source = tmp_path / "container.zip"
    page = _html_embedding_svg(BENIGN_SVG)
    source.write_bytes(_zip_bytes({"hidden.svg": HIDDEN_SVG, "page.html": page}))

    completed = _detect(str(source), "--max-nesting-depth", "1")

    assert completed.returncode == 2
    assert "hidden.svg: LAYOUT (high)" in completed.stdout
    assert "page.html: Nested depth limit reached." in completed.stdout


def test_informational_only_archive_exits_zero_and_stays_clean(tmp_path):
    source = tmp_path / "container.zip"
    source.write_bytes(_zip_bytes({"page.html": _html_embedding_svg(BENIGN_SVG)}))

    exit_code, stdout, report, html = _reports(tmp_path, source)

    assert exit_code == 0
    assert report["flagged_files"] == 0
    assert report["clean_files"] == 1
    assert report["results"][0]["severity"] == "clean"
    assert _html_summary_count(html, "Flagged Files") == 0
    assert "All 1 file(s) clean" in stdout


def test_informational_nested_finding_does_not_flag_the_container():
    result = _result_with_watermark(
        {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "nested_results": [
                _member(
                    "marked.png",
                    findings=[{"category": "METADATA", "risk": "informational"}],
                    provenance={"status": "NOT_CHECKED"},
                )
            ],
        }
    )

    assert detector.result_is_flagged(result) is False
    assert detector.scan_exit_code([result]) == 0


@pytest.mark.parametrize("status", ["TAMPERED", "UNTRUSTED_SIGNER"])
def test_nested_failed_provenance_flags_the_container(status):
    result = _result_with_watermark(
        {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "nested_results": [
                _member("signed.png", findings=[], provenance={"status": status}),
            ],
        }
    )

    assert detector.result_is_flagged(result) is True
    assert detector.result_to_json_dict(result)["severity"] == "high"
    assert detector.scan_exit_code([result]) == 1


@pytest.mark.parametrize("status", ["VALID", "MISSING", "UNSUPPORTED", "NOT_CHECKED"])
def test_nested_non_failing_provenance_does_not_flag_the_container(status):
    result = _result_with_watermark(
        {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "nested_results": [
                _member("signed.png", findings=[], provenance={"status": status}),
            ],
        }
    )

    assert detector.result_is_flagged(result) is False
    assert detector.scan_exit_code([result]) == 0


def test_nested_scan_errors_stage_marks_the_container_incomplete():
    result = _result_with_watermark(
        {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "nested_results": [
                _member(
                    "many.svg",
                    findings=[],
                    provenance={"status": "NOT_CHECKED"},
                    scan_errors=["Finding limit reached."],
                ),
            ],
        }
    )

    assert detector.result_is_incomplete(result) is True
    assert detector.scan_exit_code([result]) == 2
    assert detector.watermark_scan_errors(result["watermark"]) == [
        "many.svg: Finding limit reached."
    ]


def test_top_level_scan_errors_are_listed_without_a_member_prefix():
    watermark = {"scan_errors": ["Finding limit reached."], "nested_scan_errors": ["Bad archive."]}

    assert detector.watermark_scan_errors(watermark) == [
        "Finding limit reached.",
        "Bad archive.",
    ]


def test_malformed_nested_entries_do_not_affect_the_verdict():
    result = _result_with_watermark(
        {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "nested_results": ["not-a-member", {"path": "empty.svg", "result": None}],
        }
    )

    assert detector.result_is_flagged(result) is False
    assert detector.result_is_incomplete(result) is False


def test_nested_failed_provenance_is_named_in_terminal_output(capsys):
    result = _result_with_watermark(
        {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "nested_results": [
                _member("signed.png", findings=[], provenance={"status": "TAMPERED"}),
            ],
        }
    )

    detector.print_results(result)

    assert "signed.png: provenance TAMPERED" in capsys.readouterr().out


def test_terminal_output_neutralizes_control_characters_in_member_names(capsys):
    result = _result_with_watermark(
        {
            "findings": [],
            "provenance": {"status": "NOT_CHECKED"},
            "nested_results": [
                _member(
                    "evil\x1b[2J\u202e.svg",
                    findings=[{"category": "LAYOUT", "risk": "high"}],
                    provenance={"status": "NOT_CHECKED"},
                    nested_scan_errors=["bad\x1b[2J"],
                ),
            ],
        }
    )

    detector.print_results(result)

    output = capsys.readouterr().out
    assert "evil?[2J?.svg: LAYOUT (high)" in output
    assert "evil?[2J?.svg: bad?[2J" in output
    assert "\x1b[2J" not in output
    assert "\u202e" not in output
