# SPDX-License-Identifier: Apache-2.0
"""Batch decoding and sanitizing from a detector JSON report."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import stegguard
from stegguard.cli import main as cli_main
from stegguard.detector import analyze_file, write_json_output
from stegguard.operations import process_findings

ZERO_WIDTH_OK = "".join("​" if bit == "0" else "‌" for byte in b"OK" for bit in f"{byte:08b}")


def _hidden_file(directory: Path, name: str = "flagged.txt") -> Path:
    source = directory / name
    source.write_text("visible" + ZERO_WIDTH_OK + "\n", encoding="utf-8")
    return source


def _report(tmp_path: Path, *entries: dict, **top_level) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps({"schema_version": "1.0", "results": list(entries), **top_level}),
        encoding="utf-8",
    )
    return path


def _entry(source: Path | str, severity: str = "high", **extra) -> dict:
    return {"file": str(source), "severity": severity, **extra}


def test_process_findings_is_part_of_the_public_api():
    assert stegguard.process_findings is process_findings
    assert "process_findings" in stegguard.__all__


def test_batch_decode_extracts_payload_from_each_flagged_file(tmp_path):
    first = _hidden_file(tmp_path, "one.txt")
    second = _hidden_file(tmp_path, "two.txt")
    report = process_findings(_report(tmp_path, _entry(first), _entry(second)), "decode")

    assert [item["file"] for item in report["results"]] == [str(first), str(second)]
    assert [item["result"]["zero_width"]["decoded"] for item in report["results"]] == ["OK", "OK"]
    assert report["selected"] == 2
    assert report["succeeded"] == 2
    assert report["failed"] == 0


def test_batch_consumes_a_real_detector_report(tmp_path):
    flagged = _hidden_file(tmp_path)
    clean = tmp_path / "clean.txt"
    clean.write_text("plain\n", encoding="utf-8")
    findings = tmp_path / "real.json"
    write_json_output([analyze_file(flagged), analyze_file(clean)], str(findings))

    report = process_findings(findings, "decode")

    assert [item["file"] for item in report["results"]] == [str(flagged)]
    assert report["results"][0]["result"]["zero_width"]["decoded"] == "OK"
    assert report["below_threshold"] == 1


def test_batch_skips_clean_files_and_counts_them(tmp_path):
    source = _hidden_file(tmp_path)
    report = process_findings(_report(tmp_path, _entry(source, "clean")), "decode")

    assert report["results"] == []
    assert report["below_threshold"] == 1


@pytest.mark.parametrize(
    ("minimum", "expected"),
    [
        ("low", ["l", "m", "h", "c"]),
        ("medium", ["m", "h", "c"]),
        ("high", ["h", "c"]),
        ("critical", ["c"]),
    ],
)
def test_min_severity_selects_files_at_or_above_the_threshold(tmp_path, minimum, expected):
    entries = [
        _entry(_hidden_file(tmp_path, f"{letter}.txt"), severity)
        for letter, severity in [("l", "low"), ("m", "medium"), ("h", "high"), ("c", "critical")]
    ]
    report = process_findings(_report(tmp_path, *entries), "decode", min_severity=minimum)

    assert [Path(item["file"]).stem for item in report["results"]] == expected
    assert report["below_threshold"] == 4 - len(expected)


def test_unknown_severity_is_processed_rather_than_skipped(tmp_path):
    source = _hidden_file(tmp_path)
    report = process_findings(
        _report(tmp_path, _entry(source, "catastrophic")), "decode", min_severity="critical"
    )

    assert report["results"][0]["status"] == "OK"


def test_duplicate_report_entries_are_processed_once(tmp_path):
    source = _hidden_file(tmp_path)
    report = process_findings(_report(tmp_path, _entry(source), _entry(source)), "decode")

    assert report["selected"] == 1


def test_missing_file_is_reported_as_a_failure_not_skipped(tmp_path):
    missing = tmp_path / "gone.txt"
    report = process_findings(_report(tmp_path, _entry(missing)), "decode")

    assert report["results"][0]["status"] == "MISSING"
    assert report["failed"] == 1


def test_clean_entry_with_incomplete_scan_is_reported_as_a_failure(tmp_path):
    source = _hidden_file(tmp_path)
    entry = _entry(source, "clean", incomplete_reasons=["max_scan_seconds exceeded"])
    report = process_findings(_report(tmp_path, entry), "decode")

    assert report["results"][0]["status"] == "SCAN_INCOMPLETE"
    assert report["failed"] == 1
    assert report["below_threshold"] == 0


def test_flagged_entry_with_incomplete_scan_is_still_processed(tmp_path):
    source = _hidden_file(tmp_path)
    entry = _entry(source, "high", incomplete_reasons=["LSB analysis: failed"])
    report = process_findings(_report(tmp_path, entry), "decode")

    assert report["results"][0]["status"] == "OK"


def test_one_failing_file_does_not_stop_the_batch(tmp_path):
    good = _hidden_file(tmp_path, "good.txt")
    directory = tmp_path / "directory.txt"
    directory.mkdir()
    report = process_findings(_report(tmp_path, _entry(directory), _entry(good)), "decode")

    assert [item["status"] for item in report["results"]] == ["ERROR", "OK"]
    assert report["succeeded"] == 1
    assert report["failed"] == 1


def test_oversized_file_is_recorded_as_a_failure_and_the_batch_continues(tmp_path):
    large = tmp_path / "large.txt"
    large.write_text("x" * 5000, encoding="utf-8")
    small = tmp_path / "small.txt"
    small.write_text("y", encoding="utf-8")
    findings = _report(tmp_path, _entry(large), _entry(small))
    size = findings.stat().st_size

    report = process_findings(findings, "decode", limits={"max_file_bytes": size})

    assert report["results"][0]["status"] == "ERROR"
    assert "max_file_bytes" in report["results"][0]["error"]
    assert report["results"][1]["status"] == "OK"


@pytest.mark.parametrize("entry", [{"severity": "high"}, {"file": 5, "severity": "high"}, "text"])
def test_entry_without_a_usable_path_is_reported_as_a_failure(tmp_path, entry):
    report = process_findings(_report(tmp_path, entry), "decode")

    assert report["results"] == [
        {"file": None, "status": "ERROR", "error": "report entry has no file"}
    ]


@pytest.mark.parametrize(
    "content",
    ["[]", '{"results": {}}', '{"schema_version": "1.0"}'],
)
def test_non_report_json_is_rejected(tmp_path, content):
    path = tmp_path / "findings.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="not a StegGuard findings report"):
        process_findings(path, "decode")


def test_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError):
        process_findings(path, "decode")


def test_unsupported_schema_major_version_is_rejected(tmp_path):
    path = _report(tmp_path, schema_version="2.0")

    with pytest.raises(ValueError, match="unsupported findings schema version: 2.0"):
        process_findings(path, "decode")


def test_newer_minor_schema_version_is_accepted(tmp_path):
    report = process_findings(_report(tmp_path, schema_version="1.9"), "decode")

    assert report["selected"] == 0


def test_report_from_before_schema_versions_is_accepted(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"results": []}), encoding="utf-8")

    assert process_findings(path, "decode")["selected"] == 0


def test_oversized_findings_file_is_rejected(tmp_path):
    path = _report(tmp_path, padding="x" * 100)

    with pytest.raises(ValueError, match="max_file_bytes"):
        process_findings(path, "decode", limits={"max_file_bytes": 10})


def test_unknown_operation_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown batch operation: shred"):
        process_findings(_report(tmp_path), "shred")


def test_unknown_severity_threshold_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown severity: severe"):
        process_findings(_report(tmp_path), "decode", min_severity="severe")


def test_batch_sanitize_writes_alongside_by_default_and_preserves_originals(tmp_path):
    source = _hidden_file(tmp_path)
    original = source.read_bytes()

    report = process_findings(_report(tmp_path, _entry(source)), "sanitize")

    output = tmp_path / "flagged.sanitized.txt"
    assert output.read_text(encoding="utf-8") == "visible\n"
    assert source.read_bytes() == original
    assert report["results"][0]["result"]["sanitized_path"] == str(output)


def test_batch_sanitize_mirrors_paths_under_the_output_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pkg").mkdir()
    _hidden_file(tmp_path / "pkg", "a.txt")
    findings = _report(tmp_path, _entry(Path("pkg") / "a.txt"))

    process_findings(findings, "sanitize", output_dir="clean")

    assert (tmp_path / "clean" / "pkg" / "a.txt").read_text(encoding="utf-8") == "visible\n"


def test_absolute_source_paths_stay_inside_the_output_directory(tmp_path):
    source = _hidden_file(tmp_path)
    clean = tmp_path / "clean"

    report = process_findings(_report(tmp_path, _entry(source)), "sanitize", output_dir=clean)

    written = Path(report["results"][0]["result"]["sanitized_path"])
    assert written.resolve().is_relative_to(clean.resolve())
    assert written.read_text(encoding="utf-8") == "visible\n"


def test_parent_traversal_in_a_report_cannot_escape_the_output_directory(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _hidden_file(tmp_path, "outside.txt")
    findings = _report(tmp_path, _entry(Path("..") / "outside.txt"))
    clean = work / "clean"

    report = process_findings(findings, "sanitize", output_dir=clean)

    assert report["results"][0]["status"] == "ERROR"
    assert "outside the output directory" in report["results"][0]["error"]
    assert not clean.exists()
    assert not (tmp_path / "outside.sanitized.txt").exists()


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges on Windows")
def test_symlink_inside_the_output_directory_cannot_redirect_a_write(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pkg").mkdir()
    _hidden_file(tmp_path / "pkg", "a.txt")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "pkg").symlink_to(elsewhere)
    findings = _report(tmp_path, _entry(Path("pkg") / "a.txt"))

    report = process_findings(findings, "sanitize", output_dir=clean)

    assert report["results"][0]["status"] == "ERROR"
    assert list(elsewhere.iterdir()) == []


def test_batch_sanitize_refuses_to_overwrite_an_existing_output(tmp_path):
    source = _hidden_file(tmp_path)
    existing = tmp_path / "flagged.sanitized.txt"
    existing.write_text("keep me", encoding="utf-8")

    report = process_findings(_report(tmp_path, _entry(source)), "sanitize")

    assert report["results"][0]["status"] == "ERROR"
    assert existing.read_text(encoding="utf-8") == "keep me"


def test_batch_sanitize_reports_whether_the_output_scans_clean(tmp_path):
    source = _hidden_file(tmp_path)

    report = process_findings(_report(tmp_path, _entry(source)), "sanitize")

    assert report["results"][0]["clean_after"] is True


def test_batch_sanitize_reports_when_the_output_still_has_findings(tmp_path):
    source = _hidden_file(tmp_path)

    # Selecting an unrelated channel leaves the zero-width payload in the copy.
    report = process_findings(
        _report(tmp_path, _entry(source)), "sanitize", channels=["line_endings"]
    )

    assert report["results"][0]["status"] == "OK"
    assert report["results"][0]["clean_after"] is False


def test_batch_sanitize_applies_the_requested_profile(tmp_path):
    source = tmp_path / "note.txt"
    source.write_text("Привет\n", encoding="utf-8")

    report = process_findings(_report(tmp_path, _entry(source)), "sanitize", profile="destructive")

    assert report["results"][0]["result"]["policy"]["profile"] == "destructive"
    assert report["results"][0]["result"]["changes"]["homoglyphs_replaced"] > 0


@pytest.mark.parametrize(("in_place", "confirm"), [(True, False), (False, True)])
def test_batch_in_place_requires_both_flags_and_touches_nothing(tmp_path, in_place, confirm):
    source = _hidden_file(tmp_path)
    original = source.read_bytes()

    with pytest.raises(ValueError, match="--in-place.*--confirm"):
        process_findings(
            _report(tmp_path, _entry(source)), "sanitize", in_place=in_place, confirm=confirm
        )

    assert source.read_bytes() == original


def test_batch_in_place_overwrites_with_both_flags(tmp_path):
    source = _hidden_file(tmp_path)

    process_findings(_report(tmp_path, _entry(source)), "sanitize", in_place=True, confirm=True)

    assert source.read_text(encoding="utf-8") == "visible\n"


def test_in_place_and_output_directory_cannot_be_combined(tmp_path):
    with pytest.raises(ValueError, match="output_dir cannot be combined"):
        process_findings(
            _report(tmp_path), "sanitize", in_place=True, confirm=True, output_dir=tmp_path
        )


def test_batch_decode_refuses_write_options(tmp_path):
    with pytest.raises(ValueError, match="decode does not write files"):
        process_findings(_report(tmp_path), "decode", output_dir=tmp_path)


def test_invalid_channel_fails_before_any_file_is_written(tmp_path):
    source = _hidden_file(tmp_path)

    with pytest.raises(ValueError, match="unknown sanitization channel"):
        process_findings(_report(tmp_path, _entry(source)), "sanitize", channels=["nope"])

    assert not (tmp_path / "flagged.sanitized.txt").exists()


# ── CLI contract ──────────────────────────────────────────────────────────────


def test_cli_batch_decode_prints_a_json_report_and_exits_zero(tmp_path, capsys):
    findings = _report(tmp_path, _entry(_hidden_file(tmp_path)))

    code = cli_main(["decode", "--from-findings", str(findings)])

    assert code == 0
    assert (
        json.loads(capsys.readouterr().out)["results"][0]["result"]["zero_width"]["decoded"] == "OK"
    )


def test_cli_batch_exits_two_when_any_file_fails(tmp_path, capsys):
    findings = _report(tmp_path, _entry(tmp_path / "gone.txt"))

    code = cli_main(["decode", "--from-findings", str(findings)])

    assert code == 2
    assert json.loads(capsys.readouterr().out)["failed"] == 1


def test_cli_batch_exits_zero_when_nothing_is_selected(tmp_path, capsys):
    findings = _report(tmp_path, _entry(_hidden_file(tmp_path), "low"))

    code = cli_main(["decode", "--from-findings", str(findings), "--min-sev", "critical"])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["selected"] == 0


def test_cli_batch_sanitize_writes_to_the_output_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _hidden_file(tmp_path, "a.txt")
    findings = _report(tmp_path, _entry("a.txt"))

    code = cli_main(["sanitize", "--from-findings", str(findings), "--output-dir", "clean"])

    assert code == 0
    assert (tmp_path / "clean" / "a.txt").read_text(encoding="utf-8") == "visible\n"
    assert json.loads(capsys.readouterr().out)["operation"] == "sanitize"


def test_cli_batch_reports_unreadable_findings_with_exit_two(tmp_path, capsys):
    code = cli_main(["decode", "--from-findings", str(tmp_path / "missing.json")])

    assert code == 2
    assert "stegguard: error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "arguments",
    [
        ["decode"],
        ["sanitize"],
        ["decode", "file.txt", "--from-findings", "f.json"],
        ["decode", "file.txt", "--min-sev", "high"],
        ["sanitize", "file.txt", "--output-dir", "clean"],
        ["sanitize", "--from-findings", "f.json", "--output", "x.txt"],
        ["sanitize", "--from-findings", "f.json", "--in-place"],
        ["decode", "--from-findings", "f.json", "--min-sev", "severe"],
    ],
)
def test_cli_rejects_invalid_batch_argument_combinations_with_exit_two(arguments, capsys):
    with pytest.raises(SystemExit) as error:
        cli_main(arguments)

    assert error.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_cli_single_file_decode_still_works(tmp_path, capsys):
    source = _hidden_file(tmp_path)

    code = cli_main(["decode", str(source)])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["zero_width"]["decoded"] == "OK"
