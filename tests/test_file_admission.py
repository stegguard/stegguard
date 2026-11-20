import zipfile
from pathlib import Path

import pytest

from stegguard.operations import decode_file, sanitize_file


@pytest.mark.parametrize("name", ["notes.txt", "slides.pptx", "book.epub"])
def test_archive_cannot_be_rewritten(tmp_path, name):
    source = tmp_path / name
    with zipfile.ZipFile(source, "w") as archive:
        if name.endswith(".pptx"):
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("ppt/presentation.xml", "<presentation/>")
        elif name.endswith(".epub"):
            archive.writestr("mimetype", "application/epub+zip")
            archive.writestr("chapter.xhtml", "<p>text\u200b</p>")
        else:
            archive.writestr("notes", "text\u200b")
    result = sanitize_file(source)
    assert result["sanitization_status"] == "NOT_SUPPORTED"
    assert decode_file(source)["status"] == "NOT_SUPPORTED"
    with zipfile.ZipFile(source) as archive:
        assert archive.testzip() is None
    assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("notes.txt", b"\x00\xff"),
        ("notes.txt", b"SQLite format 3\0"),
        ("script.py", b"print('hello')\n"),
    ],
)
def test_only_validated_plain_text_can_be_rewritten(tmp_path, name, data):
    source = tmp_path / name
    source.write_bytes(data)
    assert sanitize_file(source)["sanitization_status"] == "NOT_SUPPORTED"
    assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize("suffix", [".txt", ".log"])
def test_utf16_sanitization_preserves_encoding_and_line_endings(tmp_path, suffix):
    source = tmp_path / f"notes{suffix}"
    source.write_bytes(b"\xfe\xff" + "hello\u200b\r\nworld\r\n".encode("utf-16-be"))
    result = sanitize_file(source, channels=["zero_width"])
    assert result["sanitization_status"] == "SANITIZED"
    assert (tmp_path / f"notes.sanitized{suffix}").read_bytes() == (
        b"\xfe\xff" + "hello\r\nworld\r\n".encode("utf-16-be")
    )


def test_failed_staged_validation_preserves_original(tmp_path, monkeypatch):
    import os

    source = tmp_path / "notes.txt"
    original = "hello\u200b\n".encode()
    source.write_bytes(original)
    fsync = os.fsync

    def corrupt_staged_output(descriptor):
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.write(descriptor, b"\x00")
        fsync(descriptor)

    monkeypatch.setattr(os, "fsync", corrupt_staged_output)
    result = sanitize_file(source, in_place=True, confirm=True)
    assert result["sanitization_status"] == "VALIDATION_FAILED"
    assert source.read_bytes() == original
    assert list(tmp_path.iterdir()) == [source]


def test_unsupported_channel_reports_reason(tmp_path):
    source = tmp_path / "notes.txt"
    source.write_text("hello")
    result = sanitize_file(source, channels=["metadata"])
    assert result["sanitization_status"] == "NOT_SUPPORTED"
    assert "metadata" in result["errors"][0]


def test_unknown_binary_is_reported_as_unsupported(tmp_path):
    from stegguard.detector import analyze_file, generate_html_report, result_to_json_dict

    source = tmp_path / "unknown.txt"
    source.write_bytes(b"\x00\xff")
    result = analyze_file(source)
    exported = result_to_json_dict(result)
    assert exported["inspection_status"] == "NOT_SUPPORTED"
    assert exported["unsupported_reason"]
    report = tmp_path / "report.html"
    generate_html_report([result], report)
    assert exported["unsupported_reason"] in report.read_text()


def test_batch_reports_skips_and_unsupported_inputs(tmp_path):
    import json

    from stegguard.operations import process_findings

    clean = tmp_path / "clean.txt"
    marked = tmp_path / "marked.txt"
    code = tmp_path / "script.py"
    clean.write_text("hello\n")
    marked.write_text("hello\u200b\n")
    code.write_text("print('hello')\n")
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps(
            {
                "results": [
                    {"file": str(clean), "severity": "clean"},
                    {"file": str(marked), "severity": "low"},
                    {"file": str(code), "severity": "low"},
                ]
            }
        )
    )
    report = process_findings(findings, "sanitize")
    assert report["outcome_counts"] == {"SKIPPED": 1, "SANITIZED": 1, "NOT_SUPPORTED": 1}
    assert report["selected"] == 2
    assert report["succeeded"] == report["failed"] == 1
    assert report["skipped"][0]["file"] == str(clean)
    assert report["skipped"][0]["reason"]


@pytest.mark.parametrize(
    "content",
    [
        "<svg><text>hello\u200b</text></svg>",
        "#!/usr/bin/env python3\nprint('hello\u200b')\n",
        '{"greeting": "hello\u200b"}',
    ],
)
def test_identifiable_structured_text_cannot_be_rewritten_under_txt(tmp_path, content):
    source = tmp_path / "notes.txt"
    source.write_text(content, encoding="utf-8")
    result = sanitize_file(source)
    assert result["sanitization_status"] == "NOT_SUPPORTED"
    assert list(tmp_path.iterdir()) == [source]


def test_cli_does_not_report_unsupported_input_as_clean(tmp_path, capsys):
    from stegguard.detector import main

    source = tmp_path / "unknown.txt"
    source.write_bytes(b"\x00\xff")
    main([str(source)])
    output = capsys.readouterr().out
    assert "1/1 file(s) unsupported" in output
    assert "All 1 file(s) clean" not in output


def test_unlisted_text_extension_has_no_handler(tmp_path):
    from stegguard.detector import analyze_file, result_to_json_dict

    source = tmp_path / "notes.unlisted"
    source.write_text("hello\u200b")
    report = result_to_json_dict(analyze_file(source))
    assert report["inspection_status"] == "NOT_SUPPORTED"
    assert report["unsupported_reason"]
    assert decode_file(source)["status"] == "NOT_SUPPORTED"
    assert sanitize_file(source)["sanitization_status"] == "NOT_SUPPORTED"


def test_mixed_inspection_and_rewrite_outcomes(tmp_path, monkeypatch):
    import json
    import os

    from stegguard.detector import main
    from stegguard.operations import process_findings

    inputs = tmp_path / "inputs"
    inputs.mkdir()
    fixtures = {
        "full.txt": b"hello\xe2\x80\x8b\n",
        "partial.txt": b"hello\xe2\x80\x8b \n",
        "corrupt.txt": b"world\xe2\x80\x8b\n",
        "bad.txt": b"\x00\xff",
        "broken.txt": b"\xff\xfe\x00",
        "ignored.bin": b"\x00\xff",
    }
    for name, data in fixtures.items():
        (inputs / name).write_bytes(data)
    findings = tmp_path / "findings.json"
    html = tmp_path / "findings.html"
    args = ["--ext", "txt", "--json", str(findings), "--html", str(html)]
    for paths in ([str(inputs), "-r"], [str(inputs / name) for name in fixtures]):
        assert main([*paths, *args]) == 2
        report = json.loads(findings.read_text())
        assert [
            report[key]
            for key in (
                "completed_files",
                "skipped_files",
                "unsupported_files",
                "incomplete_files",
            )
        ] == [3, 1, 1, 1]
        assert report["skipped"][0]["reason"]
        items = {Path(item["file"]).name: item for item in report["results"]}
        assert "Unicode text" in items["full.txt"]["checks_run"]
        assert not items["bad.txt"]["checks_run"]
        rendered = html.read_text()
        for label, count in (
            ("Unsupported Files", 1),
            ("Incomplete Files", 1),
            ("Skipped Files", 1),
        ):
            assert f'class="sn">{count}</div><div class="sl">{label}</div>' in rendered

    sync = os.fsync

    def damage_world(descriptor):
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, 5) == b"world":
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, b"\x00")
        sync(descriptor)

    monkeypatch.setattr(os, "fsync", damage_world)
    result = process_findings(
        findings,
        "sanitize",
        in_place=True,
        confirm=True,
        channels=["zero_width"],
    )
    assert result["outcome_counts"] == {
        "SKIPPED": 1,
        "SANITIZED": 1,
        "PARTIAL": 1,
        "VALIDATION_FAILED": 1,
        "NOT_SUPPORTED": 1,
        "SCAN_INCOMPLETE": 1,
    }
    outcomes = {Path(item["file"]).name: item for item in result["results"]}
    assert outcomes["partial.txt"]["result"]["warnings"]
    assert outcomes["corrupt.txt"]["result"]["errors"]
    assert outcomes["bad.txt"]["error"]
    assert outcomes["broken.txt"]["error"]
    assert (inputs / "corrupt.txt").read_bytes() == fixtures["corrupt.txt"]


@pytest.mark.parametrize("name", ["photo.gif", "slides.pptx", "book.epub", "data.sqlite"])
def test_declared_binary_format_requires_matching_content(tmp_path, name):
    from stegguard.detector import analyze_file, result_to_json_dict

    source = tmp_path / name
    source.write_bytes(b"ordinary text\n")
    result = result_to_json_dict(analyze_file(source))
    assert result["inspection_status"] == "NOT_SUPPORTED"
    assert result["unsupported_reason"]


def test_renamed_gif_cannot_reach_text_inspection(tmp_path):
    from stegguard.detector import analyze_file

    source = tmp_path / "photo.txt"
    source.write_bytes(b"GIF89a" + b"printable bytes")
    result = analyze_file(source)
    assert result["file_mode"] == "binary"
