# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import stegguard
from stegguard.operations import _write_bytes, decode_file, sanitize_file
from stegguard import cli


def _zwc_encode(value: bytes) -> str:
    return "".join("\u200b" if bit == "0" else "\u200c" for byte in value for bit in f"{byte:08b}")


def test_oss_package_exports_detection_decoding_sanitization_and_watermark_scan():
    assert callable(stegguard.analyze_file)
    assert callable(stegguard.decode_file)
    assert callable(stegguard.sanitize_file)
    assert callable(stegguard.scan_file)


def test_decode_file_extracts_zero_width_payload(tmp_path):
    source = tmp_path / "message.txt"
    source.write_text("visible" + _zwc_encode(b"Hi"), encoding="utf-8")

    result = decode_file(source)

    assert result["zero_width"]["decoded"] == "Hi"
    assert result["zero_width"]["confidence"] > 0.8


def test_decode_file_extracts_trailing_whitespace_payload(tmp_path):
    source = tmp_path / "snow.txt"
    bits = f"{ord('H'):08b}"
    source.write_text(
        "".join(f"visible{'\t' if bit == '1' else ' '}\n" for bit in bits),
        encoding="utf-8",
    )

    result = decode_file(source)

    assert result["trailing_whitespace"]["decoded"] == "H"


def test_decode_file_extracts_line_ending_payload(tmp_path):
    source = tmp_path / "endings.txt"
    bits = f"{ord('A'):08b}"
    source.write_bytes(b"".join(b"visible\r\n" if bit == "1" else b"visible\n" for bit in bits))

    result = decode_file(source)

    assert result["line_endings"]["decoded"] == "A"


def test_decode_file_normalizes_homoglyph_signal(tmp_path):
    source = tmp_path / "homoglyph.txt"
    source.write_text("p\u0430yment", encoding="utf-8")

    result = decode_file(source)

    assert result["homoglyphs"]["normalized_text"] == "payment"
    assert result["homoglyphs"]["replacements"] == 1


def test_sanitize_defaults_to_new_file_and_preserves_original(tmp_path):
    source = tmp_path / "message.txt"
    original = "hello\u200bworld  \n"
    source.write_bytes(original.encode("utf-8"))

    result = sanitize_file(source)

    output = Path(result["sanitized_path"])
    assert output == tmp_path / "message.sanitized.txt"
    assert output.read_text(encoding="utf-8") == "helloworld\n"
    assert source.read_text(encoding="utf-8") == original
    assert result["sha256_before"] == hashlib.sha256(original.encode()).hexdigest()
    assert result["sha256_after"] == hashlib.sha256(b"helloworld\n").hexdigest()
    assert result["changed"] is True
    assert "-hello" in result["diff"] and "+helloworld" in result["diff"]
    assert result["changes"]["zero_width_removed"] == 1
    assert result["changes"]["trailing_whitespace_removed"] == 2


@pytest.mark.parametrize(
    ("in_place", "confirm"),
    [(True, False), (False, True)],
)
def test_overwrite_requires_both_in_place_and_confirm(tmp_path, in_place, confirm):
    source = tmp_path / "message.txt"
    source.write_text("hello\u200b", encoding="utf-8")

    with pytest.raises(ValueError, match="--in-place.*--confirm"):
        sanitize_file(source, in_place=in_place, confirm=confirm)


def test_explicitly_confirmed_in_place_sanitization_overwrites_original(tmp_path):
    source = tmp_path / "message.txt"
    source.write_text("hello\u200b", encoding="utf-8")

    result = sanitize_file(source, in_place=True, confirm=True)

    assert source.read_text(encoding="utf-8") == "hello"
    assert result["sanitized_path"] == str(source)


def test_decode_cli_uses_oss_decoder(tmp_path, monkeypatch, capsys):
    source = tmp_path / "message.txt"
    source.write_text(_zwc_encode(b"OK"), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["stegguard", "decode", str(source)])

    cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["zero_width"]["decoded"] == "OK"


def test_sanitize_cli_requires_confirmation_for_in_place(tmp_path, monkeypatch):
    source = tmp_path / "message.txt"
    source.write_text("hello\u200b", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["stegguard", "sanitize", str(source), "--in-place"],
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert source.read_text(encoding="utf-8") == "hello\u200b"


def test_no_op_sanitization_preserves_valid_embedded_provenance(tmp_path):
    source = tmp_path / "clean.svg"
    original = b"<svg><!-- c2pa manifest --><text>clean</text></svg>"
    source.write_bytes(original)

    def validator(manifest, content, location):
        return {"status": "VALID", "provider": "Example"}

    result = sanitize_file(source, provenance_validator=validator)

    assert Path(result["sanitized_path"]).read_bytes() == original
    assert result["provenance_before"]["status"] == "VALID"
    assert result["provenance_after"]["status"] == "VALID"
    assert result["provenance_impact"] == "preserved"


def test_changed_sanitization_reports_provenance_invalidation(tmp_path):
    source = tmp_path / "marked.svg"
    original = b"<svg><!-- c2pa manifest --><text>hidden\xe2\x80\x8b</text></svg>"
    source.write_bytes(original)

    def validator(manifest, content, location):
        if content == original:
            return {"status": "VALID", "provider": "Example"}
        return {"status": "TAMPERED", "validation_errors": ["content hash mismatch"]}

    result = sanitize_file(source, provenance_validator=validator)

    assert result["changed"] is True
    assert result["provenance_before"]["status"] == "VALID"
    assert result["provenance_after"]["status"] == "TAMPERED"
    assert result["provenance_impact"] == "invalidated"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable")
def test_in_place_sanitization_preserves_file_permissions(tmp_path):
    source = tmp_path / "executable.sh"
    source.write_text("echo hello\u200b\n", encoding="utf-8")
    source.chmod(0o751)

    sanitize_file(source, in_place=True, confirm=True)

    assert source.stat().st_mode & 0o777 == 0o751


def test_copy_mode_refuses_to_overwrite_existing_output(tmp_path):
    source = tmp_path / "message.txt"
    output = tmp_path / "existing.txt"
    source.write_text("hello\u200b", encoding="utf-8")
    output.write_text("keep me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        sanitize_file(source, output)

    assert output.read_text(encoding="utf-8") == "keep me"


def test_copy_writer_cannot_overwrite_a_racing_destination(tmp_path):
    destination = tmp_path / "raced.txt"
    destination.write_bytes(b"other writer")

    with pytest.raises(FileExistsError):
        _write_bytes(destination, b"replacement", atomic=False)

    assert destination.read_bytes() == b"other writer"


def test_no_op_sanitization_copies_valid_sidecar_provenance(tmp_path):
    source = tmp_path / "asset.jpg"
    source.write_bytes(b"\xff\xd8plain\xff\xd9")
    sidecar = tmp_path / "asset.jpg.c2pa"
    sidecar.write_bytes(b"binary-c2pa")

    def validator(manifest, content, location):
        assert manifest == b"binary-c2pa"
        return {"status": "VALID", "provider": "Example"}

    result = sanitize_file(source, provenance_validator=validator)
    destination = Path(result["sanitized_path"])

    assert destination.with_name(destination.name + ".c2pa").read_bytes() == b"binary-c2pa"
    assert result["provenance_impact"] == "preserved"


def test_binary_sanitization_is_an_exact_no_op_copy(tmp_path):
    source = tmp_path / "image.png"
    original = b"\x89PNG\r\n\x1a\n\x00\xffbinary\r\ndata"
    source.write_bytes(original)

    result = sanitize_file(source)

    assert Path(result["sanitized_path"]).read_bytes() == original
    assert result["sanitization_status"] == "NO_OP_UNSUPPORTED"
    assert result["changed"] is False
    assert result["diff"] == ""


def test_binary_decode_reports_not_supported_without_interpreting_bytes(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(b"\x89PNG\r\n\x1a\n\x00\xff")

    result = decode_file(source)

    assert result["status"] == "NOT_SUPPORTED"
    assert "zero_width" not in result
