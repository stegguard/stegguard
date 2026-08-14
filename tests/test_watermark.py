# SPDX-License-Identifier: Apache-2.0
import json
import base64
import struct
import zipfile
import zlib

import pytest

from stegguard.watermark import (
    DETECTION_CATEGORIES,
    PROVENANCE_STATUSES,
    DetectionFinding,
    ProvenanceRecord,
    scan_file,
)
from stegguard import detector


def test_detection_categories_are_complete_and_keep_lsb_separate():
    assert DETECTION_CATEGORIES == {
        "METADATA",
        "STRUCTURAL",
        "TEXT_PATTERN",
        "LAYOUT",
        "IMAGE_ROBUST",
        "AUDIO_ROBUST",
        "VIDEO_ROBUST",
        "FINGERPRINT",
        "PROVENANCE",
        "NETWORK_OR_EXTERNAL",
        "AI_TEXT_WATERMARK",
        "C2PA_PROVENANCE",
        "LSB",
    }
    assert "LSB" != "IMAGE_ROBUST"


def test_finding_and_provenance_records_are_json_compatible():
    finding = DetectionFinding(
        category="METADATA",
        detector="png_text_chunk",
        description="embedded comment",
        confidence=0.75,
        location="tEXt",
        evidence={"key": "Comment"},
    )
    provenance = ProvenanceRecord(
        status="VALID",
        provider="Anthropic",
        claim_generator="example/1.0",
        signer_identity="Example signer",
        certificate_trust="trusted",
        digital_source_type="trainedAlgorithmicMedia",
        timestamps=["2026-08-12T00:00:00Z"],
        manifest_location="embedded",
        validation_errors=[],
        actions=[{"action": "c2pa.created"}],
    )

    payload = {"finding": finding.to_dict(), "provenance": provenance.to_dict()}
    assert json.loads(json.dumps(payload)) == payload


def test_provenance_status_vocabulary_is_stable():
    assert PROVENANCE_STATUSES == {
        "VALID",
        "TAMPERED",
        "UNTRUSTED_SIGNER",
        "MISSING",
        "UNSUPPORTED",
        "NOT_CHECKED",
    }


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def test_scan_reports_png_text_metadata_and_appended_data(tmp_path):
    path = tmp_path / "marked.png"
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"tEXt", b"Comment\x00watermark payload")
        + _png_chunk(b"IEND", b"")
        + b"hidden-appended-payload"
    )

    result = scan_file(str(path))
    categories = {finding["category"] for finding in result["findings"]}

    assert "METADATA" in categories
    assert "STRUCTURAL" in categories
    assert any(finding["detector"] == "png_appended_data" for finding in result["findings"])


def test_supported_media_without_c2pa_manifest_is_missing(tmp_path):
    path = tmp_path / "plain.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IEND", b""))

    result = scan_file(str(path))

    assert result["provenance"]["status"] == "MISSING"


def test_manifest_presence_without_validator_is_not_treated_as_valid(tmp_path):
    path = tmp_path / "marked.png"
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"c2pa", b'{"provider":"Anthropic"}')
        + _png_chunk(b"IEND", b"")
    )

    result = scan_file(str(path))

    assert result["provenance"]["status"] == "NOT_CHECKED"
    assert result["provenance"]["manifest_location"] == "embedded"
    assert result["provenance"]["validation_errors"]


def test_sidecar_c2pa_validator_populates_normalized_fields(tmp_path):
    path = tmp_path / "claude.jpg"
    path.write_bytes(b"\xff\xd8content\xff\xd9")
    sidecar = tmp_path / "claude.jpg.c2pa.json"
    sidecar.write_text('{"claim":"sample"}', encoding="utf-8")

    def validator(manifest, content, location):
        assert manifest == {"claim": "sample"}
        assert content == path.read_bytes()
        assert location == str(sidecar)
        return {
            "status": "VALID",
            "provider": "Anthropic",
            "claim_generator": "claude.example/1.0",
            "signer_identity": "Anthropic test signer",
            "certificate_trust": "trusted",
            "digital_source_type": "trainedAlgorithmicMedia",
            "timestamps": ["2026-08-12T00:00:00Z"],
            "actions": [{"action": "c2pa.created"}],
        }

    result = scan_file(str(path), provenance_validator=validator)

    assert result["provenance"]["status"] == "VALID"
    assert result["provenance"]["provider"] == "Anthropic"
    assert result["provenance"]["manifest_location"] == str(sidecar)
    descriptions = " ".join(finding["description"] for finding in result["findings"])
    assert "processed by Claude" in descriptions
    assert "authored by Claude" not in descriptions


def test_binary_c2pa_sidecar_is_passed_intact_to_validator(tmp_path):
    path = tmp_path / "asset.jpg"
    path.write_bytes(b"\xff\xd8content\xff\xd9")
    sidecar = tmp_path / "asset.jpg.c2pa"
    sidecar.write_bytes(b"\xd8\x2aCOSE-C2PA")

    def validator(manifest, content, location):
        assert manifest == b"\xd8\x2aCOSE-C2PA"
        return {"status": "VALID", "provider": "Example"}

    result = scan_file(str(path), provenance_validator=validator)

    assert result["provenance"]["status"] == "VALID"
    assert result["provenance"]["manifest_location"] == str(sidecar)


def test_tampered_provenance_is_a_high_risk_finding(tmp_path):
    path = tmp_path / "edited.svg"
    path.write_text("<svg><!-- c2pa manifest --></svg>", encoding="utf-8")

    result = scan_file(
        str(path),
        provenance_validator=lambda manifest, content, location: {
            "status": "TAMPERED",
            "validation_errors": ["content hash mismatch"],
        },
    )

    finding = next(
        finding for finding in result["findings"] if finding["category"] == "C2PA_PROVENANCE"
    )
    assert finding["risk"] == "high"
    assert result["provenance"]["validation_errors"] == ["content hash mismatch"]


def test_unsupported_provenance_format_is_explicit(tmp_path):
    path = tmp_path / "plain.txt"
    path.write_text("plain", encoding="utf-8")

    assert scan_file(str(path))["provenance"]["status"] == "UNSUPPORTED"


def test_remote_manifest_uses_injected_loader_and_validator(tmp_path):
    path = tmp_path / "remote.png"
    url = "https://credentials.example/manifest.c2pa"
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"c2pa", json.dumps({"remote_url": url}).encode())
        + _png_chunk(b"IEND", b"")
    )

    result = scan_file(
        str(path),
        remote_manifest_loader=lambda requested: {"claim": requested},
        provenance_validator=lambda manifest, content, location: {
            "status": "VALID",
            "provider": "Example",
        },
    )

    assert result["provenance"]["status"] == "VALID"
    assert result["provenance"]["manifest_location"] == url


def test_ai_text_watermark_is_not_checked_without_official_verifier(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("Some sufficiently long sample text.", encoding="utf-8")

    result = scan_file(str(path))

    assert result["ai_text_watermark"]["status"] == "NOT_CHECKED"
    assert not any(finding["category"] == "AI_TEXT_WATERMARK" for finding in result["findings"])


def test_ai_text_watermark_uses_pluggable_verifier(tmp_path):
    path = tmp_path / "sample.txt"
    text = "Some sufficiently long sample text."
    path.write_text(text, encoding="utf-8")

    class Verifier:
        def verify(self, candidate, *, path):
            assert candidate == text
            assert path.endswith("sample.txt")
            return {
                "detected": True,
                "confidence": 0.91,
                "provider": "official-test-verifier",
                "evidence": {"key_id": "test-key"},
            }

    result = scan_file(str(path), ai_text_verifier=Verifier())

    assert result["ai_text_watermark"]["status"] == "DETECTED"
    finding = next(
        finding for finding in result["findings"] if finding["category"] == "AI_TEXT_WATERMARK"
    )
    assert finding["confidence"] == 0.91


def _marked_png() -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"tEXt", b"Comment\x00nested watermark")
        + _png_chunk(b"IEND", b"")
    )


@pytest.mark.parametrize("extension", ["zip", "docx", "pptx", "xlsx"])
def test_scan_finds_supported_media_inside_zip_containers(tmp_path, extension):
    path = tmp_path / f"container.{extension}"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("media/marked.png", _marked_png())

    result = scan_file(str(path))

    nested = result["nested_results"]
    assert len(nested) == 1
    assert nested[0]["path"] == "media/marked.png"
    assert any(finding["category"] == "METADATA" for finding in nested[0]["result"]["findings"])


def test_scan_finds_supported_media_inside_pdf(tmp_path):
    path = tmp_path / "container.pdf"
    path.write_bytes(b"%PDF-1.7\nstream\n" + _marked_png() + b"\nendstream\n%%EOF")

    result = scan_file(str(path))

    assert result["nested_results"][0]["path"].endswith(".png")
    assert any(
        finding["category"] == "METADATA"
        for finding in result["nested_results"][0]["result"]["findings"]
    )


def test_scan_finds_data_uri_media_inside_html(tmp_path):
    path = tmp_path / "container.html"
    encoded = base64.b64encode(_marked_png()).decode("ascii")
    path.write_text(f'<img src="data:image/png;base64,{encoded}">', encoding="utf-8")

    result = scan_file(str(path))

    assert result["nested_results"][0]["path"] == "data-uri-1.png"
    assert any(
        finding["category"] == "METADATA"
        for finding in result["nested_results"][0]["result"]["findings"]
    )


def test_scan_accepts_line_wrapped_data_uri(tmp_path):
    path = tmp_path / "container.html"
    encoded = base64.b64encode(_marked_png()).decode("ascii")
    wrapped = "\n".join(encoded[index : index + 24] for index in range(0, len(encoded), 24))
    path.write_text(f'<img src="data:image/png;base64,{wrapped}">', encoding="utf-8")

    result = scan_file(str(path))

    assert result["nested_results"][0]["path"] == "data-uri-1.png"


def test_non_json_ai_verifier_evidence_becomes_an_error_result(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("sample text", encoding="utf-8")

    result = scan_file(
        str(path),
        ai_text_verifier=lambda text, path: {
            "detected": True,
            "confidence": 0.9,
            "evidence": {"raw": b"not-json"},
        },
    )

    assert result["ai_text_watermark"]["status"] == "ERROR"
    json.dumps(result)


def test_html_report_renders_categorized_watermark_findings(tmp_path):
    source = tmp_path / "marked.html"
    source.write_text('<p style="display:none">secret</p>', encoding="utf-8")
    result = detector.analyze_file(source)
    report = tmp_path / "report.html"

    detector.generate_html_report([result], str(report))
    html = report.read_text(encoding="utf-8")

    assert "Categorized Watermark Findings" in html
    assert "LAYOUT" in html
    assert "hidden_layout_style" in html


def test_detector_json_includes_categorized_provenance(tmp_path):
    path = tmp_path / "plain.txt"
    path.write_text("plain", encoding="utf-8")

    serialized = detector.result_to_json_dict(detector.analyze_file(path))

    assert serialized["watermark"]["provenance"]["status"] == "UNSUPPORTED"
    json.dumps(serialized)


def test_html_report_has_provenance_summary_panel_timeline_and_disclaimer(tmp_path):
    path = tmp_path / "report.html"
    base = {
        "file": "/tmp/claude.png",
        "file_mode": "binary",
        "total_hidden": 0,
        "zero_width": [],
        "homoglyphs": [],
        "other_suspicious": [],
        "trailing_whitespace_lines": [],
        "mixed_line_endings": False,
        "binary_hits": [],
        "error": None,
        "lsb_analysis": None,
        "watermark": {
            "findings": [],
            "nested_results": [],
            "provenance": ProvenanceRecord(
                status="VALID",
                provider="Anthropic",
                claim_generator="claude.example/1.0",
                signer_identity="Example signer <unsafe>",
                certificate_trust="trusted",
                digital_source_type="trainedAlgorithmicMedia",
                timestamps=["2026-08-12T00:00:00Z"],
                manifest_location="embedded",
                actions=[{"action": "c2pa.created"}, {"action": "c2pa.edited"}],
                ingredients=[{"title": "source.png", "relationship": "parentOf"}],
            ).to_dict(),
        },
    }
    tampered = json.loads(json.dumps(base))
    tampered["file"] = "/tmp/edited.png"
    tampered["watermark"]["provenance"]["status"] = "TAMPERED"
    tampered["watermark"]["provenance"]["validation_errors"] = ["hash mismatch"]

    detector.generate_html_report([base, tampered], str(path))
    html = path.read_text(encoding="utf-8")

    assert "Provenance Valid" in html
    assert "Validation Failures" in html
    assert "Provenance Timeline" in html
    assert "source.png" in html
    assert "processed by Claude" in html
    assert "missing mark does not prove human authorship" in html
    assert "Example signer &lt;unsafe&gt;" in html
    assert "hash mismatch" in html


def test_tampered_provenance_changes_json_severity_and_flagged_count(tmp_path):
    source = tmp_path / "edited.png"
    source.write_bytes(b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IEND", b""))
    result = detector.analyze_file(source)
    result["watermark"]["provenance"]["status"] = "TAMPERED"
    result["watermark"]["provenance"]["validation_errors"] = ["hash mismatch"]
    result["watermark"]["findings"] = [
        DetectionFinding(
            category="C2PA_PROVENANCE",
            detector="c2pa_validation",
            description="tampered",
            confidence=0.99,
            risk="high",
        ).to_dict()
    ]
    output = tmp_path / "findings.json"

    detector.write_json_output([result], str(output))
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["flagged_files"] == 1
    assert payload["results"][0]["severity"] == "high"


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("photo.jpg", b"\xff\xd8Exif\x00\x00Camera metadata\xff\xd9"),
        ("track.mp3", b"ID3\x04\x00\x00\x00\x00\x00\x00TIT2title"),
        ("document.pdf", b"%PDF-1.7\n/Author (Example)\n%%EOF"),
        ("image.svg", b"<svg><!-- generator: Example --></svg>"),
        ("page.html", b"<html><!-- watermark comment --></html>"),
    ],
)
def test_format_specific_metadata_fields_are_classified(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)

    result = scan_file(str(path))

    assert any(finding["category"] == "METADATA" for finding in result["findings"])


def test_archive_comment_and_office_properties_are_metadata(tmp_path):
    path = tmp_path / "document.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.comment = b"tracking comment"
        archive.writestr("docProps/core.xml", "<creator>Example</creator>")

    result = scan_file(str(path))

    finding = next(finding for finding in result["findings"] if finding["category"] == "METADATA")
    assert {"archive_comment", "office_properties"} <= set(finding["evidence"]["fields"])


def test_scan_reports_typography_patterns_and_hidden_html_layout(tmp_path):
    path = tmp_path / "marked.html"
    path.write_text(
        '<p style="display:none">secret</p>Visible  text.  More  text. '
        '<img src="https://example.test/watermark.png">',
        encoding="utf-8",
    )

    result = scan_file(str(path))
    categories = {finding["category"] for finding in result["findings"]}

    assert {"TEXT_PATTERN", "LAYOUT", "NETWORK_OR_EXTERNAL"} <= categories


def test_external_url_evidence_excludes_markdown_punctuation(tmp_path):
    path = tmp_path / "links.md"
    path.write_text("See [site](https://example.test/path).", encoding="utf-8")

    result = scan_file(str(path))

    finding = next(item for item in result["findings"] if item["category"] == "NETWORK_OR_EXTERNAL")
    assert finding["evidence"]["urls"] == ["https://example.test/path"]


def test_scan_reports_pdf_hidden_objects_and_embedded_files(tmp_path):
    path = tmp_path / "marked.pdf"
    path.write_bytes(
        b"%PDF-1.7\n1 0 obj << /Type /EmbeddedFile /Length 6 >> stream\nsecret\nendstream\nendobj\n%%EOF"
    )

    result = scan_file(str(path))

    assert any(
        finding["category"] == "STRUCTURAL" and finding["detector"] == "pdf_hidden_structure"
        for finding in result["findings"]
    )


def test_scan_classifies_robust_media_signals_without_using_lsb(tmp_path):
    samples = {
        "marked.png": b"\x89PNG\r\n\x1a\ndct-watermark correlation-template",
        "marked.wav": b"RIFF\x00\x00\x00\x00WAVEphase_watermark echo-hiding",
        "marked.mp4": b"\x00\x00\x00\x18ftypisom motion_vector_watermark chroma-watermark",
    }
    expected = {
        "marked.png": "IMAGE_ROBUST",
        "marked.wav": "AUDIO_ROBUST",
        "marked.mp4": "VIDEO_ROBUST",
    }

    for name, content in samples.items():
        path = tmp_path / name
        path.write_bytes(content)
        result = scan_file(str(path))
        categories = {finding["category"] for finding in result["findings"]}
        assert expected[name] in categories
        assert "LSB" not in categories


def test_scan_reports_device_codec_and_provenance_fingerprints(tmp_path):
    path = tmp_path / "camera.jpg"
    path.write_bytes(
        b"\xff\xd8Exif\x00\x00Make=ExampleCam Model=E1 Software=EncoderPro "
        b"device_fingerprint=abc123\xff\xd9"
    )

    result = scan_file(str(path))
    fingerprint = next(
        finding for finding in result["findings"] if finding["category"] == "FINGERPRINT"
    )

    assert fingerprint["risk"] == "informational"
    assert "device_fingerprint" in fingerprint["evidence"]["markers"]
