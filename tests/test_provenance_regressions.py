# SPDX-License-Identifier: Apache-2.0
import json
import struct
import zipfile
import zlib

from stegguard import detector
from stegguard.watermark import scan_file


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _png(manifest: dict | None = None) -> bytes:
    chunks = b""
    if manifest is not None:
        chunks += _chunk(b"c2pa", json.dumps(manifest).encode())
    return b"\x89PNG\r\n\x1a\n" + chunks + _chunk(b"IEND", b"")


def _validator(manifest, content, location):
    scenario = manifest.get("scenario")
    return {
        "intact": {
            "status": "VALID",
            "provider": "Anthropic",
            "signer_identity": "Test signer",
            "certificate_trust": "trusted",
            "digital_source_type": "trainedAlgorithmicMedia",
            "actions": [{"action": "c2pa.created"}],
        },
        "edited": {
            "status": "TAMPERED",
            "validation_errors": ["content hash mismatch"],
        },
        "resaved": {
            "status": "UNTRUSTED_SIGNER",
            "signer_identity": "Unknown signer",
            "certificate_trust": "untrusted",
        },
    }.get(scenario, {"status": "NOT_CHECKED"})


def test_html_and_json_provenance_regression_matrix(tmp_path):
    intact = tmp_path / "intact.png"
    edited = tmp_path / "edited.png"
    resaved = tmp_path / "resaved.jpg"
    stripped = tmp_path / "metadata-stripped.png"
    short_text = tmp_path / "short.txt"
    mixed = tmp_path / "mixed-origin.zip"

    intact.write_bytes(_png({"scenario": "intact"}))
    edited.write_bytes(_png({"scenario": "edited"}))
    resaved.write_bytes(b"\xff\xd8c2pa\xff\xd9")
    resaved.with_name("resaved.jpg.c2pa.json").write_text(
        '{"scenario":"resaved"}', encoding="utf-8"
    )
    stripped.write_bytes(_png())
    short_text.write_text("short", encoding="utf-8")
    with zipfile.ZipFile(mixed, "w") as archive:
        archive.writestr("media/intact.png", _png({"scenario": "intact"}))
        archive.writestr("media/stripped.jpg", b"\xff\xd8plain\xff\xd9")

    expected = {
        intact: "VALID",
        edited: "TAMPERED",
        resaved: "UNTRUSTED_SIGNER",
        stripped: "MISSING",
        short_text: "UNSUPPORTED",
        mixed: "UNSUPPORTED",
    }
    report_results = []
    serialized_results = []
    for path, expected_status in expected.items():
        watermark = scan_file(str(path), provenance_validator=_validator)
        assert watermark["provenance"]["status"] == expected_status
        if path == mixed:
            assert {
                item["result"]["provenance"]["status"] for item in watermark["nested_results"]
            } == {"VALID", "MISSING"}
        analyzed = detector.analyze_file(path)
        analyzed["watermark"] = watermark
        report_results.append(analyzed)
        serialized_results.append(detector.result_to_json_dict(analyzed))

    json_path = tmp_path / "provenance-regressions.json"
    json_path.write_text(json.dumps(serialized_results, indent=2), encoding="utf-8")
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert [item["watermark"]["provenance"]["status"] for item in loaded] == list(expected.values())

    html_path = tmp_path / "provenance-regressions.html"
    detector.generate_html_report(report_results, str(html_path))
    html = html_path.read_text(encoding="utf-8")
    for status in expected.values():
        assert status in html
    assert "Nested Provenance" in html
    assert "media/intact.png" in html
    assert "media/stripped.jpg" in html
    assert "processed by Claude" in html
    assert "missing mark does not prove human authorship" in html
