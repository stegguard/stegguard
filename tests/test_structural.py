# SPDX-License-Identifier: Apache-2.0
import io
import struct
import wave
import zipfile
import zlib

from stegguard.watermark import scan_file


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def test_png_private_ancillary_chunk_is_structural(tmp_path):
    path = tmp_path / "private.png"
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n" + _png_chunk(b"vpAg", b"private payload") + _png_chunk(b"IEND", b"")
    )

    result = scan_file(str(path))

    assert any(
        finding["category"] == "STRUCTURAL" and finding["detector"] == "png_private_chunk"
        for finding in result["findings"]
    )


def test_zip_embedded_file_inventory_is_structural(tmp_path):
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("payload.bin", b"payload")
        archive.writestr("nested/archive.zip", b"PK\x03\x04")

    result = scan_file(str(path))

    finding = next(
        finding for finding in result["findings"] if finding["detector"] == "archive_embedded_files"
    )
    assert finding["evidence"]["file_count"] == 2
    assert "nested/archive.zip" in finding["evidence"]["nested_archives"]


def test_riff_data_after_declared_size_is_structural(tmp_path):
    path = tmp_path / "audio.wav"
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8_000)
        output.writeframes(b"\x00\x00" * 1_000)
    path.write_bytes(buffer.getvalue() + b"appended payload")

    result = scan_file(str(path))

    assert any(finding["detector"] == "riff_appended_data" for finding in result["findings"])


def test_iso_bmff_private_uuid_and_trailing_data_are_structural(tmp_path):
    path = tmp_path / "video.mp4"
    ftyp = struct.pack(">I4s4sI4s", 20, b"ftyp", b"isom", 0, b"isom")
    uuid = struct.pack(">I4s", 12, b"uuid") + b"data"
    path.write_bytes(ftyp + uuid + b"tail")

    result = scan_file(str(path))

    detectors = {finding["detector"] for finding in result["findings"]}
    assert {"bmff_private_box", "bmff_appended_data"} <= detectors


def test_psd_layer_records_are_structural(tmp_path):
    path = tmp_path / "layered.psd"
    path.write_bytes(b"8BPS\x00\x01" + b"\x00" * 20 + b"8BIMluniHidden Layer")

    result = scan_file(str(path))

    assert any(finding["detector"] == "psd_layer_structure" for finding in result["findings"])
