# SPDX-License-Identifier: Apache-2.0
"""Decoding and sanitizing hidden content in binary formats."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from stegguard import ResourceLimitError, binary_ops
from stegguard.binary_ops import _LSB_WINDOW_BYTES, decode_lsb, extract_metadata
from stegguard.detector import _load_pixels_bmp, _load_pixels_png, analyze_file
from stegguard.limits import ScanLimits
from stegguard.operations import decode_file, sanitize_file

POLICY = ScanLimits()
ZERO_WIDTH_HI = "".join("​" if bit == "0" else "‌" for byte in b"Hi" for bit in f"{byte:08b}")


def _chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def _png(
    pixels: bytes,
    width: int,
    height: int,
    *,
    color_type: int = 2,
    extra: bytes = b"",
    palette: bytes | None = None,
    transparency: bytes | None = None,
    trailing: bytes = b"",
) -> bytes:
    step = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    row = width * step
    rows = b"".join(b"\x00" + pixels[y * row : (y + 1) * row] for y in range(height))
    parts = [b"\x89PNG\r\n\x1a\n"]
    parts.append(_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)))
    if palette is not None:
        parts.append(_chunk(b"PLTE", palette))
    if transparency is not None:
        parts.append(_chunk(b"tRNS", transparency))
    parts.append(extra)
    parts.append(_chunk(b"IDAT", zlib.compress(rows)))
    parts.append(_chunk(b"IEND", b""))
    return b"".join(parts) + trailing


def _embed(message: bytes, samples: int, base: int = 0x80) -> bytes:
    """Write a message into the LSBs of ``samples`` bytes, padding with a neutral value."""
    bits = [int(bit) for byte in message for bit in f"{byte:08b}"]
    return bytes((base | bits[i]) if i < len(bits) else base for i in range(samples))


def _chunks_in(raw: bytes) -> list[bytes]:
    kinds = []
    position = 8
    while position + 12 <= len(raw):
        length = struct.unpack_from(">I", raw, position)[0]
        kinds.append(raw[position + 4 : position + 8])
        position += 12 + length
    return kinds


def _bmp(pixels: bytes, width: int, height: int, depth: int = 24) -> bytes:
    pixel_offset = 54
    header = b"BM" + struct.pack("<IHHI", pixel_offset + len(pixels), 0, 0, pixel_offset)
    info = struct.pack("<IiiHHIIiiII", 40, width, height, 1, depth, 0, len(pixels), 0, 0, 0, 0)
    return header + info + pixels


def _jpeg(*segments: bytes, trailing: bytes = b"") -> bytes:
    scan = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x12\x34\xff\xd9"
    return b"\xff\xd8" + b"".join(segments) + scan + trailing


def _segment(marker: int, body: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body


def _tiff(pixels: bytes, width: int, height: int, description: bytes = b"") -> bytes:
    """Build a little-endian uncompressed grayscale TIFF with one strip."""
    description += b"\x00"
    entries = [
        (256, 4, 1, width),
        (257, 4, 1, height),
        (258, 3, 1, 8),
        (259, 3, 1, 1),
        (262, 3, 1, 1),
    ]
    directory_offset = 8
    entry_count = 8
    data_start = directory_offset + 2 + entry_count * 12 + 4
    description_offset = data_start
    strip_offset = description_offset + len(description)
    entries += [
        (270, 2, len(description), description_offset),
        (273, 4, 1, strip_offset),
        (279, 4, 1, len(pixels)),
    ]
    out = b"II" + struct.pack("<HI", 42, directory_offset)
    out += struct.pack("<H", entry_count)
    for tag, kind, count, value in sorted(entries):
        out += struct.pack("<HHI", tag, kind, count)
        out += struct.pack("<HH", value, 0) if kind == 3 else struct.pack("<I", value)
    out += struct.pack("<I", 0)
    return out + description + pixels


def _gif(*extensions: bytes, trailing: bytes = b"") -> bytes:
    header = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x80\x00\x00"
    palette = b"\x00\x00\x00\xff\xff\xff"
    image = b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00" + b"\x02\x02\x44\x01\x00"
    return header + palette + b"".join(extensions) + image + b"\x3b" + trailing


def _gif_extension(label: int, data: bytes) -> bytes:
    return bytes([0x21, label, len(data)]) + data + b"\x00"


def _mp3(*frames: bytes, v1: bytes = b"") -> bytes:
    body = b"".join(frames)
    size = len(body)
    synchsafe = bytes((size >> shift) & 0x7F for shift in (21, 14, 7, 0))
    return b"ID3\x04\x00\x00" + synchsafe + body + b"\xff\xfb\x90\x00AUDIO" + v1


def _id3_frame(name: bytes, body: bytes, size_bytes: bytes | None = None) -> bytes:
    if size_bytes is None:
        size_bytes = bytes((len(body) >> shift) & 0x7F for shift in (21, 14, 7, 0))
    return name + size_bytes + b"\x00\x00" + body


def _zip(*, archive_comment: bytes = b"", entry_comment: bytes = b"") -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo("inner.txt")
        info.comment = entry_comment
        archive.writestr(info, "inner contents")
        archive.comment = archive_comment
    return stream.getvalue()


def _sanitized(tmp_path: Path, name: str, raw: bytes, **options) -> tuple[bytes, dict]:
    source = tmp_path / name
    source.write_bytes(raw)
    result = sanitize_file(source, **options)
    return Path(result["sanitized_path"]).read_bytes(), result


# ── LSB decoding ──────────────────────────────────────────────────────────────


def test_decode_extracts_interleaved_rgb_lsb_payload_from_png(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(_png(_embed(b"attack at dawn", 400 * 3), 400, 1))

    result = decode_file(source)

    assert result["status"] == "DECODED"
    assert result["lsb"]["best"]["strategy"] == "interleaved RGB"
    assert result["lsb"]["best"]["decoded"] == "attack at dawn"
    assert result["lsb"]["format"] == "PNG"
    assert result["lsb"]["dimensions"] == [400, 1]


def test_decode_extracts_single_channel_lsb_payload(tmp_path):
    message = b"red channel secret"
    red = _embed(message, 300)
    pixels = bytearray(900)
    pixels[0::3] = red
    pixels[1::3] = b"\x80" * 300
    pixels[2::3] = b"\x81" * 300
    source = tmp_path / "image.png"
    source.write_bytes(_png(bytes(pixels), 300, 1))

    result = decode_file(source)

    assert result["lsb"]["best"]["strategy"] == "R channel"
    assert result["lsb"]["best"]["decoded"] == "red channel secret"


def test_decode_extracts_lsb_payload_from_24_bit_bmp(tmp_path):
    source = tmp_path / "image.bmp"
    rgb = _embed(b"bitmap secret", 400 * 3)
    stored = bytearray(rgb)  # BMP stores each pixel as blue, green, red
    stored[0::3], stored[2::3] = rgb[2::3], rgb[0::3]
    source.write_bytes(_bmp(bytes(stored), 400, 1))

    result = decode_file(source)

    assert result["lsb"]["best"]["decoded"] == "bitmap secret"


def test_decode_confidence_grows_with_payload_length_and_caps_at_point_nine(tmp_path):
    short = tmp_path / "short.png"
    short.write_bytes(_png(_embed(b"abcdefgh", 1200), 400, 1))
    long = tmp_path / "long.png"
    long.write_bytes(_png(_embed(b"abcdefghijklmnopqrstuvwxyz012345678", 1200), 400, 1))

    assert decode_file(short)["lsb"]["best"]["confidence"] == 0.225
    assert decode_file(long)["lsb"]["best"]["confidence"] == 0.9


def test_decode_reports_no_payload_for_an_image_with_uniform_lsbs(tmp_path):
    source = tmp_path / "flat.png"
    source.write_bytes(_png(b"\x80" * 1200, 400, 1))

    result = decode_file(source)

    assert result["status"] == "DECODED"
    assert result["lsb"]["best"] is None
    assert result["lsb"]["attempts"] == []


def test_decode_does_not_report_a_periodic_image_pattern_as_a_message(tmp_path):
    # An alternating 0/1 LSB pattern packs into the printable byte "U" repeatedly.
    source = tmp_path / "stripes.png"
    source.write_bytes(_png(bytes(0x80 | (i % 2) for i in range(1200)), 400, 1))

    assert decode_file(source)["lsb"]["best"] is None


def test_decode_does_not_report_text_shorter_than_the_minimum_length(tmp_path):
    source = tmp_path / "short.png"
    source.write_bytes(_png(_embed(b"abcdefg", 1200), 400, 1))

    assert decode_file(source)["lsb"]["best"] is None


def test_decode_lsb_examines_only_the_bounded_window(tmp_path, monkeypatch):
    samples = _LSB_WINDOW_BYTES * 8 + 800
    source = tmp_path / "large.png"
    source.write_bytes(_png(b"\x80" * samples, samples, 1, color_type=0))
    examined = []
    real_pack = binary_ops._pack_lsbs

    def record(data):
        examined.append(len(data))
        return real_pack(data)

    monkeypatch.setattr(binary_ops, "_pack_lsbs", record)

    decode_lsb(source, POLICY)

    assert examined == [_LSB_WINDOW_BYTES * 8]


def test_decode_raises_when_declared_pixels_exceed_the_limit(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(_png(b"\x80" * 1200, 400, 1))

    with pytest.raises(ResourceLimitError, match="max_image_pixels"):
        decode_file(source, limits={"max_image_pixels": 10})


def test_decode_leaves_the_source_file_unchanged(tmp_path):
    original = _png(_embed(b"attack at dawn", 1200), 400, 1)
    source = tmp_path / "image.png"
    source.write_bytes(original)

    decode_file(source)

    assert source.read_bytes() == original


# ── Metadata extraction ───────────────────────────────────────────────────────


def _field(metadata: dict, name: str) -> str:
    return next(item["value"] for item in metadata["fields"] if item["name"] == name)


def test_decode_reads_png_text_chunk():
    raw = _png(b"\x80" * 3, 1, 1, extra=_chunk(b"tEXt", b"Comment\x00hidden value"))

    metadata = extract_metadata(raw, ".png", POLICY)

    assert _field(metadata, "PNG:tEXt:Comment") == "hidden value"


def test_decode_reads_compressed_png_text_chunk():
    extra = _chunk(b"zTXt", b"Note\x00\x00" + zlib.compress(b"squeezed value"))
    raw = _png(b"\x80" * 3, 1, 1, extra=extra)

    metadata = extract_metadata(raw, ".png", POLICY)

    assert _field(metadata, "PNG:zTXt:Note") == "squeezed value"


def test_decode_reads_international_png_text_chunk():
    extra = _chunk(b"iTXt", b"Title\x00\x00\x00en\x00Titel\x00gr\xc3\xbcn")
    raw = _png(b"\x80" * 3, 1, 1, extra=extra)

    metadata = extract_metadata(raw, ".png", POLICY)

    assert _field(metadata, "PNG:iTXt:Title") == "grün"


def test_decode_enforces_the_decompression_budget_on_png_text():
    extra = _chunk(b"zTXt", b"Bomb\x00\x00" + zlib.compress(b"A" * 5000))
    raw = _png(b"\x80" * 3, 1, 1, extra=extra)

    with pytest.raises(ResourceLimitError, match="max_decompressed_bytes"):
        extract_metadata(raw, ".png", ScanLimits(max_decompressed_bytes=100))


def test_decompression_budget_is_shared_across_png_text_chunks():
    one = _chunk(b"zTXt", b"A\x00\x00" + zlib.compress(b"A" * 60))
    two = _chunk(b"zTXt", b"B\x00\x00" + zlib.compress(b"B" * 60))
    raw = _png(b"\x80" * 3, 1, 1, extra=one + two)

    with pytest.raises(ResourceLimitError, match="max_decompressed_bytes"):
        extract_metadata(raw, ".png", ScanLimits(max_decompressed_bytes=100))


def test_decode_enforces_the_findings_limit_on_metadata_fields():
    extra = _chunk(b"tEXt", b"A\x00one") + _chunk(b"tEXt", b"B\x00two")
    raw = _png(b"\x80" * 3, 1, 1, extra=extra)

    with pytest.raises(ResourceLimitError, match="max_findings"):
        extract_metadata(raw, ".png", ScanLimits(max_findings=1))


def test_decode_truncates_long_field_values_and_says_so():
    raw = _png(b"\x80" * 3, 1, 1, extra=_chunk(b"tEXt", b"Long\x00" + b"x" * 5000))

    item = extract_metadata(raw, ".png", POLICY)["fields"][0]

    assert len(item["value"]) == 4096
    assert item["truncated"] is True


def test_decode_recovers_zero_width_payload_inside_a_metadata_field():
    extra = _chunk(b"tEXt", b"Comment\x00" + ("cover" + ZERO_WIDTH_HI).encode("utf-8"))
    raw = _png(b"\x80" * 3, 1, 1, extra=extra)

    metadata = extract_metadata(raw, ".png", POLICY)

    assert metadata["zero_width_decoded"] == [
        {"field": "PNG:tEXt:Comment", "occurrences": 16, "decoded": "Hi"}
    ]


def test_decode_reads_jpeg_comment_and_exif_strings():
    raw = _jpeg(
        _segment(0xFE, b"jpeg comment"),
        _segment(0xE1, b"Exif\x00\x00\x00\x00camera note\x00"),
    )

    metadata = extract_metadata(raw, ".jpg", POLICY)

    assert _field(metadata, "JPEG:COM") == "jpeg comment"
    assert _field(metadata, "JPEG:EXIF") == "camera note"


def test_decode_reads_zip_archive_and_entry_comments():
    raw = _zip(archive_comment=b"archive note", entry_comment=b"entry note")

    metadata = extract_metadata(raw, ".zip", POLICY)

    assert _field(metadata, "ZIP:archive-comment") == "archive note"
    assert _field(metadata, "ZIP:comment:inner.txt") == "entry note"


def test_decode_rejects_zip_with_more_entries_than_the_member_limit():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("a.txt", "a")
        archive.writestr("b.txt", "b")

    with pytest.raises(ResourceLimitError, match="max_archive_members"):
        extract_metadata(stream.getvalue(), ".zip", ScanLimits(max_archive_members=1))


def test_decode_reads_id3v2_text_frame_with_each_declared_encoding():
    raw = _mp3(
        _id3_frame(b"TIT2", b"\x00caf\xe9"),
        _id3_frame(b"TPE1", b"\x01" + "artist".encode("utf-16")),
        _id3_frame(b"TALB", b"\x02" + "album".encode("utf-16-be")),
        _id3_frame(b"TCON", b"\x03gr\xc3\xbcn"),
    )

    metadata = extract_metadata(raw, ".mp3", POLICY)

    assert _field(metadata, "ID3:TIT2") == "café"
    assert _field(metadata, "ID3:TPE1") == "artist"
    assert _field(metadata, "ID3:TALB") == "album"
    assert _field(metadata, "ID3:TCON") == "grün"


def test_decode_reads_id3v24_frames_past_a_synchsafe_size_above_127():
    # v2.4 sizes are synchsafe: 0x0141 is 193 bytes, not 321 as a plain integer reads it.
    long_body = b"\x00" + b"x" * 192
    raw = _mp3(
        _id3_frame(b"TIT2", long_body, size_bytes=b"\x00\x00\x01\x41"),
        _id3_frame(b"TPE1", b"\x00after"),
    )

    metadata = extract_metadata(raw, ".mp3", POLICY)

    assert _field(metadata, "ID3:TPE1") == "after"


def test_decode_reads_id3_comment_frame_text():
    raw = _mp3(_id3_frame(b"COMM", b"\x00eng\x00the comment"))

    assert _field(extract_metadata(raw, ".mp3", POLICY), "ID3:COMM") == "the comment"


def test_decode_reads_id3v1_trailer_fields():
    v1 = b"TAG" + b"old title".ljust(30, b"\x00") + bytes(30) + bytes(30) + bytes(4)
    v1 += b"old comment".ljust(30, b"\x00") + b"\x00"
    raw = b"\xff\xfb\x90\x00AUDIO" + v1

    metadata = extract_metadata(raw, ".mp3", POLICY)

    assert _field(metadata, "ID3v1:title") == "old title"
    assert _field(metadata, "ID3v1:comment") == "old comment"


def test_decode_reads_pdf_info_string_with_nested_parentheses():
    raw = b"%PDF-1.7\n1 0 obj\n<< /Author (Jane (Doe) \\) Roe) >>\nendobj\n"

    metadata = extract_metadata(raw, ".pdf", POLICY)

    assert _field(metadata, "PDF:Author") == "Jane (Doe) \\) Roe"


def test_decode_reads_pdf_hex_info_string():
    raw = b"%PDF-1.7\n<< /Title <48696464656E> >>\n"

    assert _field(extract_metadata(raw, ".pdf", POLICY), "PDF:Title") == "Hidden"


def test_decode_reads_info_strings_anywhere_in_a_pdf():
    raw = b"%PDF-1.7\n" + b"%" + b"x" * 20000 + b"\n<< /Subject (late) >>\n"

    assert _field(extract_metadata(raw, ".pdf", POLICY), "PDF:Subject") == "late"


def test_decode_reads_gif_comment_extension():
    raw = _gif(_gif_extension(0xFE, b"gif comment"))

    assert _field(extract_metadata(raw, ".gif", POLICY), "GIF:comment") == "gif comment"


def test_decode_reads_tiff_ascii_tag():
    raw = _tiff(b"\x80" * 4, 2, 2, description=b"tiff note")

    assert _field(extract_metadata(raw, ".tiff", POLICY), "TIFF:ImageDescription") == "tiff note"


@pytest.mark.parametrize(
    ("suffix", "raw"),
    [
        (".png", b"\x89PNG\r\n\x1a\n\x00\xff"),
        (".png", b"not a png"),
        (".jpg", b"\xff\xd8\xff\xe1\xff\xff"),
        (".gif", b"GIF89a\x01"),
        (".tiff", b"II*\x00\xff\xff\xff\xff"),
        (".zip", b"PK\x05\x06"),
        (".mp3", b"ID3\x04\x00\x00\x7f\x7f\x7f\x7f"),
        (".pdf", b"not a pdf"),
        (".mp4", b"anything"),
    ],
)
def test_extract_metadata_returns_none_for_malformed_or_unknown_input(suffix, raw):
    assert extract_metadata(raw, suffix, POLICY) is None


def test_decode_reports_status_not_supported_for_an_unparsed_binary(tmp_path):
    source = tmp_path / "movie.mp4"
    source.write_bytes(b"not parsed")

    result = decode_file(source)

    assert result["status"] == "NOT_SUPPORTED"
    assert result["errors"] == ["This binary format is not supported or the file did not parse."]


# ── LSB sanitization ──────────────────────────────────────────────────────────


def test_destructive_sanitize_clears_every_rgb_png_lsb(tmp_path):
    pixels = _embed(b"attack at dawn", 1200)
    output, result = _sanitized(
        tmp_path, "image.png", _png(pixels, 400, 1), profile="destructive", channels=["lsb"]
    )

    channels, width, height, mode, _, _ = _load_pixels_png(output)
    assert (width, height, mode) == (400, 1, "RGB")
    assert channels["R"] == bytes(v & 0xFE for v in pixels[0::3])
    assert all(value & 1 == 0 for name in "RGB" for value in channels[name])
    assert result["changes"]["lsb_samples_cleared"] == sum(v & 1 for v in pixels)
    assert result["binary"]["lsb_method"] == "pixel-zero"
    assert result["sanitization_status"] == "SANITIZED"


def test_sanitize_changes_each_sample_by_at_most_one(tmp_path):
    pixels = bytes(range(256)) * 3
    output, _ = _sanitized(
        tmp_path, "image.png", _png(pixels, 256, 1), profile="destructive", channels=["lsb"]
    )

    channels = _load_pixels_png(output)[0]
    assert channels["G"] == bytes(v & 0xFE for v in pixels[1::3])


def test_sanitized_payload_can_no_longer_be_decoded(tmp_path):
    output, result = _sanitized(
        tmp_path, "image.png", _png(_embed(b"attack at dawn", 1200), 400, 1)
    )

    clean = tmp_path / "clean.png"
    clean.write_bytes(output)
    assert decode_file(clean)["lsb"]["best"] is None
    assert result["binary"]["lsb_method"] == "pixel-zero"


def test_sanitized_png_passes_the_detector_lsb_analysis(tmp_path):
    output, _ = _sanitized(tmp_path, "image.png", _png(_embed(b"attack at dawn", 1200), 400, 1))

    clean = tmp_path / "clean.png"
    clean.write_bytes(output)
    assert analyze_file(clean)["lsb_analysis"]["suspicious_channels"] == []


def test_conservative_sanitize_keeps_lsbs_without_evidence_and_warns(tmp_path):
    original = _png(b"\x80" * 1200, 400, 1)
    output, result = _sanitized(tmp_path, "flat.png", original)

    assert output == original
    assert result["changed"] is False
    assert result["binary"]["lsb_method"] == "kept_no_evidence"
    assert any("Use --profile destructive" in warning for warning in result["warnings"])


def test_conservative_sanitize_clears_lsbs_when_a_payload_decodes(tmp_path):
    output, result = _sanitized(
        tmp_path, "image.png", _png(_embed(b"attack at dawn", 1200), 400, 1)
    )

    assert result["changes"]["lsb_samples_cleared"] > 0
    assert all(value & 1 == 0 for value in _load_pixels_png(output)[0]["R"])


def test_lsb_channel_is_skipped_when_only_metadata_is_selected(tmp_path):
    pixels = _embed(b"attack at dawn", 1200)
    _, result = _sanitized(tmp_path, "image.png", _png(pixels, 400, 1), channels=["metadata"])

    assert result["binary"]["lsb_method"] == "not_applied"
    assert result["changes"]["lsb_samples_cleared"] == 0


def test_palette_png_is_expanded_so_colors_survive_lsb_clearing(tmp_path):
    # Indices 2 and 3 are unrelated colors. Clearing the index LSB would turn green red.
    palette = bytes([0, 0, 0, 255, 255, 255, 250, 0, 0, 0, 250, 0])
    raw = _png(bytes([3, 2]), 2, 1, color_type=3, palette=palette)
    output, result = _sanitized(tmp_path, "image.png", raw, profile="destructive", channels=["lsb"])

    channels, _, _, mode, _, _ = _load_pixels_png(output)
    assert mode == "RGB"
    assert channels["R"] == bytes([0, 250])
    assert channels["G"] == bytes([250, 0])
    assert channels["B"] == bytes([0, 0])
    assert result["binary"]["lsb_method"] == "palette-expanded"
    assert b"PLTE" not in _chunks_in(output)


def test_palette_png_transparency_becomes_an_alpha_channel(tmp_path):
    palette = bytes([10, 20, 30, 40, 50, 60])
    raw = _png(bytes([0, 1]), 2, 1, color_type=3, palette=palette, transparency=bytes([0]))
    output, _ = _sanitized(tmp_path, "image.png", raw, profile="destructive", channels=["lsb"])

    channels, _, _, mode, _, _ = _load_pixels_png(output)
    assert mode == "RGBA"
    assert channels["A"] == bytes([0, 254])
    assert channels["R"] == bytes([10, 40])


def test_palette_png_with_out_of_range_index_is_left_unchanged_and_reported(tmp_path):
    raw = _png(bytes([9]), 1, 1, color_type=3, palette=bytes([1, 2, 3]))
    output, result = _sanitized(tmp_path, "image.png", raw, profile="destructive", channels=["lsb"])

    assert output == raw
    assert result["sanitization_status"] == "PARTIAL"
    assert result["binary"]["lsb_method"] == "unsupported"


def test_color_key_transparency_follows_cleared_pixels(tmp_path):
    raw = _png(bytes([11, 21, 31]), 1, 1, transparency=struct.pack(">HHH", 11, 21, 31))
    output, _ = _sanitized(tmp_path, "image.png", raw, profile="destructive", channels=["lsb"])

    position = output.index(b"tRNS") + 4
    assert struct.unpack_from(">HHH", output, position) == (10, 20, 30)


def test_animated_png_lsbs_are_not_rewritten_because_frames_would_be_lost(tmp_path):
    extra = _chunk(b"acTL", struct.pack(">II", 2, 0))
    raw = _png(_embed(b"attack at dawn", 1200), 400, 1, extra=extra)
    output, result = _sanitized(tmp_path, "anim.png", raw)

    assert output == raw
    assert result["binary"]["lsb_method"] == "unsupported"
    assert result["sanitization_status"] == "PARTIAL"


def test_sanitized_png_has_valid_chunk_checksums(tmp_path):
    output, _ = _sanitized(tmp_path, "image.png", _png(_embed(b"attack at dawn", 1200), 400, 1))

    position = 8
    while position < len(output):
        length = struct.unpack_from(">I", output, position)[0]
        body = output[position + 4 : position + 8 + length]
        stored = struct.unpack_from(">I", output, position + 8 + length)[0]
        assert zlib.crc32(body) & 0xFFFFFFFF == stored
        position += 12 + length


def test_bmp_lsbs_are_cleared_in_place_preserving_header_and_size(tmp_path):
    pixels = bytes([0x81, 0x83, 0x85, 0xAA])  # one pixel, one byte of row padding
    raw = _bmp(pixels, 1, 1)
    output, result = _sanitized(tmp_path, "image.bmp", raw, profile="destructive")

    assert output[:54] == raw[:54]
    assert output[54:] == bytes([0x80, 0x82, 0x84, 0x00])
    assert result["changes"]["lsb_samples_cleared"] == 3


def test_sanitized_bmp_still_decodes(tmp_path):
    raw = _bmp(_embed(b"bitmap secret", 1200), 400, 1)
    output, _ = _sanitized(tmp_path, "image.bmp", raw, profile="destructive")

    assert all(value & 1 == 0 for value in _load_pixels_bmp(output)[0]["R"])


def test_bmp_with_pixels_past_end_of_file_is_left_unchanged(tmp_path):
    raw = _bmp(b"\x81" * 4, 100, 100)
    output, result = _sanitized(tmp_path, "image.bmp", raw, profile="destructive")

    assert output == raw
    assert result["sanitization_status"] == "NO_OP_UNSUPPORTED"


def test_tiff_lsbs_are_cleared_in_place_preserving_layout(tmp_path):
    raw = _tiff(bytes([0x81, 0x82, 0x83, 0x84]), 2, 2)
    output, result = _sanitized(
        tmp_path, "image.tiff", raw, profile="destructive", channels=["lsb"]
    )

    assert len(output) == len(raw)
    assert output[:-4] == raw[:-4]
    assert output[-4:] == bytes([0x80, 0x82, 0x82, 0x84])
    assert result["changes"]["lsb_samples_cleared"] == 2


def test_gif_lsbs_are_not_cleared_and_the_gap_is_reported(tmp_path):
    raw = _gif()
    output, result = _sanitized(tmp_path, "image.gif", raw, profile="destructive", channels=["lsb"])

    assert output == raw
    assert result["sanitization_status"] == "PARTIAL"
    assert result["binary"]["lsb_method"] == "unsupported"
    assert any("GIF palette indices" in warning for warning in result["warnings"])


def test_lsb_sanitize_enforces_the_pixel_limit_and_writes_nothing(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(_png(b"\x80" * 1200, 400, 1))

    with pytest.raises(ResourceLimitError, match="max_image_pixels"):
        sanitize_file(source, limits={"max_image_pixels": 10}, profile="destructive")

    assert not (tmp_path / "image.sanitized.png").exists()


# ── Metadata sanitization ─────────────────────────────────────────────────────


def test_sanitize_removes_png_text_chunks_and_appended_data(tmp_path):
    raw = _png(
        b"\x80" * 3,
        1,
        1,
        extra=_chunk(b"tEXt", b"Comment\x00hidden") + _chunk(b"gAMA", b"\x00\x00\xb1\x8f"),
        trailing=b"APPENDED PAYLOAD",
    )
    output, result = _sanitized(tmp_path, "image.png", raw, channels=["metadata"])

    assert _chunks_in(output) == [b"IHDR", b"gAMA", b"IDAT", b"IEND"]
    assert b"hidden" not in output
    assert b"APPENDED" not in output
    assert result["binary"]["metadata_removed"] == ["PNG:tEXt"]
    assert result["changes"]["metadata_removed"] == 1
    assert result["changes"]["trailing_bytes_removed"] == 16
    assert result["policy"]["applied"] == ["metadata"]


def test_conservative_sanitize_keeps_png_color_and_provenance_chunks(tmp_path):
    extra = _chunk(b"gAMA", b"\x00\x00\xb1\x8f") + _chunk(b"caBX", b"manifest")
    output, result = _sanitized(tmp_path, "image.png", _png(b"\x80" * 3, 1, 1, extra=extra))

    assert _chunks_in(output) == [b"IHDR", b"gAMA", b"caBX", b"IDAT", b"IEND"]
    assert result["changed"] is False


def test_destructive_sanitize_removes_png_color_and_provenance_chunks(tmp_path):
    extra = _chunk(b"gAMA", b"\x00\x00\xb1\x8f") + _chunk(b"caBX", b"manifest")
    output, _ = _sanitized(
        tmp_path,
        "image.png",
        _png(b"\x80" * 3, 1, 1, extra=extra),
        profile="destructive",
        channels=["metadata"],
    )

    assert _chunks_in(output) == [b"IHDR", b"IDAT", b"IEND"]


def test_sanitize_removes_unknown_private_png_chunks(tmp_path):
    output, _ = _sanitized(
        tmp_path,
        "image.png",
        _png(b"\x80" * 3, 1, 1, extra=_chunk(b"prVt", b"payload")),
        channels=["metadata"],
    )

    assert _chunks_in(output) == [b"IHDR", b"IDAT", b"IEND"]


def test_sanitize_removes_jpeg_comment_exif_and_appended_data(tmp_path):
    jfif = _segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    raw = _jpeg(
        jfif,
        _segment(0xFE, b"hidden comment"),
        _segment(0xE1, b"Exif\x00\x00secret"),
        trailing=b"APPENDED",
    )
    output, result = _sanitized(tmp_path, "photo.jpg", raw)

    assert output == _jpeg(jfif)
    assert result["binary"]["metadata_removed"] == ["JPEG:COM", "JPEG:APP1"]
    assert result["changes"]["trailing_bytes_removed"] == 8
    assert any("display rotated" in warning for warning in result["warnings"])


def test_jpeg_sanitize_reports_that_image_data_was_not_cleaned(tmp_path):
    _, result = _sanitized(tmp_path, "photo.jpg", _jpeg(_segment(0xFE, b"note")))

    assert result["sanitization_status"] == "PARTIAL"
    assert any("Transform-domain" in warning for warning in result["warnings"])


def test_conservative_sanitize_keeps_jpeg_icc_and_c2pa_segments(tmp_path):
    icc = _segment(0xE2, b"ICC_PROFILE\x00data")
    c2pa = _segment(0xEB, b"JP\x00\x00c2pa")
    raw = _jpeg(icc, c2pa, _segment(0xFE, b"note"))
    output, _ = _sanitized(tmp_path, "photo.jpg", raw)

    assert output == _jpeg(icc, c2pa)


def test_destructive_sanitize_removes_jpeg_icc_and_c2pa_segments(tmp_path):
    jfif = _segment(0xE0, b"JFIF\x00")
    raw = _jpeg(jfif, _segment(0xE2, b"ICC"), _segment(0xEB, b"c2pa"))
    output, _ = _sanitized(tmp_path, "photo.jpg", raw, profile="destructive")

    assert output == _jpeg(jfif)


def test_sanitize_removes_zip_comments_and_the_archive_stays_valid(tmp_path):
    raw = _zip(archive_comment=b"archive note", entry_comment=b"entry note")
    output, result = _sanitized(tmp_path, "data.zip", raw)

    with zipfile.ZipFile(io.BytesIO(output)) as archive:
        assert archive.comment == b""
        assert archive.getinfo("inner.txt").comment == b""
        assert archive.read("inner.txt") == b"inner contents"
        assert archive.testzip() is None
    assert b"archive note" not in output
    assert b"entry note" not in output
    # Python's reader tolerates stale lengths here, but stricter readers do not.
    central = output.index(b"PK\x01\x02")
    assert struct.unpack_from("<H", output, central + 32)[0] == 0
    end_record = output.index(b"PK\x05\x06")
    assert struct.unpack_from("<H", output, end_record + 20)[0] == 0
    assert end_record + 22 == len(output)
    assert sorted(result["binary"]["metadata_removed"]) == [
        "ZIP:archive-comment",
        "ZIP:entry-comment",
    ]


def test_zip_sanitize_warns_that_member_files_were_not_sanitized(tmp_path):
    _, result = _sanitized(tmp_path, "data.zip", _zip(archive_comment=b"note"))

    assert result["sanitization_status"] == "PARTIAL"
    assert any("Files inside the archive" in warning for warning in result["warnings"])
    assert any("digital signature" in warning for warning in result["warnings"])


def test_zip_without_comments_is_byte_identical_after_sanitize(tmp_path):
    raw = _zip()
    output, result = _sanitized(tmp_path, "data.zip", raw)

    assert output == raw
    assert result["changed"] is False


def test_sanitize_removes_id3v2_and_id3v1_leaving_audio(tmp_path):
    v1 = b"TAG" + b"old title".ljust(125, b"\x00")
    raw = _mp3(_id3_frame(b"TIT2", b"\x00secret"), v1=v1)
    output, result = _sanitized(tmp_path, "song.mp3", raw)

    assert output == b"\xff\xfb\x90\x00AUDIO"
    assert result["binary"]["metadata_removed"] == ["ID3v2", "ID3v1"]


def test_sanitize_blanks_pdf_info_at_the_same_length_preserving_offsets(tmp_path):
    raw = b"%PDF-1.7\n1 0 obj\n<< /Author (Jane) /Title (Doc) >>\nendobj\nstartxref\n42\n"
    output, result = _sanitized(tmp_path, "doc.pdf", raw)

    assert output == raw.replace(b"(Jane)", b"(    )").replace(b"(Doc)", b"(   )")
    assert len(output) == len(raw)
    assert result["binary"]["metadata_removed"] == ["PDF:Author", "PDF:Title"]
    assert result["sanitization_status"] == "PARTIAL"


def test_sanitize_blanks_uncompressed_pdf_xmp(tmp_path):
    xmp = b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>secret</x:xmpmeta>"
    raw = b"%PDF-1.7\n" + xmp + b"\n"
    output, result = _sanitized(tmp_path, "doc.pdf", raw)

    assert b"secret" not in output
    assert len(output) == len(raw)
    assert result["binary"]["metadata_removed"] == ["PDF:XMP"]


def test_sanitize_removes_gif_comment_but_keeps_the_loop_extension(tmp_path):
    loop = _gif_extension(0xFF, b"NETSCAPE2.0\x03\x01\x00\x00")
    comment = _gif_extension(0xFE, b"hidden")
    raw = _gif(loop, comment, trailing=b"APPENDED")
    output, result = _sanitized(tmp_path, "image.gif", raw, channels=["metadata"])

    assert output == _gif(loop)
    assert result["binary"]["metadata_removed"] == ["GIF:comment"]
    assert result["changes"]["trailing_bytes_removed"] == 8


def test_sanitize_blanks_tiff_ascii_tag_preserving_offsets(tmp_path):
    raw = _tiff(b"\x80" * 4, 2, 2, description=b"secret")
    output, result = _sanitized(tmp_path, "image.tiff", raw, channels=["metadata"])

    assert b"secret" not in output
    assert len(output) == len(raw)
    assert output[-4:] == b"\x80" * 4
    assert result["binary"]["metadata_removed"] == ["TIFF:ImageDescription"]


# ── Binary safety ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("image.png", b"\x89PNG\r\n\x1a\n\x00\xff"),
        ("photo.jpg", b"\xff\xd8plain\xff\xd9"),
        ("image.gif", b"GIF89a\x01"),
        ("image.tiff", b"II*\x00\xff\xff\xff\xff"),
        ("image.bmp", b"BM"),
        ("data.zip", b"PK\x05\x06"),
        ("doc.pdf", b"not a pdf"),
        ("movie.mp4", b"\x00\x00\x00\x18ftypmp42"),
    ],
)
@pytest.mark.parametrize("profile", ["conservative", "destructive"])
def test_malformed_or_unknown_binaries_are_copied_exactly(tmp_path, name, raw, profile):
    output, result = _sanitized(tmp_path, name, raw, profile=profile)

    assert output == raw
    assert result["sanitization_status"] == "NO_OP_UNSUPPORTED"
    assert result["changed"] is False


def test_zero_width_byte_sequences_inside_compressed_data_are_not_deleted(tmp_path):
    # Pro deleted these sequences from raw bytes, which would corrupt this archive.
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("inner.txt", "​‌ payload".encode("utf-8"))
    raw = stream.getvalue()
    assert "​".encode("utf-8") in raw

    output, _ = _sanitized(tmp_path, "data.zip", raw)

    assert output == raw


def test_text_channels_on_a_binary_file_change_nothing(tmp_path):
    raw = _png(_embed(b"attack at dawn", 1200), 400, 1, extra=_chunk(b"tEXt", b"A\x00b"))
    output, result = _sanitized(tmp_path, "image.png", raw, channels=["zero_width"])

    assert output == raw
    assert result["sanitization_status"] == "NO_OP_UNSUPPORTED"
    assert result["policy"]["channels"] == ["zero_width"]


def test_binary_channel_on_a_text_file_changes_nothing(tmp_path):
    source = tmp_path / "note.txt"
    source.write_text("visible​\n", encoding="utf-8")

    result = sanitize_file(source, channels=["lsb"])

    assert Path(result["sanitized_path"]).read_text(encoding="utf-8") == "visible​\n"
    assert result["policy"]["applied"] == []


def test_binary_report_default_policy_lists_binary_channels_only(tmp_path):
    _, result = _sanitized(tmp_path, "image.png", _png(b"\x80" * 3, 1, 1))

    assert result["policy"]["channels"] == ["metadata", "lsb"]


def test_sanitizing_a_binary_preserves_the_original_file(tmp_path):
    raw = _png(_embed(b"attack at dawn", 1200), 400, 1)
    source = tmp_path / "image.png"
    source.write_bytes(raw)

    result = sanitize_file(source)

    assert source.read_bytes() == raw
    assert result["original_preserved"] is True
    assert result["sha256_before"] != result["sha256_after"]


def test_in_place_binary_sanitize_overwrites_only_with_confirmation(tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(_png(b"\x80" * 3, 1, 1, extra=_chunk(b"tEXt", b"A\x00secret")))

    result = sanitize_file(source, in_place=True, confirm=True)

    assert b"secret" not in source.read_bytes()
    assert result["original_preserved"] is False


def test_metadata_change_reports_invalidated_provenance(tmp_path):
    source = tmp_path / "image.png"
    original = _png(b"\x80" * 3, 1, 1, extra=_chunk(b"tEXt", b"A\x00secret"))
    source.write_bytes(original)
    sidecar = tmp_path / "image.png.c2pa"
    sidecar.write_bytes(b"manifest")

    def validator(manifest, content, location):
        if content == original:
            return {"status": "VALID", "provider": "Example"}
        return {"status": "TAMPERED", "validation_errors": ["hash mismatch"]}

    result = sanitize_file(source, provenance_validator=validator)

    assert result["provenance_before"]["status"] == "VALID"
    assert result["provenance_impact"] == "invalidated"
