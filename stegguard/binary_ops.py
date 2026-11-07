# SPDX-License-Identifier: Apache-2.0
"""Format-aware decoding and sanitization of binary files.

Every rewrite here understands the container it edits. Nothing deletes bytes from
a file without knowing what they are, because removing bytes blindly breaks ZIP
offsets, PNG checksums, and PDF cross-reference tables. A file that does not parse
is left untouched and reported as unsupported.
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from stegguard.detector import (
    LSB_FORMATS,
    ZERO_WIDTH_CHARS,
    _load_image_pixels,
    _load_pixels_png,
    analyze_lsb_image,
    attempt_decode_zero_width,
)
from stegguard.limits import ResourceLimitError, ScanLimits, decompress_limited

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_VALUE_CHARS = 4096
_MAX_STRINGS_PER_BLOCK = 40

# LSB payload search. Payloads start at the first sample, so a bounded window is
# enough and keeps the cost independent of image size.
_LSB_WINDOW_BYTES = 4096
_LSB_MIN_CHARS = 8
_LSB_MIN_DISTINCT_CHARS = 4  # periodic images produce runs such as "UUUUUUUU"
_LSB_FULL_CONFIDENCE_CHARS = 32

_CLEAR_LSB = bytes(value & 0xFE for value in range(256))
_LSB_AS_ASCII = bytes(0x30 + (value & 1) for value in range(256))

_STRING_PATTERN = re.compile(r"[^\x00-\x08\x0e-\x1f\x7f-\x9f�]{4,}")
_PDF_INFO_KEY = re.compile(
    rb"/(Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate)\s*([(<])"
)
_PDF_XMP = re.compile(rb"<x:xmpmeta\b.*?</x:xmpmeta>", re.DOTALL)

# Chunks needed to display a PNG. Conservative also keeps color management, physical
# size, animation, and C2PA provenance; destructive keeps only what pixels require.
_PNG_REQUIRED_CHUNKS = {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"}
_PNG_CONSERVATIVE_CHUNKS = _PNG_REQUIRED_CHUNKS | {
    b"gAMA",
    b"cHRM",
    b"sRGB",
    b"iCCP",
    b"sBIT",
    b"pHYs",
    b"bKGD",
    b"hIST",
    b"caBX",
    b"acTL",
    b"fcTL",
    b"fdAT",
}
_PNG_ANIMATION_CHUNKS = {b"acTL", b"fcTL", b"fdAT"}
_PNG_SAMPLES_PER_PIXEL = {0: 1, 2: 3, 4: 2, 6: 4}

# JPEG APPn markers: APP0 JFIF, APP14 Adobe color transform, APP2 ICC, APP11 C2PA.
_JPEG_REQUIRED_APP = {0xE0, 0xEE}
_JPEG_CONSERVATIVE_APP = _JPEG_REQUIRED_APP | {0xE2, 0xEB}

_ZIP_SUFFIXES = {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods"}

_TIFF_ASCII_TYPE = 2
_TIFF_METADATA_BLOB_TAGS = {700: "XMP", 33723: "IPTC", 34377: "Photoshop"}
_TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
_TIFF_TAG_NAMES = {
    269: "DocumentName",
    270: "ImageDescription",
    271: "Make",
    272: "Model",
    285: "PageName",
    305: "Software",
    306: "DateTime",
    315: "Artist",
    316: "HostComputer",
    33432: "Copyright",
}


def _text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _strings(data: bytes) -> list[str]:
    """Return readable runs from a binary block, keeping any zero-width characters."""
    readable = data.decode("utf-8", errors="replace")
    return _STRING_PATTERN.findall(readable)[:_MAX_STRINGS_PER_BLOCK]


class _Fields:
    """Collect metadata fields within the scan's finding budget."""

    def __init__(self, limits: ScanLimits) -> None:
        self._limit = limits.max_findings
        self.fields: list[dict[str, Any]] = []
        self.zero_width_decoded: list[dict[str, Any]] = []

    def add(self, name: str, value: str) -> None:
        if len(self.fields) >= self._limit:
            raise ResourceLimitError(f"max_findings exceeded: limit is {self._limit}")
        self.fields.append(
            {
                "name": name,
                "value": value[:_MAX_VALUE_CHARS],
                "truncated": len(value) > _MAX_VALUE_CHARS,
            }
        )
        hidden = [SimpleNamespace(char=char) for char in value if char in ZERO_WIDTH_CHARS]
        decoded = attempt_decode_zero_width(hidden)
        if decoded:
            self.zero_width_decoded.append(
                {"field": name, "occurrences": len(hidden), "decoded": decoded}
            )

    def add_strings(self, name: str, data: bytes) -> None:
        for value in _strings(data):
            self.add(name, value)


class _DecompressionBudget:
    """Share ``max_decompressed_bytes`` across every compressed field in one file."""

    def __init__(self, limits: ScanLimits) -> None:
        self._remaining = limits.max_decompressed_bytes

    def inflate(self, data: bytes) -> bytes:
        output = decompress_limited(data, self._remaining)
        self._remaining -= len(output)
        return output


# ── PNG ───────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class _Chunk:
    kind: bytes
    data: bytes


def _png_chunks(raw: bytes) -> tuple[list[_Chunk], int] | None:
    """Parse every chunk through IEND, returning them and the end offset."""
    if raw[:8] != _PNG_SIGNATURE:
        return None
    chunks: list[_Chunk] = []
    position = 8
    while position + 12 <= len(raw):
        length = struct.unpack_from(">I", raw, position)[0]
        end = position + 12 + length
        if end > len(raw):
            return None
        kind = raw[position + 4 : position + 8]
        chunks.append(_Chunk(kind, raw[position + 8 : position + 8 + length]))
        position = end
        if kind == b"IEND":
            return (chunks, end) if chunks[0].kind == b"IHDR" else None
    return None


def _png_serialize(chunks: list[_Chunk]) -> bytes:
    parts = [_PNG_SIGNATURE]
    for chunk in chunks:
        body = chunk.kind + chunk.data
        parts.append(struct.pack(">I", len(chunk.data)))
        parts.append(body)
        parts.append(struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))
    return b"".join(parts)


def _extract_png(raw: bytes, fields: _Fields, limits: ScanLimits) -> bool:
    parsed = _png_chunks(raw)
    if parsed is None:
        return False
    budget = _DecompressionBudget(limits)
    for chunk in parsed[0]:
        if chunk.kind == b"tEXt":
            key, _, value = chunk.data.partition(b"\x00")
            fields.add(f"PNG:tEXt:{_text(key)}", _text(value))
        elif chunk.kind == b"zTXt":
            key, _, rest = chunk.data.partition(b"\x00")
            try:
                fields.add(f"PNG:zTXt:{_text(key)}", _text(budget.inflate(rest[1:])))
            except zlib.error:
                fields.add(f"PNG:zTXt:{_text(key)}", "")
        elif chunk.kind == b"iTXt":
            key, _, rest = chunk.data.partition(b"\x00")
            compressed = rest[:1] == b"\x01"
            _, _, rest = rest[2:].partition(b"\x00")  # language tag
            _, _, value = rest.partition(b"\x00")  # translated keyword
            try:
                fields.add(
                    f"PNG:iTXt:{_text(key)}",
                    _text(budget.inflate(value) if compressed else value),
                )
            except zlib.error:
                fields.add(f"PNG:iTXt:{_text(key)}", "")
        elif chunk.kind == b"eXIf":
            fields.add_strings("PNG:eXIf", chunk.data)
    return True


def _strip_png(raw: bytes, profile: str) -> tuple[bytes, list[str], int] | None:
    parsed = _png_chunks(raw)
    if parsed is None:
        return None
    chunks, end = parsed
    allowed = _PNG_REQUIRED_CHUNKS if profile == "destructive" else _PNG_CONSERVATIVE_CHUNKS
    kept = [chunk for chunk in chunks if chunk.kind in allowed]
    removed = [
        f"PNG:{chunk.kind.decode('latin-1')}" for chunk in chunks if chunk.kind not in allowed
    ]
    trailing = len(raw) - end
    if not removed and not trailing:
        return raw, [], 0
    return _png_serialize(kept), removed, trailing


def _clear_png_lsbs(raw: bytes, limits: ScanLimits) -> tuple[bytes, int, str] | None:
    """Re-encode an 8-bit PNG with every sample LSB cleared.

    Palette images are expanded to RGB or RGBA rather than having their indices
    cleared. An index is not a sample: index 7 and index 6 can be unrelated colors,
    so clearing index bits would visibly corrupt the image.
    """
    parsed = _png_chunks(raw)
    if parsed is None:
        return None
    chunks = parsed[0]
    if any(chunk.kind in _PNG_ANIMATION_CHUNKS for chunk in chunks):
        return None
    loaded = _load_pixels_png(raw, limits)
    if loaded is None:
        return None
    channels, width, height, mode, palette, _ = loaded

    if mode == "P":
        transparency = next((c.data for c in chunks if c.kind == b"tRNS"), None)
        expanded = _expand_palette(channels["indices"], palette, transparency, width * height)
        if expanded is None:
            return None
        pixels, color_type = expanded
        cleared = channels["indices"].translate(_LSB_AS_ASCII).count(b"1")
        method = "palette-expanded"
    else:
        color_type = {"L": 0, "RGB": 2, "LA": 4, "RGBA": 6}[mode]
        step = _PNG_SAMPLES_PER_PIXEL[color_type]
        interleaved = bytearray(width * height * step)
        for offset, name in enumerate(mode):
            interleaved[offset::step] = channels[name]
        cleared = bytes(interleaved).translate(_LSB_AS_ASCII).count(b"1")
        pixels = bytes(interleaved).translate(_CLEAR_LSB)
        method = "pixel-zero"

    row_bytes = width * _PNG_SAMPLES_PER_PIXEL[color_type]
    scanlines = b"".join(
        b"\x00" + pixels[row * row_bytes : (row + 1) * row_bytes] for row in range(height)
    )
    header = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    rebuilt: list[_Chunk] = [_Chunk(b"IHDR", header)]
    for chunk in chunks:
        if chunk.kind in (b"IHDR", b"IDAT", b"IEND"):
            continue
        if mode == "P" and chunk.kind in (b"PLTE", b"tRNS", b"bKGD", b"hIST", b"sPLT"):
            continue  # these describe the palette that no longer exists
        if mode != "P" and chunk.kind == b"tRNS":
            # A color key must follow the pixels it matches.
            key = bytearray(chunk.data)
            key[1::2] = bytes(key[1::2]).translate(_CLEAR_LSB)
            rebuilt.append(_Chunk(b"tRNS", bytes(key)))
            continue
        rebuilt.append(chunk)
    rebuilt.append(_Chunk(b"IDAT", zlib.compress(scanlines, 6)))
    rebuilt.append(_Chunk(b"IEND", b""))
    return _png_serialize(rebuilt), cleared, method


def _expand_palette(
    indices: bytes,
    palette: list[int] | None,
    transparency: bytes | None,
    pixel_count: int,
) -> tuple[bytes, int] | None:
    if not palette or len(indices) != pixel_count:
        return None
    colors = len(palette) // 3
    if indices and max(indices) >= colors:
        return None
    tables = [
        bytes(palette[index * 3 + band] & 0xFE if index < colors else 0 for index in range(256))
        for band in range(3)
    ]
    step = 4 if transparency else 3
    pixels = bytearray(pixel_count * step)
    for band, table in enumerate(tables):
        pixels[band::step] = indices.translate(table)
    if transparency:
        alpha = bytes(
            (transparency[index] if index < len(transparency) else 255) & 0xFE
            for index in range(256)
        )
        pixels[3::4] = indices.translate(alpha)
    return bytes(pixels), 6 if transparency else 2


# ── JPEG ──────────────────────────────────────────────────────────────────────


def _jpeg_segments(raw: bytes) -> tuple[list[tuple[int, int, int]], int] | None:
    """Return (marker, start, end) for header segments, and the offset of SOS."""
    if raw[:2] != b"\xff\xd8":
        return None
    segments: list[tuple[int, int, int]] = []
    position = 2
    while position + 4 <= len(raw):
        if raw[position] != 0xFF:
            return None
        marker = raw[position + 1]
        if marker == 0xDA:
            return segments, position
        length = struct.unpack_from(">H", raw, position + 2)[0]
        end = position + 2 + length
        if length < 2 or end > len(raw):
            return None
        segments.append((marker, position, end))
        position = end
    return None


def _extract_jpeg(raw: bytes, fields: _Fields) -> bool:
    parsed = _jpeg_segments(raw)
    if parsed is None:
        return False
    for marker, start, end in parsed[0]:
        body = raw[start + 4 : end]
        if marker == 0xFE:
            fields.add("JPEG:COM", _text(body))
        elif marker == 0xE1 and body.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            fields.add("JPEG:XMP", _text(body.partition(b"\x00")[2]))
        elif marker == 0xE1 and body.startswith(b"Exif\x00\x00"):
            fields.add_strings("JPEG:EXIF", body[6:])
        elif marker == 0xED or 0xE3 <= marker <= 0xEF and marker not in _JPEG_CONSERVATIVE_APP:
            fields.add_strings(f"JPEG:APP{marker - 0xE0}", body)
    return True


def _strip_jpeg(raw: bytes, profile: str) -> tuple[bytes, list[str], int] | None:
    parsed = _jpeg_segments(raw)
    if parsed is None:
        return None
    segments, scan_start = parsed
    allowed = _JPEG_REQUIRED_APP if profile == "destructive" else _JPEG_CONSERVATIVE_APP
    parts = [raw[:2]]
    removed: list[str] = []
    for marker, start, end in segments:
        if marker == 0xFE:
            removed.append("JPEG:COM")
        elif 0xE0 <= marker <= 0xEF and marker not in allowed:
            removed.append(f"JPEG:APP{marker - 0xE0}")
        else:
            parts.append(raw[start:end])
    final_marker = raw.rfind(b"\xff\xd9", scan_start)
    if final_marker == -1:
        return None
    image_end = final_marker + 2
    parts.append(raw[scan_start:image_end])
    return b"".join(parts), removed, len(raw) - image_end


# ── GIF ───────────────────────────────────────────────────────────────────────


def _gif_blocks(raw: bytes) -> tuple[list[tuple[int, int, int, bytes]], int] | None:
    """Walk a GIF, returning extension blocks (label, start, end, data) and its end."""
    if raw[:6] not in (b"GIF87a", b"GIF89a") or len(raw) < 13:
        return None

    def skip_sub_blocks(position: int) -> tuple[int, bytes]:
        collected = bytearray()
        while True:
            size = raw[position]
            position += 1
            if size == 0:
                return position, bytes(collected)
            collected += raw[position : position + size]
            position += size

    packed = raw[10]
    position = 13 + (3 * 2 ** ((packed & 7) + 1) if packed & 0x80 else 0)
    blocks: list[tuple[int, int, int, bytes]] = []
    while True:
        block = raw[position]
        if block == 0x3B:
            return blocks, position + 1
        if block == 0x2C:
            local = raw[position + 9]
            position += 10 + (3 * 2 ** ((local & 7) + 1) if local & 0x80 else 0)
            position, _ = skip_sub_blocks(position + 1)  # minimum code size, then data
        elif block == 0x21:
            label = raw[position + 1]
            end, data = skip_sub_blocks(position + 2)
            blocks.append((label, position, end, data))
            position = end
        else:
            return None


def _is_gif_loop_extension(data: bytes) -> bool:
    return data.startswith((b"NETSCAPE2.0", b"ANIMEXTS1.0"))


def _extract_gif(raw: bytes, fields: _Fields) -> bool:
    parsed = _gif_blocks(raw)
    if parsed is None:
        return False
    for label, _, _, data in parsed[0]:
        if label == 0xFE:
            fields.add("GIF:comment", _text(data))
        elif label == 0x01:
            fields.add("GIF:plain-text", _text(data[12:]))
        elif label == 0xFF and not _is_gif_loop_extension(data):
            fields.add(f"GIF:application:{_text(data[:11])}", _text(data[11:]))
    return True


def _strip_gif(raw: bytes) -> tuple[bytes, list[str], int] | None:
    parsed = _gif_blocks(raw)
    if parsed is None:
        return None
    blocks, end = parsed
    names = {0xFE: "GIF:comment", 0x01: "GIF:plain-text", 0xFF: "GIF:application"}
    parts: list[bytes] = []
    removed: list[str] = []
    cursor = 0
    for label, start, block_end, data in blocks:
        keep_loop = label == 0xFF and _is_gif_loop_extension(data)
        if label in names and not keep_loop:
            parts.append(raw[cursor:start])
            cursor = block_end
            removed.append(names[label])
    parts.append(raw[cursor:end])
    return b"".join(parts), removed, len(raw) - end


# ── TIFF ──────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class _TiffEntry:
    tag: int
    kind: int
    count: int
    value_offset: int  # where the value bytes live, inline or out of line
    size: int


def _tiff_directory(raw: bytes) -> tuple[str, dict[int, _TiffEntry], int] | None:
    """Parse the first IFD, returning byte order, entries, and the next IFD offset."""
    order = {b"II": "<", b"MM": ">"}.get(raw[:2])
    if order is None or struct.unpack_from(f"{order}H", raw, 2)[0] != 42:
        return None
    directory = struct.unpack_from(f"{order}I", raw, 4)[0]
    count = struct.unpack_from(f"{order}H", raw, directory)[0]
    entries: dict[int, _TiffEntry] = {}
    for index in range(count):
        offset = directory + 2 + index * 12
        tag, kind, items = struct.unpack_from(f"{order}HHI", raw, offset)
        size = items * _TIFF_TYPE_SIZES.get(kind, 1)
        value_offset = (
            offset + 8 if size <= 4 else struct.unpack_from(f"{order}I", raw, offset + 8)[0]
        )
        if value_offset + size > len(raw):
            return None
        entries[tag] = _TiffEntry(tag, kind, items, value_offset, size)
    next_directory = struct.unpack_from(f"{order}I", raw, directory + 2 + count * 12)[0]
    return order, entries, next_directory


def _tiff_values(raw: bytes, order: str, entry: _TiffEntry) -> list[int]:
    code = {1: "B", 3: "H", 4: "I"}.get(entry.kind)
    if code is None:
        return []
    return list(struct.unpack_from(f"{order}{entry.count}{code}", raw, entry.value_offset))


def _tiff_metadata_entries(entries: dict[int, _TiffEntry]) -> list[tuple[str, _TiffEntry]]:
    found = []
    for tag, entry in entries.items():
        if tag in _TIFF_METADATA_BLOB_TAGS:
            found.append((_TIFF_METADATA_BLOB_TAGS[tag], entry))
        elif entry.kind == _TIFF_ASCII_TYPE:
            found.append((_TIFF_TAG_NAMES.get(tag, f"tag{tag}"), entry))
    return found


def _extract_tiff(raw: bytes, fields: _Fields) -> bool:
    parsed = _tiff_directory(raw)
    if parsed is None:
        return False
    for name, entry in _tiff_metadata_entries(parsed[1]):
        value = raw[entry.value_offset : entry.value_offset + entry.size].rstrip(b"\x00")
        fields.add(f"TIFF:{name}", _text(value))
    return True


def _strip_tiff(raw: bytes) -> tuple[bytes, list[str], int] | None:
    """Blank metadata values in place, so every offset in the file stays valid."""
    parsed = _tiff_directory(raw)
    if parsed is None:
        return None
    output = bytearray(raw)
    removed = []
    for name, entry in _tiff_metadata_entries(parsed[1]):
        region = raw[entry.value_offset : entry.value_offset + entry.size]
        if region.strip(b"\x00"):
            output[entry.value_offset : entry.value_offset + entry.size] = bytes(entry.size)
            removed.append(f"TIFF:{name}")
    return bytes(output), removed, 0


def _clear_tiff_lsbs(raw: bytes) -> tuple[bytes, int, str] | None:
    """Clear LSBs of uncompressed 8-bit strips in place, leaving the layout alone."""
    parsed = _tiff_directory(raw)
    if parsed is None:
        return None
    order, entries, next_directory = parsed
    if next_directory != 0 or 273 not in entries or 279 not in entries:
        return None

    def single(tag: int, default: int) -> int:
        values = _tiff_values(raw, order, entries[tag]) if tag in entries else [default]
        return values[0] if values and len(set(values)) == 1 else -1

    if (
        single(259, 1) != 1  # compression
        or single(258, 8) != 8  # bits per sample
        or single(284, 1) != 1  # planar configuration
        or single(262, 2) not in (0, 1, 2)  # grayscale or RGB, not palette
    ):
        return None
    offsets = _tiff_values(raw, order, entries[273])
    lengths = _tiff_values(raw, order, entries[279])
    if not offsets or len(offsets) != len(lengths):
        return None
    if any(start + length > len(raw) for start, length in zip(offsets, lengths)):
        return None
    output = bytearray(raw)
    cleared = 0
    for start, length in zip(offsets, lengths):
        strip = raw[start : start + length]
        cleared += strip.translate(_LSB_AS_ASCII).count(b"1")
        output[start : start + length] = strip.translate(_CLEAR_LSB)
    return bytes(output), cleared, "pixel-zero"


# ── BMP ───────────────────────────────────────────────────────────────────────


def _clear_bmp_lsbs(raw: bytes) -> tuple[bytes, int, str] | None:
    """Clear LSBs of uncompressed 24- and 32-bit rows in place, and zero row padding."""
    if len(raw) < 54 or raw[:2] != b"BM":
        return None
    pixel_offset = struct.unpack_from("<I", raw, 10)[0]
    width = struct.unpack_from("<i", raw, 18)[0]
    height = abs(struct.unpack_from("<i", raw, 22)[0])
    depth = struct.unpack_from("<H", raw, 28)[0]
    compression = struct.unpack_from("<I", raw, 30)[0]
    if compression != 0 or depth not in (24, 32) or width <= 0 or height == 0:
        return None
    row_bytes = width * (depth // 8)
    stride = (row_bytes + 3) & ~3
    if pixel_offset + stride * height > len(raw):
        return None
    output = bytearray(raw)
    cleared = 0
    for row in range(height):
        start = pixel_offset + row * stride
        samples = raw[start : start + row_bytes]
        cleared += samples.translate(_LSB_AS_ASCII).count(b"1")
        output[start : start + row_bytes] = samples.translate(_CLEAR_LSB)
        output[start + row_bytes : start + stride] = bytes(stride - row_bytes)
    return bytes(output), cleared, "pixel-zero"


# ── ZIP ───────────────────────────────────────────────────────────────────────


def _zip_end_record(raw: bytes) -> int | None:
    """Find the end-of-central-directory record whose comment reaches end of file."""
    position = len(raw)
    floor = max(0, len(raw) - 65557)
    while True:
        position = raw.rfind(b"PK\x05\x06", floor, position)
        if position == -1 or position + 22 > len(raw):
            return None
        comment_length = struct.unpack_from("<H", raw, position + 20)[0]
        if position + 22 + comment_length == len(raw):
            return position


def _zip_central_entries(
    raw: bytes, end_record: int, limits: ScanLimits
) -> list[tuple[int, int, int]] | None:
    """Return (offset, full length, comment length) per central entry; None for ZIP64."""
    count, size, start = struct.unpack_from("<HII", raw, end_record + 10)
    if 0xFFFFFFFF in (size, start) or count == 0xFFFF:
        return None
    if count > limits.max_archive_members:
        raise ResourceLimitError(
            f"max_archive_members exceeded: {count} > {limits.max_archive_members}"
        )
    entries = []
    position = start
    for _ in range(count):
        if raw[position : position + 4] != b"PK\x01\x02":
            return None
        name, extra, comment = struct.unpack_from("<HHH", raw, position + 28)
        length = 46 + name + extra + comment
        if position + length > end_record:
            return None
        entries.append((position, length, comment))
        position += length
    return entries if position == start + size else None


def _extract_zip(raw: bytes, fields: _Fields, limits: ScanLimits) -> bool:
    end_record = _zip_end_record(raw)
    if end_record is None:
        return False
    comment = raw[end_record + 22 :]
    if comment:
        fields.add("ZIP:archive-comment", _text(comment))
    for position, length, comment_length in _zip_central_entries(raw, end_record, limits) or []:
        if comment_length:
            name_length = struct.unpack_from("<H", raw, position + 28)[0]
            name = _text(raw[position + 46 : position + 46 + name_length])
            comment_start = position + length - comment_length
            fields.add(f"ZIP:comment:{name}", _text(raw[comment_start : position + length]))
    return True


def _strip_zip(raw: bytes, limits: ScanLimits) -> tuple[bytes, list[str], int] | None:
    end_record = _zip_end_record(raw)
    if end_record is None:
        return None
    entries = _zip_central_entries(raw, end_record, limits)
    if entries is None:
        return None
    start = struct.unpack_from("<I", raw, end_record + 16)[0]
    directory = bytearray()
    removed = []
    for position, length, comment_length in entries:
        entry = bytearray(raw[position : position + length - comment_length])
        if comment_length:
            entry[32:34] = b"\x00\x00"
            removed.append("ZIP:entry-comment")
        directory += entry
    record = bytearray(raw[end_record : end_record + 22])
    if end_record + 22 < len(raw):
        removed.append("ZIP:archive-comment")
    struct.pack_into("<I", record, 12, len(directory))
    struct.pack_into("<H", record, 20, 0)
    return raw[:start] + bytes(directory) + bytes(record), removed, 0


# ── ID3 ───────────────────────────────────────────────────────────────────────


def _synchsafe(data: bytes) -> int:
    return (data[0] & 0x7F) << 21 | (data[1] & 0x7F) << 14 | (data[2] & 0x7F) << 7 | data[3] & 0x7F


def _id3_tag_length(raw: bytes) -> int:
    """Return the full length of a leading ID3v2 tag, or 0 when there is none."""
    if raw[:3] != b"ID3" or len(raw) < 10:
        return 0
    footer = 10 if raw[5] & 0x10 else 0
    length = 10 + _synchsafe(raw[6:10]) + footer
    return length if length <= len(raw) else 0


def _id3_text(data: bytes) -> str:
    """Decode an ID3 text value using its leading encoding byte."""
    if not data:
        return ""
    encodings = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}
    encoding = encodings.get(data[0], "latin-1")
    return data[1:].decode(encoding, errors="replace").rstrip("\x00")


def _extract_mp3(raw: bytes, fields: _Fields) -> bool:
    length = _id3_tag_length(raw)
    has_v1 = len(raw) >= 128 and raw[-128:-125] == b"TAG"
    if not length and not has_v1:
        return False
    if length:
        version = raw[3]
        header, id_size = (6, 3) if version == 2 else (10, 4)
        position = 10
        while position + header <= length - (10 if raw[5] & 0x10 else 0):
            frame = raw[position : position + id_size].decode("latin-1")
            if not frame.strip("\x00"):
                break
            size_bytes = raw[position + id_size : position + id_size + (3 if version == 2 else 4)]
            size = _synchsafe(size_bytes) if version == 4 else int.from_bytes(size_bytes, "big")
            body = raw[position + header : position + header + size]
            if frame[0] == "T":
                fields.add(f"ID3:{frame}", _id3_text(body))
            elif frame in ("COMM", "USLT", "COM", "ULT"):
                encoding = body[:1]
                wide = encoding in (b"\x01", b"\x02")
                _, _, text = body[4:].partition(b"\x00\x00" if wide else b"\x00")
                fields.add(f"ID3:{frame}", _id3_text(encoding + text))
            elif frame in ("PRIV", "GEOB", "PRV", "GEO"):
                fields.add_strings(f"ID3:{frame}", body)
            position += header + size
    if has_v1:
        tag = raw[-128:]
        for name, start, end in (
            ("title", 3, 33),
            ("artist", 33, 63),
            ("album", 63, 93),
            ("year", 93, 97),
            ("comment", 97, 127),
        ):
            value = tag[start:end].rstrip(b"\x00 ")
            if value:
                fields.add(f"ID3v1:{name}", _text(value))
    return True


def _strip_mp3(raw: bytes) -> tuple[bytes, list[str], int] | None:
    length = _id3_tag_length(raw)
    has_v1 = len(raw) >= 128 and raw[-128:-125] == b"TAG"
    if not length and not has_v1:
        return None
    removed = (["ID3v2"] if length else []) + (["ID3v1"] if has_v1 else [])
    return raw[length : len(raw) - 128 if has_v1 else len(raw)], removed, 0


# ── PDF ───────────────────────────────────────────────────────────────────────


def _pdf_value_end(raw: bytes, start: int) -> int | None:
    """Return the offset of the delimiter closing the string opening at ``start``."""
    if raw[start] == 0x3C:  # hex string
        end = raw.find(b">", start)
        return end if end != -1 else None
    depth = 0
    position = start
    while position < len(raw):
        byte = raw[position]
        if byte == 0x5C:
            position += 2
            continue
        if byte == 0x28:
            depth += 1
        elif byte == 0x29:
            depth -= 1
            if depth == 0:
                return position
        position += 1
    return None


def _pdf_regions(raw: bytes) -> list[tuple[str, int, int]] | None:
    """Locate Info strings and uncompressed XMP as (name, start, end) value spans."""
    if not raw.startswith(b"%PDF-"):
        return None
    regions = []
    for match in _PDF_INFO_KEY.finditer(raw):
        opening = match.start(2)
        end = _pdf_value_end(raw, opening)
        if end is not None:
            regions.append((f"PDF:{match.group(1).decode('ascii')}", opening + 1, end))
    for match in _PDF_XMP.finditer(raw):
        regions.append(("PDF:XMP", match.start(), match.end()))
    return regions


def _pdf_value(data: bytes, hex_string: bool) -> str:
    if hex_string:
        digits = re.sub(rb"[^0-9A-Fa-f]", b"", data)
        data = bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("ascii"))
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    return _text(data)


def _extract_pdf(raw: bytes, fields: _Fields) -> bool:
    regions = _pdf_regions(raw)
    if regions is None:
        return False
    for name, start, end in regions:
        fields.add(name, _pdf_value(raw[start:end], name != "PDF:XMP" and raw[start - 1] == 0x3C))
    return True


def _strip_pdf(raw: bytes) -> tuple[bytes, list[str], int] | None:
    """Blank values with spaces at the same length, so the xref table stays correct."""
    regions = _pdf_regions(raw)
    if regions is None:
        return None
    output = bytearray(raw)
    removed = []
    for name, start, end in regions:
        if raw[start:end].strip():
            output[start:end] = b" " * (end - start)
            removed.append(name)
    return bytes(output), removed, 0


# ── Public entry points ───────────────────────────────────────────────────────

_PARSE_ERRORS = (struct.error, IndexError, ValueError)


def extract_metadata(raw: bytes, suffix: str, limits: ScanLimits) -> dict[str, Any] | None:
    """Read hidden-capable metadata fields, or return None when the format is unknown."""
    fields = _Fields(limits)
    extractors: dict[str, Callable[[], bool]] = {
        ".png": lambda: _extract_png(raw, fields, limits),
        ".jpg": lambda: _extract_jpeg(raw, fields),
        ".jpeg": lambda: _extract_jpeg(raw, fields),
        ".gif": lambda: _extract_gif(raw, fields),
        ".tif": lambda: _extract_tiff(raw, fields),
        ".tiff": lambda: _extract_tiff(raw, fields),
        ".mp3": lambda: _extract_mp3(raw, fields),
        ".pdf": lambda: _extract_pdf(raw, fields),
    }
    if suffix in _ZIP_SUFFIXES:
        extractors[suffix] = lambda: _extract_zip(raw, fields, limits)
    extractor = extractors.get(suffix)
    if extractor is None:
        return None
    try:
        recognized = extractor()
    except ResourceLimitError:
        raise
    except _PARSE_ERRORS:
        return None
    if not recognized:
        return None
    return {"fields": fields.fields, "zero_width_decoded": fields.zero_width_decoded}


def _pack_lsbs(samples: bytes) -> bytes:
    bits = samples.translate(_LSB_AS_ASCII)
    usable = len(bits) - len(bits) % 8
    if not usable:
        return b""
    return int(bits[:usable], 2).to_bytes(usable // 8, "big")


def _leading_text(payload: bytes) -> str:
    """Return the readable text at the start of a payload, if it looks like a message."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        text = payload[: error.start].decode("utf-8")
    for index, char in enumerate(text):
        if not (char.isprintable() or char in "\t\r\n"):
            text = text[:index]
            break
    if len(text) < _LSB_MIN_CHARS or len(set(text)) < _LSB_MIN_DISTINCT_CHARS:
        return ""
    return text


def _lsb_strategies(channels: dict[str, bytes], mode: str) -> list[tuple[str, bytes]]:
    """Build each candidate sample ordering, limited to the search window."""
    window_samples = _LSB_WINDOW_BYTES * 8
    if mode == "P":
        return [("palette-index", channels["indices"][:window_samples])]

    def interleaved(names: str) -> bytes:
        pixels = window_samples // len(names) + 1
        length = min(pixels, min(len(channels[name]) for name in names))
        flat = bytearray(length * len(names))
        for offset, name in enumerate(names):
            flat[offset :: len(names)] = channels[name][:length]
        return bytes(flat[:window_samples])

    names = [name for name in mode if name in channels]
    strategies: list[tuple[str, bytes]] = []
    if len(names) > 1:
        strategies.append((f"interleaved {mode}", interleaved(mode)))
    # Single channels come before sequential, which matches the first channel when the
    # window ends inside it, so that a one-channel payload gets the more specific label.
    strategies.extend((f"{name} channel", channels[name][:window_samples]) for name in names)
    if len(names) > 1:
        sequential = b"".join(channels[name][:window_samples] for name in names)
        strategies.append((f"sequential {mode}", sequential[:window_samples]))
    if "A" in names and len(names) > 2:
        visible = "".join(name for name in mode if name != "A")
        strategies.append((f"interleaved {visible}", interleaved(visible)))
    return strategies


def decode_lsb(path: Path, limits: ScanLimits) -> dict[str, Any] | None:
    """Look for readable text in pixel LSBs; None when pixels cannot be decoded.

    This finds plain text starting at the first sample. Encrypted, compressed,
    length-prefixed, or randomly spread payloads look like noise, so an empty result
    is not evidence that an image is clean.
    """
    if path.suffix.lower() not in LSB_FORMATS:
        return None
    loaded = _load_image_pixels(path, limits)
    if loaded is None:
        return None
    channels, width, height, mode, _, image_format = loaded
    strategies = _lsb_strategies(channels, mode)
    attempts: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for name, samples in strategies:
        payload = _pack_lsbs(samples)
        if payload in seen:
            continue
        seen.add(payload)
        text = _leading_text(payload)
        if text:
            attempts.append(
                {
                    "strategy": name,
                    "decoded": text,
                    "confidence": round(0.9 * min(len(text) / _LSB_FULL_CONFIDENCE_CHARS, 1.0), 3),
                }
            )
    attempts.sort(key=lambda attempt: attempt["confidence"], reverse=True)
    return {
        "format": image_format,
        "dimensions": [width, height],
        "mode": mode,
        "strategies_tried": len(seen),
        "best": attempts[0] if attempts else None,
        "attempts": attempts,
    }


@dataclass(slots=True)
class BinarySanitizeResult:
    """Outcome of sanitizing a binary file."""

    data: bytes
    status: str
    metadata_removed: list[str] = field(default_factory=list)
    trailing_bytes_removed: int = 0
    lsb_samples_cleared: int = 0
    lsb_method: str = "not_applied"
    warnings: list[str] = field(default_factory=list)


def _strip_metadata(
    raw: bytes, suffix: str, profile: str, limits: ScanLimits
) -> tuple[bytes, list[str], int] | None:
    strippers: dict[str, Callable[[], tuple[bytes, list[str], int] | None]] = {
        ".png": lambda: _strip_png(raw, profile),
        ".jpg": lambda: _strip_jpeg(raw, profile),
        ".jpeg": lambda: _strip_jpeg(raw, profile),
        ".gif": lambda: _strip_gif(raw),
        ".tif": lambda: _strip_tiff(raw),
        ".tiff": lambda: _strip_tiff(raw),
        ".mp3": lambda: _strip_mp3(raw),
        ".pdf": lambda: _strip_pdf(raw),
    }
    if suffix in _ZIP_SUFFIXES:
        strippers[suffix] = lambda: _strip_zip(raw, limits)
    stripper = strippers.get(suffix)
    if stripper is None:
        return None
    try:
        return stripper()
    except ResourceLimitError:
        raise
    except _PARSE_ERRORS:
        return None


def _clear_lsbs(raw: bytes, suffix: str, limits: ScanLimits) -> tuple[bytes, int, str] | None:
    try:
        if suffix == ".png":
            return _clear_png_lsbs(raw, limits)
        if suffix == ".bmp":
            return _clear_bmp_lsbs(raw)
        if suffix in (".tif", ".tiff"):
            return _clear_tiff_lsbs(raw)
    except ResourceLimitError:
        raise
    except _PARSE_ERRORS:
        return None
    return None


def _lsb_evidence(path: Path, limits: ScanLimits) -> bool | None:
    """Return whether pixels show a payload, or None when they cannot be read."""
    decoded = decode_lsb(path, limits)  # raises when the image exceeds the scan budget
    if decoded is None:
        return None
    if decoded["best"]:
        return True
    return bool(analyze_lsb_image(path, False, limits).get("suspicious_channels"))


def sanitize_binary(
    path: Path,
    raw: bytes,
    channels: tuple[str, ...],
    profile: str,
    limits: ScanLimits,
) -> BinarySanitizeResult:
    """Remove hidden content a format allows, reporting what could not be removed."""
    suffix = path.suffix.lower()
    result = BinarySanitizeResult(data=raw, status="NO_OP_UNSUPPORTED")
    handled = False
    gaps: list[str] = []

    if "metadata" in channels:
        stripped = _strip_metadata(raw, suffix, profile, limits)
        if stripped is not None:
            handled = True
            result.data, result.metadata_removed, result.trailing_bytes_removed = stripped
            if suffix in _ZIP_SUFFIXES:
                gaps.append(
                    "Only archive and entry comments were removed. Files inside the archive "
                    "were not sanitized."
                )
            elif suffix == ".pdf":
                gaps.append(
                    "Only Info strings and uncompressed XMP were blanked. Compressed objects, "
                    "attachments, and hidden layers were not sanitized."
                )
            elif suffix == ".mp3":
                gaps.append("Only ID3 tags were removed. Audio frames were not sanitized.")
            elif suffix in (".jpg", ".jpeg"):
                gaps.append(
                    "Compressed JPEG image data was not sanitized. Transform-domain payloads "
                    "survive metadata removal."
                )

    if "lsb" in channels and suffix in LSB_FORMATS:
        evidence = _lsb_evidence(path, limits)
        unreadable = (
            "Pixel LSBs were not cleared because this image layout is not supported "
            "(compressed, interlaced, animated, or not 8-bit)."
        )
        if profile == "destructive" or evidence:
            cleared = _clear_lsbs(result.data, suffix, limits)
            if cleared is not None:
                handled = True
                result.data, result.lsb_samples_cleared, result.lsb_method = cleared
            elif suffix == ".gif" and evidence is not None:
                gaps.append(
                    "Pixel LSBs were not cleared. Clearing GIF palette indices would change "
                    "image colors, so convert the image to remove this channel."
                )
                result.lsb_method = "unsupported"
            elif handled or evidence is not None:
                gaps.append(unreadable)
                result.lsb_method = "unsupported"
        elif evidence is None:
            if handled:
                gaps.append(unreadable)
                result.lsb_method = "unsupported"
        else:
            result.lsb_method = "kept_no_evidence"
            result.warnings.append(
                "Pixel LSBs were kept because analysis found no evidence of a payload. A short "
                "or encrypted payload can evade analysis. Use --profile destructive to clear "
                "them regardless."
            )

    result.warnings.extend(gaps)
    if handled:
        result.status = "PARTIAL" if gaps else "SANITIZED"
    elif gaps:
        result.status = "PARTIAL"
    elif result.lsb_method == "kept_no_evidence":
        result.status = "SANITIZED"
    if result.metadata_removed and any(
        name in ("JPEG:APP1", "PNG:eXIf") for name in result.metadata_removed
    ):
        result.warnings.append(
            "EXIF was removed, including any orientation tag, so the image may display rotated."
        )
    if result.data != raw and suffix in _ZIP_SUFFIXES | {".pdf"}:
        result.warnings.append("Any digital signature on this file is no longer valid.")
    return result
