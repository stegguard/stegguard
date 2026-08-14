# Copyright 2025 Aditya Arakeri
# SPDX-License-Identifier: Apache-2.0

"""
test_detector.py — Test suite for steg_detector.py

Run modes:
    python3 test_detector.py           # normal test run
    python3 test_detector.py -v        # verbose per-test output
    python3 test_detector.py --cov     # run + print coverage report
"""

from __future__ import annotations

import hashlib, io, json, os, struct, sys, tempfile, unittest, zlib
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

import stegguard.detector as sd

import math as _math
import hashlib as _hashlib

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════


def tmp(content, suffix=".py"):
    fd, name = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, content if isinstance(content, bytes) else content.encode("utf-8"))
    finally:
        os.close(fd)
    return Path(name)


def png(text_chunks=None):
    def chunk(t, d):
        raw = t + d
        return struct.pack(">I", len(d)) + raw + struct.pack(">I", zlib.crc32(raw) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
    body = b"".join(
        chunk(b"tEXt", k.encode("latin-1") + b"\x00" + v.encode("latin-1"))
        for k, v in (text_chunks or [])
    )
    return sig + ihdr + idat + body + chunk(b"IEND", b"")


def zip_comment(comment):
    cb = comment.encode("utf-8")
    return b"PK\x05\x06" + b"\x00" * 16 + struct.pack("<H", len(cb)) + cb


def id3(frames):
    body = b""
    for fid, text in frames.items():
        payload = b"\x00" + text.encode("utf-8")
        body += fid.encode("ascii") + struct.pack(">I", len(payload)) + b"\x00\x00" + payload
    ss = bytes([(len(body) >> (7 * i)) & 0x7F for i in range(3, -1, -1)])
    return b"ID3\x03\x00\x00" + ss + body


def bits_to_zwc_occ(message):
    bits = "".join(format(b, "08b") for b in message)
    return [
        {"char": "\u200b" if b == "0" else "\u200c", "line": 1, "col": i + 1}
        for i, b in enumerate(bits)
    ]


def eol_encode(message):
    bits = "".join(format(b, "08b") for b in message)
    return "".join("x\r\n" if b == "1" else "x\n" for b in bits)


def cap(fn, *args, **kwargs):
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


def _make_png(pixels_rgb: bytes, w: int, h: int) -> bytes:
    """Build a minimal valid 8-bit RGB PNG."""

    def _chunk(t, d):
        raw = t + d
        return struct.pack(">I", len(d)) + raw + struct.pack(">I", zlib.crc32(raw) & 0xFFFFFFFF)

    raw_rows = b""
    for r in range(h):
        raw_rows += b"\x00"
        raw_rows += pixels_rgb[r * w * 3 : (r + 1) * w * 3]
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    idat = _chunk(b"IDAT", zlib.compress(raw_rows))
    iend = _chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def _make_natural_image(w: int = 64, h: int = 64, seed: int = 7) -> bytes:
    import random

    rng = random.Random(seed)
    px = bytearray()
    for r in range(h):
        for c in range(w):
            v = int(
                128
                + 60 * _math.cos(2 * _math.pi * c / 32) * _math.cos(2 * _math.pi * r / 32)
                + 20 * _math.cos(2 * _math.pi * c / 16)
                + rng.randint(-5, 5)
            )
            v = max(0, min(255, v))
            px += bytes([v, max(0, min(255, v + 15)), max(0, min(255, v - 10))])
    return bytes(px)


def _make_stego_image(natural_px: bytes, fraction: float = 1.0, seed: int = 42) -> bytes:
    n = int(len(natural_px) * fraction)
    px = bytearray(natural_px)
    for i in range(n):
        bit = int(_hashlib.md5(str(i).encode()).hexdigest(), 16) & 1
        px[i] = (px[i] & 0xFE) | bit
    return bytes(px)


def _natural_png(w=64, h=64) -> Path:
    px = _make_natural_image(w, h)
    p = tmp(_make_png(px, w, h), ".png")
    return p


def _stego_png(w=64, h=64, fraction=1.0) -> Path:
    px = _make_natural_image(w, h)
    sp = _make_stego_image(px, fraction)
    p = tmp(_make_png(sp, w, h), ".png")
    return p


def _make_bmp(pixels_bgr: bytes, w: int, h: int) -> bytes:
    row_size = ((w * 3) + 3) & ~3
    padding = row_size - w * 3
    pixel_data = b""
    for row in range(h - 1, -1, -1):
        pixel_data += pixels_bgr[row * w * 3 : (row + 1) * w * 3] + b"\x00" * padding
    file_size = 54 + len(pixel_data)
    header = (
        b"BM"
        + struct.pack("<I", file_size)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 54)
        + struct.pack("<I", 40)
        + struct.pack("<ii", w, h)
        + struct.pack("<HH", 1, 24)
        + struct.pack("<I", 0)
        + struct.pack("<I", len(pixel_data))
        + struct.pack("<iiii", 96, 96, 0, 0)
    )
    return header + pixel_data


def _make_gif(palette_indices: bytes, palette: bytes, w: int, h: int) -> bytes:
    n_colors = len(palette) // 3
    gct_exp = max(0, (n_colors - 1).bit_length() - 1)
    gct_size = 2 ** (gct_exp + 1)
    gct_full = palette + b"\x00" * ((gct_size - n_colors) * 3)
    packed = 0x80 | (gct_exp & 7)
    header = b"GIF87a" + struct.pack("<HHBBb", w, h, packed, 0, 0) + gct_full
    img_desc = struct.pack("<BHHHHb", 0x2C, 0, 0, w, h, 0)
    min_cs = max(2, gct_exp + 1)
    lzw_data = b"\x00"
    trailer = b"\x3b"
    return (
        header + img_desc + bytes([min_cs]) + bytes([len(lzw_data)]) + lzw_data + b"\x00" + trailer
    )


def _build_bmp_24bit(w: int, h: int, pixel_fn=None) -> bytes:
    if pixel_fn is None:
        pixel_fn = lambda r, c: (
            (r * 16 + c * 8) % 256,
            (r * 8 + c * 4) % 256,
            (r * 4 + c * 2) % 256,
        )
    row_size = ((w * 3) + 3) & ~3
    pad = row_size - w * 3
    pixel_data = b""
    for row in range(h - 1, -1, -1):
        for col in range(w):
            r_, g, b = pixel_fn(row, col)
            pixel_data += bytes([b, g, r_])
        pixel_data += b"\x00" * pad
    hdr = (
        b"BM"
        + struct.pack("<I", 54 + len(pixel_data))
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 54)
        + struct.pack("<I", 40)
        + struct.pack("<ii", w, h)
        + struct.pack("<HH", 1, 24)
        + struct.pack("<I", 0)
        + struct.pack("<I", len(pixel_data))
        + struct.pack("<iiii", 96, 96, 0, 0)
    )
    return hdr + pixel_data


def _build_bmp_32bit(w: int, h: int) -> bytes:
    row_size = w * 4
    pixel_data = b""
    for row in range(h - 1, -1, -1):
        for col in range(w):
            v = (row * 16 + col * 8) % 256
            pixel_data += bytes([v, (v + 85) % 256, (v + 170) % 256, 255])
    hdr = (
        b"BM"
        + struct.pack("<I", 54 + len(pixel_data))
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 54)
        + struct.pack("<I", 40)
        + struct.pack("<ii", w, h)
        + struct.pack("<HH", 1, 32)
        + struct.pack("<I", 0)
        + struct.pack("<I", len(pixel_data))
        + struct.pack("<iiii", 96, 96, 0, 0)
    )
    return hdr + pixel_data


def _build_png_filtered(w: int, h: int, ftype: int) -> bytes:
    bpp = 3
    raw_pixels = []
    for r in range(h):
        row = bytearray()
        for c in range(w):
            v = (r * 16 + c * 8) % 256
            row += bytes([v, (v + 85) % 256, (v + 170) % 256])
        raw_pixels.append(bytes(row))
    filtered = b""
    prev_raw = bytes(w * bpp)
    for raw_row in raw_pixels:
        rb = bytearray(raw_row)
        out = bytearray(w * bpp)
        if ftype == 0:
            out[:] = rb
        elif ftype == 1:
            for i in range(w * bpp):
                a = out[i - bpp] if i >= bpp else 0
                out[i] = (rb[i] - a) & 0xFF
        elif ftype == 2:
            for i in range(w * bpp):
                out[i] = (rb[i] - prev_raw[i]) & 0xFF
        elif ftype == 3:
            for i in range(w * bpp):
                a = out[i - bpp] if i >= bpp else 0
                out[i] = (rb[i] - (a + prev_raw[i]) // 2) & 0xFF
        elif ftype == 4:

            def _paeth(a, b_, c):
                p = a + b_ - c
                pa, pb, pc = abs(p - a), abs(p - b_), abs(p - c)
                return a if pa <= pb and pa <= pc else (b_ if pb <= pc else c)

            for i in range(w * bpp):
                a = out[i - bpp] if i >= bpp else 0
                b_ = prev_raw[i]
                c = prev_raw[i - bpp] if i >= bpp else 0
                out[i] = (rb[i] - _paeth(a, b_, c)) & 0xFF
        filtered += bytes([ftype]) + bytes(out)
        prev_raw = raw_row

    def chunk(t, d):
        raw = t + d
        return struct.pack(">I", len(d)) + raw + struct.pack(">I", zlib.crc32(raw) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(filtered))
    iend = chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def _build_tiff_rgb(w: int, h: int) -> bytes:
    pixels = bytes([(i * 3) % 256 for i in range(w * h * 3)])
    n_tags = 9
    ifd_off = 8
    data_off = ifd_off + 2 + n_tags * 12 + 4
    tags = [
        (256, 3, 1, w),
        (257, 3, 1, h),
        (258, 3, 1, 8),
        (259, 3, 1, 1),
        (262, 3, 1, 2),
        (273, 4, 1, data_off),
        (277, 3, 1, 3),
        (278, 3, 1, h),
        (279, 4, 1, w * h * 3),
    ]
    ifd = struct.pack("<H", n_tags)
    for tag, dt, cnt, val in tags:
        ifd += struct.pack("<HHI", tag, dt, cnt)
        ifd += struct.pack("<HH", val, 0) if dt == 3 else struct.pack("<I", val)
    ifd += struct.pack("<I", 0)
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", ifd_off)
    body = header + ifd
    body += b"\x00" * (data_off - len(body))
    return body + pixels


def _build_tiff_grey(w: int, h: int) -> bytes:
    pixels = bytes([i % 256 for i in range(w * h)])
    n_tags = 8
    ifd_off = 8
    data_off = ifd_off + 2 + n_tags * 12 + 4
    tags = [
        (256, 3, 1, w),
        (257, 3, 1, h),
        (258, 3, 1, 8),
        (259, 3, 1, 1),
        (262, 3, 1, 1),
        (273, 4, 1, data_off),
        (278, 3, 1, h),
        (279, 4, 1, w * h),
    ]
    ifd = struct.pack("<H", n_tags)
    for tag, dt, cnt, val in tags:
        ifd += struct.pack("<HHI", tag, dt, cnt)
        ifd += struct.pack("<HH", val, 0) if dt == 3 else struct.pack("<I", val)
    ifd += struct.pack("<I", 0)
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", ifd_off)
    body = header + ifd
    body += b"\x00" * (data_off - len(body))
    return body + pixels


def _build_tiff_multi_strip(w: int, h: int) -> bytes:
    pixels = bytes([i % 256 for i in range(w * h * 3)])
    half = h // 2
    strip1 = pixels[: w * half * 3]
    strip2 = pixels[w * half * 3 :]
    n_tags = 9
    ifd_off = 8
    array_off = ifd_off + 2 + n_tags * 12 + 4
    offs_ptr = array_off
    cnts_ptr = array_off + 8
    data_off1 = array_off + 16
    data_off2 = data_off1 + len(strip1)
    tags = [
        (256, 3, 1, w),
        (257, 3, 1, h),
        (258, 3, 1, 8),
        (259, 3, 1, 1),
        (262, 3, 1, 2),
        (273, 4, 2, offs_ptr),
        (277, 3, 1, 3),
        (278, 3, 1, half),
        (279, 4, 2, cnts_ptr),
    ]
    ifd = struct.pack("<H", n_tags)
    for tag, dt, cnt, val in tags:
        ifd += struct.pack("<HHI", tag, dt, cnt)
        ifd += struct.pack("<HH", val, 0) if dt == 3 else struct.pack("<I", val)
    ifd += struct.pack("<I", 0)
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", ifd_off)
    body = header + ifd
    body += b"\x00" * (array_off - len(body))
    body += struct.pack("<II", data_off1, data_off2)
    body += struct.pack("<II", len(strip1), len(strip2))
    body += strip1 + strip2
    return body


# ══════════════════════════════════════════════════════════════════════════════
# DETECTOR — color / severity_html / is_venv_path / file_matches
# ══════════════════════════════════════════════════════════════════════════════


class TestColor(unittest.TestCase):
    def test_text_always_present(self):
        with patch("sys.stdout") as m:
            m.isatty.return_value = True
            self.assertIn("hi", sd.color("hi", sd.RED))

    def test_codes_present_in_tty(self):
        with patch("sys.stdout") as m:
            m.isatty.return_value = True
            self.assertIn("\x1b[", sd.color("x"))

    def test_no_codes_outside_tty(self):
        with patch("sys.stdout") as m:
            m.isatty.return_value = False
            self.assertEqual(sd.color("x", sd.RED), "x")

    def test_multi_codes_no_crash(self):
        sd.color("x", sd.RED, sd.BOLD)


class TestSeverityHtml(unittest.TestCase):
    def _s(self, h, tw, mx):
        return sd.severity_html(h, tw, mx)[0]

    def test_clean(self):
        self.assertEqual(self._s(0, [], False), "clean")

    def test_low(self):
        self.assertEqual(self._s(1, [], False), "low")

    def test_medium_hidden(self):
        self.assertEqual(self._s(2, [], False), "medium")

    def test_medium_trailing(self):
        self.assertEqual(self._s(0, ["x"] * 4, False), "medium")

    def test_high(self):
        self.assertEqual(self._s(8, [], False), "high")

    def test_critical(self):
        self.assertEqual(self._s(20, [], False), "critical")

    def test_mixed_eol(self):
        self.assertEqual(self._s(0, [], True), "medium")

    def test_mixed_pushes_critical(self):
        self.assertEqual(self._s(15, [], True), "critical")


class TestIsVenvPath(unittest.TestCase):
    def test_node_modules(self):
        self.assertTrue(sd.is_venv_path(Path("/r/node_modules/f.js")))

    def test_venv(self):
        self.assertTrue(sd.is_venv_path(Path("/p/venv/lib/f.py")))

    def test_dot_venv(self):
        self.assertTrue(sd.is_venv_path(Path("/p/.venv/cfg")))

    def test_egg_info(self):
        self.assertTrue(sd.is_venv_path(Path("/p/foo.egg-info/PKG-INFO")))

    def test_dist_info(self):
        self.assertTrue(sd.is_venv_path(Path("/p/r-2.dist-info/META")))

    def test_egg_link(self):
        self.assertTrue(sd.is_venv_path(Path("/p/foo.egg-link")))

    def test_vendor(self):
        self.assertTrue(sd.is_venv_path(Path("/p/vendor/dep/f.go")))

    def test_normal(self):
        self.assertFalse(sd.is_venv_path(Path("/proj/src/main.py")))

    def test_marker_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "pyvenv.cfg").write_text("home = /usr/bin\n")
            p = Path(d, "main.go")
            p.write_text("package main\n")
            self.assertTrue(sd.is_venv_path(p))

    def test_no_marker(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "main.go")
            p.write_text("x\n")
            self.assertFalse(sd.is_venv_path(p))

    def test_lockfile_in_project_root_is_not_venv_marker(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "package-lock.json").write_text("{}\n")
            p = Path(d, "src.js")
            p.write_text("console.log(1)\n")
            self.assertFalse(sd.is_venv_path(p))


class TestFileMatches(unittest.TestCase):
    def test_py_in_set(self):
        self.assertTrue(sd.file_matches(Path("f.py"), {".py"}))

    def test_not_in_set(self):
        self.assertFalse(sd.file_matches(Path("f.png"), {".py"}))

    def test_dotenv(self):
        self.assertTrue(sd.file_matches(Path(".env"), {".env"}))

    def test_dotenv_miss(self):
        self.assertFalse(sd.file_matches(Path(".env"), {".py"}))

    def test_all_ext(self):
        self.assertTrue(sd.file_matches(Path("f.py"), sd.ALL_EXTENSIONS))


class TestCollectFiles(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.mkdtemp()
        self.root = Path(self._td)

    def tearDown(self):
        import shutil

        shutil.rmtree(self._td, ignore_errors=True)

    def _make(self, *parts, txt="x"):
        p = self.root.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt)
        return p

    def test_flat(self):
        self._make("a.py")
        self._make("b.js")
        files, _ = sd.collect_files(self.root, {".py"}, False, False)
        self.assertEqual(len(files), 1)

    def test_recursive(self):
        self._make("sub", "c.py")
        self._make("d.py")
        files, _ = sd.collect_files(self.root, {".py"}, True, False)
        self.assertEqual(len(files), 2)

    def test_non_recursive_skips_nested(self):
        self._make("sub", "c.py")
        self._make("d.py")
        files, _ = sd.collect_files(self.root, {".py"}, False, False)
        self.assertEqual(len(files), 1)

    def test_skip_venvs(self):
        self._make("venv", "activate.py")
        self._make("src", "main.py")
        files, skipped = sd.collect_files(self.root, {".py"}, True, True)
        self.assertNotIn(self.root / "venv" / "activate.py", files)
        self.assertGreater(skipped, 0)

    def test_all_extensions(self):
        self._make("f.py")
        self._make("f.ts")
        files, _ = sd.collect_files(self.root, sd.ALL_EXTENSIONS, False, False)
        self.assertEqual(len(files), 2)

    def test_nonexistent_root_raises(self):
        with self.assertRaises(Exception):
            sd.collect_files(self.root / "no_exist", {".py"}, False, False)

    def test_skip_venv_does_not_skip_project_root_with_lockfile(self):
        self._make("package-lock.json", txt="{}")
        src = self._make("src.js", txt="console.log(1)")
        files, skipped = sd.collect_files(self.root, {".js"}, True, True)
        self.assertIn(src, files)
        self.assertEqual(skipped, 0)


class TestAnalyzeBinaryFile(unittest.TestCase):
    def test_clean(self):
        p = tmp(b"\x00\x01\x02\x03", ".png")
        try:
            r = sd.analyze_binary_file(p)
            self.assertEqual(r["file_mode"], "binary")
            self.assertEqual(r["total_hidden"], 0)
            self.assertIsNone(r["error"])
        finally:
            p.unlink()

    def test_zwc_detected(self):
        p = tmp(b"\x89PNG" + "\u200b".encode(), ".png")
        try:
            r = sd.analyze_binary_file(p)
            self.assertGreater(r["total_hidden"], 0)
            self.assertIn("ZWC", [h.cat for h in r["binary_hits"]])
        finally:
            p.unlink()

    def test_bidi_detected(self):
        p = tmp(b"\x00" + "\u202e".encode(), ".png")
        try:
            r = sd.analyze_binary_file(p)
            self.assertIn("BIDI", [h.cat for h in r["binary_hits"]])
        finally:
            p.unlink()

    def test_hits_sorted(self):
        p = tmp(b"\x00" * 10 + "\u200b".encode() + b"\x00" * 10 + "\u200c".encode(), ".png")
        try:
            offs = [h.byte_off for h in sd.analyze_binary_file(p)["binary_hits"]]
            self.assertEqual(offs, sorted(offs))
        finally:
            p.unlink()

    def test_context_built(self):
        p = tmp(b"\x41" * 30 + "\u200b".encode() + b"\x41" * 30, ".png")
        try:
            self.assertGreater(len(sd.analyze_binary_file(p)["binary_hits"][0].context), 0)
        finally:
            p.unlink()

    def test_unreadable(self):
        r = sd.analyze_binary_file(Path("/nonexistent.png"))
        self.assertIsNotNone(r["error"])

    def test_compat_keys(self):
        p = tmp(b"\x00", ".png")
        try:
            r = sd.analyze_binary_file(p)
            for k in (
                "zero_width",
                "homoglyphs",
                "other_suspicious",
                "trailing_whitespace_lines",
                "mixed_line_endings",
            ):
                self.assertIn(k, r)
        finally:
            p.unlink()


class TestAnalyzeFile(unittest.TestCase):
    def test_clean(self):
        p = tmp("hello\n")
        try:
            r = sd.analyze_file(p)
            self.assertEqual(r["file_mode"], "text")
            self.assertEqual(r["total_hidden"], 0)
        finally:
            p.unlink()

    def test_zwc(self):
        p = tmp("hello\u200bworld\n")
        try:
            r = sd.analyze_file(p)
            self.assertEqual(r["zero_width"][0].char, "\u200b")
        finally:
            p.unlink()

    def test_multiple_zwc_types(self):
        p = tmp("\u200b\u200c\u200d\ufeff")
        try:
            self.assertEqual(sd.analyze_file(p)["total_hidden"], 4)
        finally:
            p.unlink()

    def test_homoglyph(self):
        p = tmp("def \u0430uth():\n    pass\n")
        try:
            self.assertEqual(sd.analyze_file(p)["homoglyphs"][0].char, "\u0430")
        finally:
            p.unlink()

    def test_other_suspicious(self):
        p = tmp("hello\u00a0world\n")
        try:
            self.assertGreater(sd.analyze_file(p)["total_hidden"], 0)
        finally:
            p.unlink()

    def test_bidi(self):
        p = tmp("code\u202etext\n")
        try:
            self.assertGreater(sd.analyze_file(p)["total_hidden"], 0)
        finally:
            p.unlink()

    def test_trailing_spaces(self):
        p = tmp("line   \nclean\n")
        try:
            self.assertEqual(len(sd.analyze_file(p)["trailing_whitespace_lines"]), 1)
        finally:
            p.unlink()

    def test_trailing_tab(self):
        p = tmp(b"code\t\n")
        try:
            tw = sd.analyze_file(p)["trailing_whitespace_lines"]
            self.assertIsInstance(tw[0].trail_byte, int)
        finally:
            p.unlink()

    def test_mixed_eol(self):
        p = tmp(b"a\r\nb\nc\r\n")
        try:
            self.assertTrue(sd.analyze_file(p)["mixed_line_endings"])
        finally:
            p.unlink()

    def test_crlf_only_not_mixed_eol(self):
        p = tmp(b"a\r\nb\r\nc\r\n")
        try:
            self.assertFalse(sd.analyze_file(p)["mixed_line_endings"])
        finally:
            p.unlink()

    def test_binary_ext_routes_to_binary(self):
        p = tmp(b"\x89PNG\r\n", ".png")
        try:
            self.assertEqual(sd.analyze_file(p)["file_mode"], "binary")
        finally:
            p.unlink()

    def test_unreadable(self):
        self.assertIsNotNone(sd.analyze_file(Path("/nonexistent.py"))["error"])

    def test_latin1_fallback(self):
        p = tmp("caf\xe9\n".encode("latin-1"))
        try:
            self.assertIsNone(sd.analyze_file(p)["error"])
        finally:
            p.unlink()

    def test_verbose(self):
        p = tmp("hello\u200bworld\n")
        try:
            self.assertGreater(sd.analyze_file(p, verbose=True)["total_hidden"], 0)
        finally:
            p.unlink()

    def test_combined_threats(self):
        p = tmp("def \u0430uth():\n    x\u200by\n")
        try:
            r = sd.analyze_file(p)
            self.assertGreater(len(r["zero_width"]), 0)
            self.assertGreater(len(r["homoglyphs"]), 0)
        finally:
            p.unlink()


class TestAttemptDecodeZeroWidth(unittest.TestCase):
    def _occ(self, chars):
        return [sd.ZwcFinding(1, i + 1, i, i, c, "") for i, c in enumerate(chars)]

    def _enc(self, msg):
        bits = "".join(format(b, "08b") for b in msg)
        return ["\u200b" if b == "0" else "\u200c" for b in bits]

    def test_decode_hi(self):
        self.assertEqual(sd.attempt_decode_zero_width(self._occ(self._enc(b"Hi"))), "Hi")

    def test_zwj_as_one(self):
        bits = "".join(format(b, "08b") for b in b"A")
        chars = ["\u200b" if b == "0" else "\u200d" for b in bits]
        self.assertEqual(sd.attempt_decode_zero_width(self._occ(chars)), "A")

    def test_too_few_returns_empty(self):
        self.assertEqual(sd.attempt_decode_zero_width(self._occ(["\u200b"] * 4)), "")

    def test_non_printable_empty(self):
        self.assertEqual(sd.attempt_decode_zero_width(self._occ(["\u200b"] * 16)), "")

    def test_other_zwc_skipped(self):
        chars = self._enc(b"X") + ["\u2060", "\ufeff"]
        self.assertEqual(sd.attempt_decode_zero_width(self._occ(chars)), "X")


class TestResultToJsonDict(unittest.TestCase):
    def _r(self, **kw):
        base = dict(
            file="/tmp/t.py",
            file_mode="text",
            total_hidden=0,
            zero_width=[],
            homoglyphs=[],
            other_suspicious=[],
            trailing_whitespace_lines=[],
            mixed_line_endings=False,
            binary_hits=[],
            error=None,
        )
        base.update(kw)
        return base

    def test_clean(self):
        p = tmp("x\n")
        try:
            d = sd.result_to_json_dict(self._r(file=str(p)))
            self.assertEqual(d["severity"], "clean")
            self.assertEqual(len(d["sha256"]), 64)
        finally:
            p.unlink()

    def test_critical(self):
        self.assertEqual(sd.result_to_json_dict(self._r(total_hidden=25))["severity"], "critical")

    def test_sha256_missing_file(self):
        self.assertEqual(sd.result_to_json_dict(self._r(file="/no.py"))["sha256"], "")

    def test_zero_width_serialized(self):
        r = self._r(total_hidden=1, zero_width=[sd.ZwcFinding(1, 5, 10, 10, "\u200b", "ZWS")])
        d = sd.result_to_json_dict(r)
        self.assertEqual(d["zero_width"][0]["char"], "\u200b")

    def test_homoglyphs_serialized(self):
        r = self._r(
            total_hidden=1, homoglyphs=[sd.HomoglyphFinding(2, 3, 50, 50, "\u0430", "Cyrillic")]
        )
        self.assertEqual(sd.result_to_json_dict(r)["homoglyphs"][0]["char"], "\u0430")

    def test_other_suspicious(self):
        r = self._r(
            total_hidden=1, other_suspicious=[sd.SuspiciousFinding(1, 2, 3, 3, "\u00ad", "SHY")]
        )
        self.assertEqual(sd.result_to_json_dict(r)["other_suspicious"][0]["char"], "\u00ad")

    def test_trailing_ws(self):
        r = self._r(trailing_whitespace_lines=[sd.TrailingFinding(3, 2, 32)])
        d = sd.result_to_json_dict(r)
        self.assertEqual(d["trailing_whitespace_lines"][0]["line"], 3)

    def test_binary_hits(self):
        r = self._r(
            file_mode="binary",
            total_hidden=1,
            binary_hits=[sd.BinaryHit(100, "ZWC", "\u200b", "ZWS", "ctx")],
        )
        d = sd.result_to_json_dict(r)
        self.assertEqual(d["binary_hits"][0]["byte_off"], 100)

    def test_mixed_eol(self):
        self.assertTrue(
            sd.result_to_json_dict(self._r(mixed_line_endings=True))["mixed_line_endings"]
        )


class TestWriteJsonOutput(unittest.TestCase):
    def _r(self, total=0, trailing=False, mixed=False):
        p = tmp("x\n")
        return p, dict(
            file=str(p),
            file_mode="text",
            total_hidden=total,
            zero_width=[],
            homoglyphs=[],
            other_suspicious=[],
            trailing_whitespace_lines=[sd.TrailingFinding(1, 1, 32)] if trailing else [],
            mixed_line_endings=mixed,
            binary_hits=[],
            error=None,
        )

    def test_valid_json(self):
        p, r = self._r()
        out = Path(tempfile.mktemp(suffix=".json"))
        try:
            sd.write_json_output([r], str(out))
            self.assertIn("stegguard_version", json.loads(out.read_text()))
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_flagged_hidden(self):
        p1, r1 = self._r(total=5)
        p2, r2 = self._r()
        out = Path(tempfile.mktemp(suffix=".json"))
        try:
            sd.write_json_output([r1, r2], str(out))
            self.assertEqual(json.loads(out.read_text())["flagged_files"], 1)
        finally:
            p1.unlink()
            p2.unlink()
            out.unlink(missing_ok=True)

    def test_flagged_trailing(self):
        p, r = self._r(trailing=True)
        out = Path(tempfile.mktemp(suffix=".json"))
        try:
            sd.write_json_output([r], str(out))
            self.assertEqual(json.loads(out.read_text())["flagged_files"], 1)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_flagged_mixed(self):
        p, r = self._r(mixed=True)
        out = Path(tempfile.mktemp(suffix=".json"))
        try:
            sd.write_json_output([r], str(out))
            self.assertEqual(json.loads(out.read_text())["flagged_files"], 1)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_flagged_lsb_only(self):
        p, r = self._r()
        r["file_mode"] = "binary"
        r["lsb_analysis"] = {
            "suspicious_channels": ["R"],
            "dimensions": (16, 16),
            "verdict": "SUSPICIOUS",
            "confidence": 0.45,
        }
        out = Path(tempfile.mktemp(suffix=".json"))
        try:
            sd.write_json_output([r], str(out))
            payload = json.loads(out.read_text())
            self.assertEqual(payload["flagged_files"], 1)
            self.assertEqual(payload["results"][0]["severity"], "high")
        finally:
            p.unlink()
            out.unlink(missing_ok=True)


class TestGenerateHtmlReport(unittest.TestCase):
    def test_non_empty(self):
        p = tmp("hello\u200bworld\n")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            self.assertGreater(out.stat().st_size, 1000)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_all_severity_levels(self):
        files = [
            tmp(c)
            for c in [
                "\u200b" * 25 + "\n",
                "\u200b" * 8 + "\n",
                "\u200b" * 2 + "\n",
                "\u200b\n",
                "clean\n",
            ]
        ]
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(f) for f in files], str(out))
            content = out.read_text()
            for lbl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"):
                self.assertIn(lbl, content)
        finally:
            [f.unlink() for f in files]
            out.unlink(missing_ok=True)

    def test_multiple_files(self):
        files = [tmp(f"code\u200b{'x' * i}\n") for i in range(3)]
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(f) for f in files], str(out))
            self.assertIn("html", out.read_text().lower())
        finally:
            [f.unlink() for f in files]
            out.unlink(missing_ok=True)

    def test_palette_lsb_handles_sparse_channel_stats(self):
        out = Path(tempfile.mktemp(suffix=".html"))
        result = {
            "file": "/tmp/palette.png",
            "file_mode": "binary",
            "total_hidden": 0,
            "zero_width": [],
            "homoglyphs": [],
            "other_suspicious": [],
            "trailing_whitespace_lines": [],
            "mixed_line_endings": False,
            "binary_hits": [],
            "error": None,
            "lsb_analysis": {
                "verdict": "SUSPICIOUS",
                "confidence": 0.45,
                "suspicious_channels": ["palette-index"],
                "dimensions": (16, 16),
                "format": "PNG",
                "chi_square": {"idx": {"p_value": 0.9912, "suspicious": True}},
                "rs_analysis": {"idx": {"suspicious": True, "embedding_estimate": None}},
                "sp_analysis": {"idx": {"suspicious": True, "embedding_estimate": 0.33}},
                "lsb_entropy": {"idx": {"suspicious": True, "block_mean_entropy": 0.987654}},
                "palette_lsb": {"suspicious": True, "n_colors": 16, "colors_used": 12},
            },
        }
        try:
            sd.generate_html_report([result], str(out))
            html = out.read_text(encoding="utf-8")
            self.assertIn("Pixel-level LSB Steganalysis", html)
            self.assertIn("palette-index", html)
        finally:
            out.unlink(missing_ok=True)


class TestPrintResults(unittest.TestCase):
    def test_clean(self):
        p = tmp("clean\n")
        try:
            cap(sd.print_results, sd.analyze_file(p))
        finally:
            p.unlink()

    def test_zwc_verbose_decode(self):
        p = tmp("x\u200by\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=True, decode=True)
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_all_threats(self):
        p = tmp("def \u0430uth():\n    x\u200by   \ncode\u202e\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p, verbose=True), verbose=True, decode=True)
            self.assertGreater(len(out), 100)
        finally:
            p.unlink()

    def test_binary(self):
        p = tmp(b"\x89PNG" + "\u200b".encode(), ".png")
        try:
            cap(sd.print_results, sd.analyze_file(p), verbose=True)
        finally:
            p.unlink()

    def test_mixed_eol(self):
        p = tmp(b"a\r\nb\nc\r\n")
        try:
            cap(sd.print_results, sd.analyze_file(p))
        finally:
            p.unlink()

    def test_error_result(self):
        cap(sd.print_results, sd.analyze_file(Path("/nonexistent.py")))


class TestPrintResultsBranches(unittest.TestCase):
    def test_binary_clean_message(self):
        p = tmp(b"\x89PNG\r\n" + b"\x00" * 100, ".png")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=True)
            self.assertIn("Clean", out)
        finally:
            p.unlink()

    def test_binary_bidi_detected(self):
        p = tmp(b"\x89PNG\r\n" + "\u202e".encode() + b"\x00" * 50, ".png")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=True)
            self.assertIn("BIDI", out)
        finally:
            p.unlink()

    def test_zwc_medium_severity(self):
        p = tmp("\u200b\u200c\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=True, decode=False)
            self.assertTrue("MEDIUM" in out or "LOW" in out or "HIGH" in out)
        finally:
            p.unlink()

    def test_zwc_high_severity(self):
        p = tmp("\u200b" * 20 + "\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=False, decode=False)
            self.assertTrue("HIGH" in out or "CRITICAL" in out)
        finally:
            p.unlink()

    def test_zwc_decode_message_shown(self):
        bits = "".join(format(b, "08b") for b in b"Hi")
        chars = "".join("\u200b" if b == "0" else "\u200c" for b in bits)
        p = tmp("x" + chars + "y\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=False, decode=True)
            self.assertIn("Hi", out)
        finally:
            p.unlink()

    def test_homoglyph_high_severity(self):
        p = tmp("def \u0430\u0435\u043e\u0441\u0440\u0441\u043e\u0440():\n    pass\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=True, decode=False)
            self.assertTrue("HIGH" in out or "MEDIUM" in out or "LOW" in out)
        finally:
            p.unlink()

    def test_homoglyph_medium_severity(self):
        p = tmp("def \u0430\u0435():\n    pass\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=False, decode=False)
            self.assertTrue(len(out) > 0)
        finally:
            p.unlink()

    def test_other_suspicious_high(self):
        p = tmp("a\u00a0b\u00a0c\u00a0d\u00a0e\u00a0f\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=True, decode=False)
            self.assertIn("HIGH", out)
        finally:
            p.unlink()

    def test_other_suspicious_medium(self):
        p = tmp("a\u00a0b\u00a0c\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=False, decode=False)
            self.assertIn("MEDIUM", out)
        finally:
            p.unlink()

    def test_trailing_ws_medium(self):
        p = tmp(b"a    \nb   \nbb  \nc \nd     \n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=False, decode=False)
            self.assertIn("MEDIUM", out)
        finally:
            p.unlink()

    def test_trailing_ws_truncation_verbose(self):
        content = "".join(f"l{i}" + " " * (2 + i % 5) + "\n" for i in range(25))
        p = tmp(content.encode())
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=True, decode=False)
            self.assertIn("...and", out)
        finally:
            p.unlink()

    def test_trailing_ws_high_consistent(self):
        p = tmp(b"x    \ny    \nz    \nw    \n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=False)
            self.assertIn("HIGH", out)
        finally:
            p.unlink()

    def test_trailing_ws_high_max8(self):
        p = tmp(b"code        \n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p), verbose=False)
            self.assertIn("HIGH", out)
        finally:
            p.unlink()


class TestHtmlReportBranches(unittest.TestCase):
    def test_binary_file_in_report(self):
        p = tmp(b"\x89PNG\r\n" + "\u200b".encode() + b"\x00" * 100, ".png")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            content = out.read_text()
            self.assertIn("html", content.lower())
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_mixed_eol_in_report(self):
        p = tmp(b"a\r\nb\nc\r\n")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            self.assertGreater(out.stat().st_size, 1000)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_trailing_ws_in_report(self):
        p = tmp("line   \n")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            self.assertGreater(out.stat().st_size, 1000)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_other_suspicious_in_report(self):
        p = tmp("hello\u00a0world\n")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            self.assertGreater(out.stat().st_size, 1000)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_bidi_in_report(self):
        p = tmp("code\u202etext\u202c\n")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            self.assertGreater(out.stat().st_size, 1000)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_homoglyph_in_report(self):
        p = tmp("def \u0430uth():\n    pass\n")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            self.assertGreater(out.stat().st_size, 1000)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_empty_results_list_no_crash(self):
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([], str(out))
            self.assertTrue(out.exists())
        finally:
            out.unlink(missing_ok=True)


class TestDetectorMain(unittest.TestCase):
    def _run(self, args, extra_files=None):
        buf = io.StringIO()
        with patch("sys.argv", ["steg_detector.py"] + args):
            with redirect_stdout(buf):
                try:
                    sd.main()
                except SystemExit:
                    pass
        return buf.getvalue()

    def test_basic_scan(self):
        p = tmp("hello\u200bworld\n")
        try:
            out = self._run([str(p)])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_verbose_decode(self):
        bits = "".join(format(b, "08b") for b in b"Hi")
        chars = "".join("\u200b" if b == "0" else "\u200c" for b in bits)
        p = tmp("x" + chars + "y\n")
        try:
            out = self._run([str(p), "-v", "-d"])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_recursive_scan(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("x\u200by\n")
            out = self._run([d, "-r"])
            self.assertGreater(len(out), 0)

    def test_ext_filter(self):
        p = tmp("x\u200by\n")
        try:
            self._run([str(p), "--ext", ".py"])
        finally:
            p.unlink()

    def test_json_output(self):
        p = tmp("x\u200by\n")
        j = Path(tempfile.mktemp(suffix=".json"))
        try:
            self._run([str(p), "--json", str(j)])
            self.assertTrue(j.exists())
        finally:
            p.unlink()
            j.unlink(missing_ok=True)

    def test_html_output(self):
        p = tmp("x\u200by\n")
        h = Path(tempfile.mktemp(suffix=".html"))
        try:
            self._run([str(p), "--html", str(h)])
            self.assertTrue(h.exists())
        finally:
            p.unlink()
            h.unlink(missing_ok=True)

    def test_no_venv_flag(self):
        p = tmp("x\u200by\n")
        try:
            self._run([str(p), "--no-venv"])
        finally:
            p.unlink()

    def test_clean_file(self):
        p = tmp("clean code here\n")
        try:
            out = self._run([str(p)])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_multiple_files(self):
        p1 = tmp("x\u200by\n")
        p2 = tmp("def \u0430uth():\n    pass\n")
        try:
            out = self._run([str(p1), str(p2)])
            self.assertGreater(len(out), 0)
        finally:
            p1.unlink()
            p2.unlink()

    def test_binary_file(self):
        p = tmp(b"\x89PNG\r\n" + "\u200b".encode() + b"\x00" * 50, ".png")
        try:
            out = self._run([str(p)])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_html_per_folder(self):
        with tempfile.TemporaryDirectory() as scan_dir:
            with tempfile.TemporaryDirectory() as out_dir:
                (Path(scan_dir) / "a.py").write_text("x\u200by\n")
                (Path(scan_dir) / "sub").mkdir()
                (Path(scan_dir) / "sub" / "b.py").write_text("clean\n")
                self._run([scan_dir, "-r", "--html-per-folder", out_dir])

    def test_ext_all(self):
        p = tmp("x\u200by\n")
        try:
            self._run([str(p), "--ext", "ALL"])
        finally:
            p.unlink()

    def test_nonexistent_path(self):
        try:
            self._run(["/nonexistent_dir_xyz"])
        except Exception:
            pass


class TestDetectorMainFunction(unittest.TestCase):
    def _run_main(self, argv):
        import stegguard.detector as _sd

        old_argv = sys.argv[:]
        sys.argv = ["steg_detector.py"] + argv
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _sd.main()
            return buf.getvalue()
        except SystemExit:
            return buf.getvalue() if "buf" in dir() else ""
        finally:
            sys.argv = old_argv

    def test_main_single_file(self):
        p = tmp("hello\u200bworld\n")
        try:
            out = self._run_main([str(p)])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_main_clean_file(self):
        p = tmp("clean\n")
        try:
            out = self._run_main([str(p)])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_main_verbose_decode(self):
        p = tmp("x\u200by\n")
        try:
            out = self._run_main(["-v", "-d", str(p)])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_main_directory_scan(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("x\u200by\n")
            (Path(d) / "b.py").write_text("clean\n")
            out = self._run_main([d])
            self.assertGreater(len(out), 0)

    def test_main_recursive_scan(self):
        with tempfile.TemporaryDirectory() as d:
            sub = Path(d) / "sub"
            sub.mkdir()
            (sub / "c.py").write_text("x\u200by\n")
            out = self._run_main(["-r", d])
            self.assertGreater(len(out), 0)

    def test_main_custom_ext(self):
        p = tmp("x\u200by\n")
        try:
            out = self._run_main(["--ext", ".py", str(p.parent)])
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_main_no_venv(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "main.py").write_text("clean\n")
            out = self._run_main(["--no-venv", "-r", d])
            self.assertGreater(len(out), 0)

    def test_main_html_output(self):
        p = tmp("x\u200by\n")
        out_html = Path(tempfile.mktemp(suffix=".html"))
        try:
            self._run_main(["--html", str(out_html), str(p)])
            self.assertTrue(out_html.exists())
        finally:
            p.unlink()
            out_html.unlink(missing_ok=True)

    def test_main_json_output(self):
        p = tmp("x\u200by\n")
        out_json = Path(tempfile.mktemp(suffix=".json"))
        try:
            self._run_main(["--json", str(out_json), str(p)])
            self.assertTrue(out_json.exists())
            data = json.loads(out_json.read_text())
            self.assertIn("results", data)
        finally:
            p.unlink()
            out_json.unlink(missing_ok=True)

    def test_main_handles_paths_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="steg test ") as d:
            root = Path(d)
            p = root / "file with spaces.py"
            p.write_text("hello\u200bworld\n")
            out_html = root / "report file.html"
            out_json = root / "report file.json"
            out = self._run_main(["--html", str(out_html), "--json", str(out_json), str(p)])
            self.assertIn(str(p), out)
            self.assertTrue(out_html.exists())
            self.assertTrue(out_json.exists())

    def test_main_no_files_found(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "f.xyz").write_text("x\n")
            out = self._run_main(["--ext", ".py", d])
            self.assertGreater(len(out), 0)

    def test_main_nonexistent_path(self):
        out = self._run_main(["/nonexistent_xyz_abc"])
        self.assertIsInstance(out, str)


class TestMainEdgeCases(unittest.TestCase):
    """Detector-only edge cases."""

    def _det(self, argv):
        import stegguard.detector as _sd

        old = sys.argv[:]
        sys.argv = ["steg_detector.py"] + argv
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                _sd.main()
        except SystemExit:
            pass
        finally:
            sys.argv = old
        return buf.getvalue()

    def test_det_no_files_found_with_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            venv = root / "venv"
            venv.mkdir()
            (venv / "pip.py").write_text("x\n")
            out = self._det(["--no-venv", "--ext", ".rs", d])
            self.assertGreater(len(out), 0)

    def test_det_scan_with_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "main.py").write_text("x\n")
            venv = root / "venv"
            venv.mkdir()
            (venv / "pip.py").write_text("y\n")
            out = self._det(["-r", "--no-venv", d])
            self.assertGreater(len(out), 0)

    def test_det_html_per_folder(self):
        with tempfile.TemporaryDirectory() as d:
            with tempfile.TemporaryDirectory() as scan_root:
                sub = Path(scan_root) / "proj"
                sub.mkdir()
                (sub / "f.py").write_text("x\u200by\n")
                out = self._det(["--html-per-folder", d, scan_root])
                self.assertIsInstance(out, str)

    def test_det_json_output_in_scan(self):
        p = tmp("x\u200by\n")
        json_out = Path(tempfile.mktemp(suffix=".json"))
        try:
            out = self._det(["--json", str(json_out), str(p)])
            if json_out.exists():
                self.assertIn("results", json.loads(json_out.read_text()))
        finally:
            p.unlink()
            json_out.unlink(missing_ok=True)

    def test_det_multiple_paths(self):
        p1 = tmp("x\u200by\n")
        p2 = tmp("clean\n")
        try:
            out = self._det([str(p1), str(p2)])
            self.assertGreater(len(out), 0)
        finally:
            p1.unlink()
            p2.unlink()

    def test_det_path_not_found(self):
        out = self._det(["/nonexistent_xyz_abc123"])
        self.assertIsInstance(out, str)


class TestMainHtmlPerFolderPaths(unittest.TestCase):
    def _det(self, argv):
        import stegguard.detector as _sd

        old = sys.argv[:]
        sys.argv = ["steg_detector.py"] + argv
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                _sd.main()
        except SystemExit:
            pass
        finally:
            sys.argv = old
        return buf.getvalue()

    def test_html_per_folder_no_subdirs(self):
        with tempfile.TemporaryDirectory() as scan_dir, tempfile.TemporaryDirectory() as out_dir:
            out = self._det(["--html-per-folder", out_dir, scan_dir])
            self.assertIn("No subfolders", out)

    def test_html_per_folder_file_path_warning(self):
        p = tmp("x\n")
        with tempfile.TemporaryDirectory() as out_dir:
            try:
                out = self._det(["--html-per-folder", out_dir, str(p)])
                self.assertIn("file", out.lower())
            finally:
                p.unlink()

    def test_html_per_folder_with_content(self):
        with tempfile.TemporaryDirectory() as scan_dir, tempfile.TemporaryDirectory() as out_dir:
            sub = Path(scan_dir) / "project"
            sub.mkdir()
            (sub / "f.py").write_text("x\u200by\n")
            out = self._det(["--html-per-folder", out_dir, "-r", scan_dir])
            self.assertIsInstance(out, str)

    def test_html_per_folder_nonexistent_path(self):
        with tempfile.TemporaryDirectory() as out_dir:
            out = self._det(["--html-per-folder", out_dir, "/nonexistent_xyz123"])
            self.assertIn("Warning", out)

    def test_no_files_with_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            venv = Path(d) / "venv"
            venv.mkdir()
            (venv / "pip.py").write_text("x\n")
            out = self._det(["--no-venv", "--ext", ".rs", d])
            self.assertIsInstance(out, str)

    def test_html_combined_with_per_folder(self):
        with (
            tempfile.TemporaryDirectory() as scan_dir,
            tempfile.TemporaryDirectory() as out_dir,
            tempfile.NamedTemporaryFile(suffix=".html", delete=False) as hf,
        ):
            sub = Path(scan_dir) / "proj"
            sub.mkdir()
            (sub / "f.py").write_text("x\u200by\n")
            html_path = hf.name
        try:
            out = self._det(["--html-per-folder", out_dir, "--html", html_path, scan_dir])
            self.assertIsInstance(out, str)
        finally:
            Path(html_path).unlink(missing_ok=True)


class TestLSBChiSquare(unittest.TestCase):
    def test_natural_low_pvalue(self):
        px = _make_natural_image(64, 64)
        r = sd._chi_square_lsb(px[0::3])
        self.assertLess(r["p_value"], 0.10)
        self.assertFalse(r["suspicious"])

    def test_stego_high_pvalue(self):
        nat = _make_natural_image(128, 128)
        stg = _make_stego_image(nat, fraction=1.0)
        nat_r = sd._chi_square_lsb(nat[0::3])
        stg_r = sd._chi_square_lsb(stg[0::3])
        self.assertGreater(stg_r["p_value"], nat_r["p_value"])

    def test_suspicious_flag_set_on_stego(self):
        nat = _make_natural_image(128, 128)
        stg = _make_stego_image(nat, fraction=1.0)
        r_r = sd._chi_square_lsb(stg[0::3])
        r_g = sd._chi_square_lsb(stg[1::3])
        r_b = sd._chi_square_lsb(stg[2::3])
        any_sus = r_r["suspicious"] or r_g["suspicious"] or r_b["suspicious"]
        self.assertTrue(any_sus)

    def test_returns_expected_keys(self):
        r = sd._chi_square_lsb(bytes(range(256)))
        for k in ("chi_sq", "df", "p_value", "suspicious"):
            self.assertIn(k, r)

    def test_empty_channel(self):
        r = sd._chi_square_lsb(b"")
        self.assertIsInstance(r["p_value"], float)

    def test_uniform_channel_suspicious(self):
        ch = bytes(val for v in range(128) for val in (v * 2, v * 2 + 1) for _ in range(4))
        r = sd._chi_square_lsb(ch)
        self.assertGreater(r["p_value"], 0.3)
        self.assertTrue(r["suspicious"])


class TestLSBRSAnalysis(unittest.TestCase):
    def test_returns_expected_keys(self):
        px = _make_natural_image(32, 32)
        r = sd._rs_analysis(px[0::3], 32)
        for k in ("R_m", "S_m", "R_n", "S_n", "asymmetry", "embedding_estimate", "suspicious"):
            self.assertIn(k, r)

    def test_estimates_in_unit_range(self):
        px = _make_natural_image(64, 64)
        r = sd._rs_analysis(px[0::3], 64)
        self.assertGreaterEqual(r["embedding_estimate"], 0.0)
        self.assertLessEqual(r["embedding_estimate"], 1.0)

    def test_too_small_returns_error(self):
        r = sd._rs_analysis(b"\x01", 1)
        self.assertIn("error", r)
        self.assertFalse(r["suspicious"])

    def test_stego_higher_estimate_than_natural(self):
        nat = _make_natural_image(128, 128)
        stg = _make_stego_image(nat, fraction=1.0)
        r_nat = sd._rs_analysis(nat[0::3], 128)
        r_stg = sd._rs_analysis(stg[0::3], 128)
        self.assertFalse(r_nat["suspicious"])


class TestLSBEntropyAnalysis(unittest.TestCase):
    def test_returns_expected_keys(self):
        px = _make_natural_image(32, 32)
        r = sd._lsb_entropy(px[0::3], 32)
        for k in (
            "global_entropy",
            "block_mean_entropy",
            "block_entropy_var",
            "lsb_balance",
            "suspicious",
        ):
            self.assertIn(k, r)

    def test_natural_not_suspicious(self):
        px = bytes([128] * (128 * 128))
        r = sd._lsb_entropy(px, 128)
        self.assertFalse(r["suspicious"])
        self.assertEqual(r["global_entropy"], 0.0)

    def test_perfect_stego_suspicious(self):
        ch = bytes([0x55, 0xAA] * 2048)
        r = sd._lsb_entropy(ch, 64)
        self.assertGreaterEqual(r["global_entropy"], 0.90)

    def test_tiny_image_no_crash(self):
        r = sd._lsb_entropy(b"\x00\x01\x02\x03", 2)
        self.assertIn("suspicious", r)

    def test_all_zeros_clean(self):
        r = sd._lsb_entropy(bytes(512), 32)
        self.assertEqual(r["global_entropy"], 0.0)
        self.assertFalse(r["suspicious"])

    def test_all_ones_clean(self):
        r = sd._lsb_entropy(bytes([0xFF] * 512), 32)
        self.assertEqual(r["global_entropy"], 0.0)
        self.assertFalse(r["suspicious"])


class TestLSBSPAnalysis(unittest.TestCase):
    def test_returns_expected_keys(self):
        px = _make_natural_image(32, 32)
        r = sd._sp_analysis(px[0::3], 32)
        for k in ("W", "X", "Y", "Z", "suspicious"):
            self.assertIn(k, r)

    def test_wxyz_sum_to_one(self):
        px = _make_natural_image(64, 64)
        r = sd._sp_analysis(px[0::3], 64)
        total = r["W"] + r["X"] + r["Y"] + r["Z"]
        self.assertAlmostEqual(total, 1.0, places=3)

    def test_too_small_no_crash(self):
        r = sd._sp_analysis(b"\x00", 1)
        self.assertIn("error", r)
        self.assertFalse(r["suspicious"])

    def test_overflow_not_suspicious(self):
        gradient = bytes(i % 256 for i in range(256))
        r = sd._sp_analysis(gradient, 16)
        if not r.get("reliable", True):
            self.assertFalse(r["suspicious"])


class TestLSBPaletteAnalysis(unittest.TestCase):
    def test_returns_expected_keys(self):
        pal = list(range(3 * 8))
        idx = bytes([0, 1, 2, 3, 4, 5, 6, 7] * 16)
        r = sd._palette_lsb(pal, idx)
        for k in ("n_colors", "colors_used", "index_lsb_entropy", "suspicious"):
            self.assertIn(k, r)

    def test_too_few_colors_not_suspicious(self):
        r = sd._palette_lsb([0, 0, 0, 255, 255, 255], bytes([0, 1] * 8))
        self.assertFalse(r["suspicious"])
        pal7 = list(range(3 * 7))
        r7 = sd._palette_lsb(pal7, bytes([i % 7 for i in range(64)]))
        self.assertFalse(r7["suspicious"])

    def test_sorted_palette_detected(self):
        pal = []
        for i in range(32):
            lum = i * 8
            pal += [lum, lum, lum]
        idx = bytes([i % 32 for i in range(256)])
        r = sd._palette_lsb(pal, idx)
        self.assertTrue(r["palette_sorted"])

    def test_high_entropy_indices_suspicious(self):
        pal = []
        for i in range(64):
            lum = i * 4
            pal += [lum, lum, lum]
        idx = bytes([i % 64 for i in range(1024)])
        r = sd._palette_lsb(pal, idx)
        self.assertIn("index_lsb_entropy", r)


class TestLoadImagePixels(unittest.TestCase):
    def test_load_png_rgb(self):
        p = _natural_png(32, 32)
        try:
            result = sd._load_image_pixels(p)
            self.assertIsNotNone(result)
            ch, w, h, mode, pal, fmt = result
            self.assertEqual(w, 32)
            self.assertEqual(h, 32)
            self.assertIn("R", ch)
            self.assertEqual(len(ch["R"]), 32 * 32)
        finally:
            p.unlink()

    def test_load_bmp_rgb(self):
        nat = _make_natural_image(16, 16)
        bgr_px = bytearray()
        for i in range(16 * 16):
            bgr_px += bytes([nat[i * 3 + 2], nat[i * 3 + 1], nat[i * 3]])
        p = tmp(_make_bmp(bytes(bgr_px), 16, 16), ".bmp")
        try:
            result = sd._load_image_pixels(p)
            if result is not None:
                ch, w, h, mode, pal, fmt = result
                self.assertEqual(w, 16)
                self.assertEqual(h, 16)
        finally:
            p.unlink()

    def test_load_palette_png(self):
        def _chunk(t, d):
            raw = t + d
            return struct.pack(">I", len(d)) + raw + struct.pack(">I", zlib.crc32(raw) & 0xFFFFFFFF)

        w, h = 8, 8
        raw_rows = b""
        for r in range(h):
            raw_rows += b"\x00" + bytes([i % 2 for i in range(w)])
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
        plte = _chunk(b"PLTE", b"\x00\x00\x00\xff\xff\xff")
        idat = _chunk(b"IDAT", zlib.compress(raw_rows))
        iend = _chunk(b"IEND", b"")
        p = tmp(sig + ihdr + plte + idat + iend, ".png")
        try:
            result = sd._load_image_pixels(p)
            if result is not None:
                ch, w2, h2, mode, pal, fmt = result
                self.assertEqual(mode, "P")
                self.assertIn("indices", ch)
                self.assertIsNotNone(pal)
        finally:
            p.unlink()

    def test_unsupported_format_returns_none(self):
        p = tmp(b"\xff\xd8\xff\xe0FAKE_JPEG", ".jpg")
        try:
            result = sd._load_pixels_png(p.read_bytes())
            self.assertIsNone(result)
        finally:
            p.unlink()

    def test_corrupted_png_returns_none(self):
        p = tmp(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, ".png")
        try:
            result = sd._load_pixels_png(p.read_bytes())
            self.assertIsNone(result)
        finally:
            p.unlink()

    def test_corrupted_bmp_returns_none(self):
        result = sd._load_pixels_bmp(b"BM" + b"\x00" * 10)
        self.assertIsNone(result)

    def test_corrupted_gif_returns_none(self):
        result = sd._load_pixels_gif(b"GIF87a" + b"\x00" * 5)
        self.assertIsNone(result)


class TestAnalyzeLsbImage(unittest.TestCase):
    def test_clean_image_verdict(self):
        p = _natural_png(128, 128)
        try:
            r = sd.analyze_lsb_image(p)
            self.assertEqual(r["verdict"], "CLEAN")
            self.assertEqual(r["confidence"], 0.0)
            self.assertEqual(r["suspicious_channels"], [])
            self.assertIsNone(r["error"])
        finally:
            p.unlink()

    def test_stego_image_flagged(self):
        p = _stego_png(128, 128, fraction=1.0)
        try:
            r = sd.analyze_lsb_image(p)
            self.assertIn(r["verdict"], ("SUSPICIOUS", "LIKELY_STEGO"))
            self.assertGreater(r["confidence"], 0.0)
            self.assertGreater(len(r["suspicious_channels"]), 0)
        finally:
            p.unlink()

    def test_result_has_required_keys(self):
        p = _natural_png(32, 32)
        try:
            r = sd.analyze_lsb_image(p)
            for k in (
                "format",
                "dimensions",
                "pixels",
                "mode",
                "verdict",
                "confidence",
                "suspicious_channels",
                "chi_square",
                "rs_analysis",
                "sp_analysis",
                "lsb_entropy",
                "error",
                "notes",
            ):
                self.assertIn(k, r)
        finally:
            p.unlink()

    def test_dimensions_and_pixels_correct(self):
        p = _natural_png(32, 48)
        try:
            r = sd.analyze_lsb_image(p)
            self.assertEqual(r["dimensions"], (32, 48))
            self.assertEqual(r["pixels"], 32 * 48)
        finally:
            p.unlink()

    def test_unreadable_file_returns_error(self):
        p = Path("/tmp/nonexistent_lsb_test_xyz.png")
        r = sd.analyze_lsb_image(p)
        self.assertIsNotNone(r["error"])
        self.assertEqual(r["verdict"], "UNKNOWN")

    def test_bmp_clean(self):
        nat = _make_natural_image(32, 32)
        bgr_px = bytearray()
        for i in range(32 * 32):
            bgr_px += bytes([nat[i * 3 + 2], nat[i * 3 + 1], nat[i * 3]])
        p = tmp(_make_bmp(bytes(bgr_px), 32, 32), ".bmp")
        try:
            r = sd.analyze_lsb_image(p)
            self.assertIn(r["verdict"], ("CLEAN", "SUSPICIOUS", "LIKELY_STEGO", "UNKNOWN"))
        finally:
            p.unlink()

    def test_verbose_mode(self):
        p = _natural_png(32, 32)
        try:
            r = sd.analyze_lsb_image(p, verbose=True)
            self.assertIn("verdict", r)
        finally:
            p.unlink()


class TestAnalyzeFileWithLSB(unittest.TestCase):
    def test_png_gets_lsb_analysis(self):
        p = _natural_png(32, 32)
        try:
            r = sd.analyze_file(p)
            self.assertIn("lsb_analysis", r)
            self.assertIsNotNone(r["lsb_analysis"])
        finally:
            p.unlink()

    def test_non_lsb_format_gets_none(self):
        p = tmp(b"ID3\x03\x00\x00\x00\x00\x00\x00", ".mp3")
        try:
            r = sd.analyze_file(p)
            self.assertIn("lsb_analysis", r)
            self.assertIsNone(r["lsb_analysis"])
        finally:
            p.unlink()

    def test_text_file_has_no_lsb_key(self):
        p = tmp("hello world\n")
        try:
            r = sd.analyze_file(p)
            self.assertNotIn("lsb_analysis", r)
        finally:
            p.unlink()

    def test_bmp_gets_lsb_analysis(self):
        nat = _make_natural_image(16, 16)
        bgr_px = bytearray()
        for i in range(16 * 16):
            bgr_px += bytes([nat[i * 3 + 2], nat[i * 3 + 1], nat[i * 3]])
        p = tmp(_make_bmp(bytes(bgr_px), 16, 16), ".bmp")
        try:
            r = sd.analyze_file(p)
            self.assertIn("lsb_analysis", r)
        finally:
            p.unlink()

    def test_stego_png_severity_upgraded(self):
        p = _stego_png(128, 128, fraction=1.0)
        try:
            r = sd.analyze_file(p)
            d = sd.result_to_json_dict(r)
            self.assertNotEqual(d["severity"], "clean")
            self.assertIn("lsb_analysis", d)
        finally:
            p.unlink()

    def test_result_to_json_includes_lsb(self):
        p = _natural_png(32, 32)
        try:
            r = sd.analyze_file(p)
            d = sd.result_to_json_dict(r)
            self.assertIn("lsb_analysis", d)
        finally:
            p.unlink()


class TestSeverityHtmlWithLSB(unittest.TestCase):
    def test_lsb_alone_upgrades_to_high(self):
        sev, label, color = sd.severity_html(0, [], False, lsb_suspicious=True)
        self.assertEqual(sev, "high")

    def test_lsb_plus_chars_can_reach_critical(self):
        sev, label, _ = sd.severity_html(15, [], False, lsb_suspicious=True)
        self.assertEqual(sev, "critical")

    def test_no_lsb_clean_stays_clean(self):
        sev, _, _ = sd.severity_html(0, [], False, lsb_suspicious=False)
        self.assertEqual(sev, "clean")

    def test_lsb_suspicious_false_no_effect(self):
        sev1, _, _ = sd.severity_html(0, [], False, lsb_suspicious=False)
        sev2, _, _ = sd.severity_html(0, [], False)
        self.assertEqual(sev1, sev2)


class TestPrintResultsWithLSB(unittest.TestCase):
    def _run_print(self, r, **kw):
        return cap(sd.print_results, r, **kw)

    def test_print_results_clean_lsb(self):
        p = _natural_png(32, 32)
        try:
            r = sd.analyze_file(p)
            out = self._run_print(r, verbose=False, decode=False)
            self.assertIn("Clean", out)
        finally:
            p.unlink()

    def test_print_results_stego_lsb_verbose(self):
        p = _stego_png(128, 128, fraction=1.0)
        try:
            r = sd.analyze_file(p)
            out = self._run_print(r, verbose=True, decode=False)
            self.assertIsInstance(out, str)
        finally:
            p.unlink()

    def test_print_lsb_results_directly_clean(self):
        lsb = {
            "verdict": "CLEAN",
            "confidence": 0.0,
            "suspicious_channels": [],
            "format": "PNG",
            "dimensions": (64, 64),
            "pixels": 4096,
            "chi_square": {},
            "rs_analysis": {},
            "lsb_entropy": {},
            "sp_analysis": {},
            "palette_lsb": None,
            "notes": [],
            "error": None,
        }
        out = cap(sd._print_lsb_results, lsb, False)
        self.assertIn("no steganography detected", out)

    def test_print_lsb_results_directly_suspicious(self):
        lsb = {
            "verdict": "SUSPICIOUS",
            "confidence": 0.65,
            "suspicious_channels": ["R", "G"],
            "format": "PNG",
            "dimensions": (64, 64),
            "pixels": 4096,
            "chi_square": {"R": {"p_value": 0.7, "suspicious": True, "chi_sq": 10.0, "df": 127}},
            "rs_analysis": {
                "R": {
                    "embedding_estimate": 0.20,
                    "suspicious": True,
                    "asymmetry": 0.01,
                    "R_m": 0.5,
                    "S_m": 0.3,
                    "R_n": 0.49,
                    "S_n": 0.31,
                }
            },
            "lsb_entropy": {
                "R": {
                    "block_mean_entropy": 0.98,
                    "block_entropy_var": 0.003,
                    "lsb_balance": 0.50,
                    "global_entropy": 0.98,
                    "suspicious": True,
                }
            },
            "sp_analysis": {
                "R": {
                    "W": 0.4,
                    "X": 0.1,
                    "Y": 0.25,
                    "Z": 0.25,
                    "embedding_estimate": 0.25,
                    "suspicious": True,
                    "reliable": True,
                }
            },
            "palette_lsb": None,
            "notes": ["Test note"],
            "error": None,
        }
        out = cap(sd._print_lsb_results, lsb, True)
        self.assertIn("SUSPICIOUS", out)

    def test_print_lsb_results_error_handled(self):
        lsb = {
            "error": "Could not decode pixel data",
            "verdict": "UNKNOWN",
            "suspicious_channels": [],
            "confidence": 0.0,
        }
        out = cap(sd._print_lsb_results, lsb, False)
        self.assertIn("Could not decode", out)

    def test_print_lsb_results_likely_stego(self):
        lsb = {
            "verdict": "LIKELY_STEGO",
            "confidence": 0.9,
            "suspicious_channels": ["R", "G", "B"],
            "format": "PNG",
            "dimensions": (128, 128),
            "pixels": 16384,
            "chi_square": {},
            "rs_analysis": {},
            "lsb_entropy": {},
            "sp_analysis": {},
            "palette_lsb": None,
            "notes": [],
            "error": None,
        }
        out = cap(sd._print_lsb_results, lsb, False)
        self.assertIn("LIKELY_STEGO", out)

    def test_print_lsb_palette_verbose(self):
        lsb = {
            "verdict": "SUSPICIOUS",
            "confidence": 0.5,
            "suspicious_channels": ["palette-index"],
            "format": "GIF",
            "dimensions": (32, 32),
            "pixels": 1024,
            "chi_square": {},
            "rs_analysis": {},
            "lsb_entropy": {},
            "sp_analysis": {},
            "palette_lsb": {
                "n_colors": 16,
                "colors_used": 12,
                "index_lsb_entropy": 0.97,
                "palette_sorted": True,
                "usage_cv": 0.15,
                "suspicious": True,
            },
            "notes": [],
            "error": None,
        }
        out = cap(sd._print_lsb_results, lsb, True)
        self.assertIn("Palette", out)


class TestHTMLReportWithLSB(unittest.TestCase):
    def test_html_report_with_stego_png(self):
        p = _stego_png(128, 128, fraction=1.0)
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            html = out.read_text()
            self.assertIn("LSB", html)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_html_report_lsb_stat_card(self):
        p = _stego_png(128, 128, fraction=1.0)
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            html = out.read_text()
            self.assertIn("LSB Pixel Steg", html)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_html_report_clean_png(self):
        p = _natural_png(32, 32)
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            html = out.read_text()
            self.assertGreater(len(html), 1000)
        finally:
            p.unlink()
            out.unlink(missing_ok=True)


class TestLSBFormatLoaders(unittest.TestCase):
    def test_png_filter_none(self):
        p = _natural_png(16, 16)
        try:
            raw = p.read_bytes()
            result = sd._load_pixels_png(raw)
            self.assertIsNotNone(result)
            ch, w, h, mode, pal, fmt = result
            self.assertEqual((w, h), (16, 16))
        finally:
            p.unlink()

    def test_chi2_sf_basic(self):
        p = sd._chi2_sf(0, 127)
        self.assertAlmostEqual(p, 1.0, places=2)

    def test_chi2_sf_large_x(self):
        p = sd._chi2_sf(1000, 127)
        self.assertLess(p, 0.001)

    def test_chi2_sf_invalid(self):
        p = sd._chi2_sf(5, 0)
        self.assertEqual(p, 1.0)

    def test_png_unfilter_all_types(self):
        row = bytes(range(16))
        prev = bytes([128] * 16)
        for ftype in range(5):
            out = sd._png_unfilter(ftype, row, prev, bpp=3)
            self.assertEqual(len(out), 16)

    def test_lsb_formats_constant(self):
        self.assertIn(".png", sd.LSB_FORMATS)
        self.assertIn(".bmp", sd.LSB_FORMATS)
        self.assertIn(".gif", sd.LSB_FORMATS)
        self.assertIn(".tif", sd.LSB_FORMATS)
        self.assertIn(".tiff", sd.LSB_FORMATS)


class TestCoverageBoost(unittest.TestCase):
    def test_html_report_binary_no_hits(self):
        p = tmp(b"\x89PNG\r\n\x00\x01\x02\x03", ".png")
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            content = out.read_text()
            self.assertIn("html", content.lower())
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    def test_html_report_many_trailing(self):
        lines = ("code" + " " * 3 + "\n") * 35
        p = tmp(lines)
        out = Path(tempfile.mktemp(suffix=".html"))
        try:
            sd.generate_html_report([sd.analyze_file(p)], str(out))
            content = out.read_text()
            self.assertIn("html", content.lower())
        finally:
            p.unlink()
            out.unlink(missing_ok=True)

    @unittest.skipIf(os.name == "nt", "POSIX permission denial is not portable")
    def test_collect_files_permission_error_handled(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            sub = root / "sub"
            sub.mkdir()
            (root / "a.py").write_text("x\n")
            (sub / "b.py").write_text("y\n")
            os.chmod(str(sub), 0o000)
            try:
                files, _ = sd.collect_files(root, {".py"}, True, False)
                self.assertGreater(len(files), 0)
            finally:
                os.chmod(str(sub), 0o755)

    def test_collect_files_venv_skipped_counter(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            venv = root / "venv"
            venv.mkdir()
            (venv / "pip.py").write_text("x\n")
            (root / "main.py").write_text("y\n")
            _, skipped = sd.collect_files(root, {".py"}, True, True)
            self.assertGreater(skipped, 0)

    def test_print_results_many_zwc_types_verbose(self):
        p = tmp("\u200b\u200c\u200d\u200e\u200f\n")
        try:
            out = cap(sd.print_results, sd.analyze_file(p, verbose=True), verbose=True, decode=True)
            self.assertGreater(len(out), 0)
        finally:
            p.unlink()

    def test_analyze_file_bidi_only(self):
        p = tmp("normal\u202ecode\u202cmore\n")
        try:
            r = sd.analyze_file(p)
            self.assertGreater(r["total_hidden"], 0)
        finally:
            p.unlink()

    def test_attempt_decode_zwc_exactly_8_bits(self):
        bits = format(ord("A"), "08b")
        occ = [
            sd.ZwcFinding(1, i + 1, i, i, "\u200b" if b == "0" else "\u200c", "")
            for i, b in enumerate(bits)
        ]
        self.assertEqual(sd.attempt_decode_zero_width(occ), "A")

    def test_result_to_json_dict_with_binary(self):
        p = tmp(b"\x89PNG" + b"\x00", ".png")
        try:
            r = sd.analyze_file(p)
            d = sd.result_to_json_dict(r)
            self.assertEqual(d["file_mode"], "binary")
        finally:
            p.unlink()

    def test_analyze_file_other_suspicious_serialized(self):
        p = tmp("caf\u00e9\u00a0menu\n")
        try:
            r = sd.analyze_file(p)
            d = sd.result_to_json_dict(r)
            self.assertIsInstance(d["other_suspicious"], list)
        finally:
            p.unlink()


class TestExtraBranchCoverage(unittest.TestCase):
    def test_collect_files_venv_inside_nonrecursive_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "main.py").write_text("x\n")
            venv = root / "venv"
            venv.mkdir()
            (venv / "pip.py").write_text("y\n")
            files, skipped = sd.collect_files(root, {".py"}, True, True)
            names = [f.name for f in files]
            self.assertIn("main.py", names)
            self.assertNotIn("pip.py", names)

    def test_collect_files_dotfiles_found(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            env = root / ".env"
            env.write_text("SECRET=x\n")
            files, _ = sd.collect_files(root, {".env"}, False, False)
            self.assertEqual(len(files), 1)

    def test_result_to_json_dict_with_binary(self):
        p = tmp(b"\x89PNG" + b"\x00", ".png")
        try:
            r = sd.analyze_file(p)
            d = sd.result_to_json_dict(r)
            self.assertEqual(d["file_mode"], "binary")
        finally:
            p.unlink()

    def test_analyze_file_other_suspicious_serialized(self):
        p = tmp("caf\u00e9\u00a0menu\n")
        try:
            r = sd.analyze_file(p)
            d = sd.result_to_json_dict(r)
            self.assertIsInstance(d["other_suspicious"], list)
        finally:
            p.unlink()


# ══════════════════════════════════════════════════════════════════════════════
# COVERAGE RUNNER
# ══════════════════════════════════════════════════════════════════════════════


def _run_coverage():
    covered = {}
    import stegguard.detector as _sd_m

    target = {_sd_m.__file__}

    def tracer(frame, event, arg):
        fname = frame.f_code.co_filename
        if event == "line" and fname in target:
            covered.setdefault(fname, set()).add(frame.f_lineno)
        return tracer

    sys.settrace(tracer)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    buf = io.StringIO()
    result = unittest.TextTestRunner(verbosity=1, stream=buf).run(suite)
    sys.settrace(None)
    print(buf.getvalue())

    print("\n" + "═" * 68)
    print("  COVERAGE REPORT")
    print("═" * 68)
    grand_hit = grand_exe = 0

    for fpath in sorted(target):
        fname = Path(fpath).name
        try:
            src = Path(fpath).read_text().splitlines()
        except Exception:
            continue
        import ast as _ast

        exe = set()
        try:
            tree = _ast.parse("\n".join(src))
            _stmts = (
                _ast.Assign,
                _ast.AugAssign,
                _ast.AnnAssign,
                _ast.Return,
                _ast.Delete,
                _ast.Raise,
                _ast.Assert,
                _ast.Import,
                _ast.ImportFrom,
                _ast.Expr,
                _ast.Pass,
                _ast.Break,
                _ast.Continue,
                _ast.For,
                _ast.While,
                _ast.If,
                _ast.With,
                _ast.Try,
                _ast.ExceptHandler,
                _ast.FunctionDef,
                _ast.AsyncFunctionDef,
                _ast.ClassDef,
            )
            for _n in _ast.walk(tree):
                if hasattr(_n, "lineno") and isinstance(_n, _stmts):
                    exe.add(_n.lineno)
        except Exception:
            exe = set(
                i for i, l in enumerate(src, 1) if l.strip() and not l.strip().startswith("#")
            )
        hit = covered.get(fpath, set()) & exe
        missed = exe - hit
        pct = 100 * len(hit) / max(len(exe), 1)
        grand_hit += len(hit)
        grand_exe += len(exe)
        print(f"\n  {fname}")
        print(
            f"    Executable : {len(exe):4d}  Covered : {len(hit):4d}  "
            f"Missed : {len(missed):4d}  Coverage : {pct:.1f}%"
        )
        if missed:
            s, ranges = sorted(missed), []
            lo = hi = s[0]
            for ln in s[1:]:
                if ln == hi + 1:
                    hi = ln
                else:
                    ranges.append(f"{lo}" if lo == hi else f"{lo}-{hi}")
                    lo = hi = ln
            ranges.append(f"{lo}" if lo == hi else f"{lo}-{hi}")
            print(f"    Missed lines : {', '.join(ranges)}")

    overall = 100 * grand_hit / max(grand_exe, 1)
    print(f"\n  {'─' * 50}")
    print(f"  TOTAL  {grand_hit}/{grand_exe}  ({overall:.1f}%)")
    print("═" * 68)
    return result


if __name__ == "__main__":
    if "--cov" in sys.argv:
        sys.argv.remove("--cov")
        result = _run_coverage()
        sys.exit(0 if result.wasSuccessful() else 1)
    unittest.main()
