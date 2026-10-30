#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create deterministic, harmless fixtures for the StegGuard demo."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import zlib


HIDDEN_TEXT = "DEMO"


def _zero_width_encode(value: str) -> str:
    return "".join(
        "\u200b" if bit == "0" else "\u200c"
        for byte in value.encode("utf-8")
        for bit in f"{byte:08b}"
    )


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)


def _demo_png() -> bytes:
    width = height = 16
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            value = 238 if (x + y) % 2 else 32
            rows.extend((value, 96, 255 - value))

    manifest = json.dumps(
        {
            "claim_generator": "StegGuard safe demo",
            "title": "Synthetic demonstration asset",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)),
            _png_chunk(b"tEXt", b"Comment\x00Synthetic StegGuard demo watermark marker"),
            _png_chunk(b"stEg", b"safe-demo-private-chunk"),
            _png_chunk(b"caBX", manifest),
            _png_chunk(b"IDAT", zlib.compress(bytes(rows), level=9)),
            _png_chunk(b"IEND", b""),
        )
    )


def create_samples(output_dir: Path) -> dict[str, object]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"sample output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    hidden = _zero_width_encode(HIDDEN_TEXT)
    suspicious = (
        "StegGuard safe demonstration file\r\n"
        f"Visible text before [{hidden}] visible text after\n"
        "Trailing whitespace follows this line    \r\n"
        "Homoglyph example: pаypal (the first a is Cyrillic)\n"
        "This fixture contains no executable or malicious payload.\n"
    )
    (output_dir / "suspicious.txt").write_bytes(suspicious.encode("utf-8"))
    (output_dir / "watermarked.png").write_bytes(_demo_png())

    manifest: dict[str, object] = {
        "safe_demo": True,
        "hidden_text": HIDDEN_TEXT,
        "samples": ["suspicious.txt", "watermarked.png"],
        "signals": [
            "zero-width binary text",
            "mixed line endings",
            "trailing whitespace",
            "Cyrillic homoglyph",
            "PNG metadata",
            "PNG private chunk",
            "synthetic embedded provenance declaration",
        ],
    }
    (output_dir / "samples.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Directory for generated fixtures")
    args = parser.parse_args()
    try:
        manifest = create_samples(args.output)
    except (FileExistsError, OSError) as exc:
        parser.error(str(exc))
    print(f"Created {len(manifest['samples'])} safe demo samples in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
