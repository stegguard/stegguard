# SPDX-License-Identifier: Apache-2.0
"""Safe public decoding and sanitization operations."""

from __future__ import annotations

import difflib
import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping

from stegguard.detector import (
    BINARY_EXTENSIONS,
    HOMOGLYPH_CHARS,
    ZERO_WIDTH_CHARS,
    analyze_file,
    attempt_decode_zero_width,
)
from stegguard.limits import ScanLimits, read_limited, resolve_limits
from stegguard.schema import SCHEMA_VERSION


_BIDI_CHARS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2069",
}
_HOMOGLYPH_REPLACEMENTS: dict[str, str | int | None] = {
    char: details[1] for char, details in HOMOGLYPH_CHARS.items()
}
_SANITIZE_TABLE = str.maketrans(
    {
        **{char: None for char in ZERO_WIDTH_CHARS},
        **{char: None for char in _BIDI_CHARS},
        **_HOMOGLYPH_REPLACEMENTS,
    }
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_text(path: Path, limits: ScanLimits) -> tuple[bytes, str, str]:
    raw = read_limited(path, limits)
    try:
        return raw, raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw, raw.decode("latin-1"), "latin-1"


def _decode_bits(bits: str) -> tuple[str, float]:
    if len(bits) < 8:
        return "", 0.0
    payload = bytes(int(bits[index : index + 8], 2) for index in range(0, len(bits) - 7, 8))
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        decoded = payload.decode("latin-1")
    printable = sum(char.isprintable() or char in "\r\n\t" for char in decoded)
    confidence = printable / max(len(decoded), 1) * 0.9
    return (decoded if confidence >= 0.6 else ""), confidence


def decode_file(
    path: str | Path,
    *,
    limits: ScanLimits | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Decode recognized text-carried signals without modifying the source."""
    policy = resolve_limits(limits)
    source = Path(path)
    if source.suffix.lower() in BINARY_EXTENSIONS:
        raw = read_limited(source, policy)
        return {
            "schema_version": SCHEMA_VERSION,
            "file": str(source),
            "sha256": _sha256(raw),
            "status": "NOT_SUPPORTED",
            "errors": ["Built-in payload decoding currently supports text-carried channels only."],
        }
    raw, text, encoding = _read_text(source, policy)
    findings = analyze_file(source, limits=policy)
    decoded = attempt_decode_zero_width(findings.get("zero_width", []))
    printable = sum(char.isprintable() for char in decoded)
    confidence = (printable / len(decoded) * 0.9) if decoded else 0.0
    trailing_bits = ""
    for line in text.splitlines():
        match = re.search(r"[ \t]+$", line)
        if match:
            trailing_bits += "".join("1" if char == "\t" else "0" for char in match.group())
    trailing_decoded, trailing_confidence = _decode_bits(trailing_bits)

    ending_bits = ""
    for byte_line in raw.splitlines(keepends=True):
        if byte_line.endswith(b"\r\n"):
            ending_bits += "1"
        elif byte_line.endswith((b"\n", b"\r")):
            ending_bits += "0"
    ending_decoded, ending_confidence = _decode_bits(ending_bits)

    replacements = sum(text.count(char) for char in _HOMOGLYPH_REPLACEMENTS)
    normalized_text = text.translate(str.maketrans(_HOMOGLYPH_REPLACEMENTS))
    return {
        "schema_version": SCHEMA_VERSION,
        "file": str(source),
        "status": "DECODED",
        "sha256": _sha256(raw),
        "encoding": encoding,
        "zero_width": {
            "decoded": decoded,
            "confidence": confidence,
            "occurrences": len(findings.get("zero_width", [])),
        },
        "trailing_whitespace": {
            "decoded": trailing_decoded,
            "confidence": trailing_confidence,
            "bits": trailing_bits,
        },
        "line_endings": {
            "decoded": ending_decoded,
            "confidence": ending_confidence,
            "bits": ending_bits,
        },
        "homoglyphs": {
            "normalized_text": normalized_text,
            "replacements": replacements,
        },
        "mixed_line_endings": findings.get("mixed_line_endings", False),
        "text_length": len(text),
    }


def _sanitize_text(text: str) -> tuple[str, dict[str, int]]:
    zero_width_removed = sum(text.count(char) for char in ZERO_WIDTH_CHARS)
    bidi_removed = sum(text.count(char) for char in _BIDI_CHARS)
    homoglyphs_replaced = sum(text.count(char) for char in _HOMOGLYPH_REPLACEMENTS)

    translated = text.translate(_SANITIZE_TABLE)
    output_lines: list[str] = []
    trailing_whitespace_removed = 0
    line_endings_normalized = 0
    for line in translated.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body) :]
        clean_body = body.rstrip(" \t")
        trailing_whitespace_removed += len(body) - len(clean_body)
        if ending and ending != "\n":
            line_endings_normalized += 1
        output_lines.append(clean_body + ("\n" if ending else ""))

    return "".join(output_lines), {
        "zero_width_removed": zero_width_removed,
        "bidi_removed": bidi_removed,
        "homoglyphs_replaced": homoglyphs_replaced,
        "trailing_whitespace_removed": trailing_whitespace_removed,
        "line_endings_normalized": line_endings_normalized,
    }


def _write_bytes(path: Path, data: bytes, *, atomic: bool, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not atomic:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            path.chmod(mode)
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sanitize_file(
    path: str | Path,
    output_path: str | Path | None = None,
    *,
    in_place: bool = False,
    confirm: bool = False,
    provenance_validator: Any = None,
    limits: ScanLimits | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Sanitize a text file, copying by default and reporting every change."""
    if in_place != confirm:
        raise ValueError("overwriting requires both --in-place and --confirm")
    if in_place and output_path is not None:
        raise ValueError("output_path cannot be combined with --in-place")

    policy = resolve_limits(limits)
    source = Path(path)
    source_mode = stat.S_IMODE(source.stat().st_mode)
    is_binary = source.suffix.lower() in BINARY_EXTENSIONS
    if is_binary:
        raw_before = read_limited(source, policy)
        text = ""
        encoding = ""
    else:
        raw_before, text, encoding = _read_text(source, policy)
    from stegguard.watermark import scan_file

    provenance_before = scan_file(
        str(source),
        provenance_validator=provenance_validator,
        limits=policy,
    )["provenance"]
    if is_binary:
        clean_text = ""
        raw_after = raw_before
        changes = {
            "zero_width_removed": 0,
            "bidi_removed": 0,
            "homoglyphs_replaced": 0,
            "trailing_whitespace_removed": 0,
            "line_endings_normalized": 0,
        }
    else:
        clean_text, changes = _sanitize_text(text)
        raw_after = clean_text.encode(encoding)

    if in_place:
        destination = source
    elif output_path is not None:
        destination = Path(output_path)
    else:
        destination = source.with_name(f"{source.stem}.sanitized{source.suffix}")
    if not in_place and (destination.exists() or destination.is_symlink()):
        raise FileExistsError(f"sanitized output already exists: {destination}")

    source_sidecar: Path | None = None
    destination_sidecar: Path | None = None
    manifest_location = provenance_before.get("manifest_location", "")
    if (
        not in_place
        and raw_before == raw_after
        and provenance_before.get("status") == "VALID"
        and manifest_location not in ("", "embedded")
        and not str(manifest_location).startswith(("http://", "https://"))
    ):
        source_sidecar = Path(manifest_location)
        sidecar_suffix = ".c2pa.json" if source_sidecar.name.endswith(".c2pa.json") else ".c2pa"
        destination_sidecar = destination.with_name(destination.name + sidecar_suffix)
        if destination_sidecar.exists() or destination_sidecar.is_symlink():
            raise FileExistsError(
                f"sanitized provenance sidecar already exists: {destination_sidecar}"
            )

    diff = (
        ""
        if is_binary
        else "".join(
            difflib.unified_diff(
                text.splitlines(keepends=True),
                clean_text.splitlines(keepends=True),
                fromfile=str(source),
                tofile=str(destination),
            )
        )
    )
    _write_bytes(destination, raw_after, atomic=in_place, mode=source_mode)
    if source_sidecar is not None and destination_sidecar is not None:
        _write_bytes(
            destination_sidecar,
            read_limited(source_sidecar, policy),
            atomic=False,
            mode=stat.S_IMODE(source_sidecar.stat().st_mode),
        )
    provenance_after = scan_file(
        str(destination),
        provenance_validator=provenance_validator,
        limits=policy,
    )["provenance"]
    if provenance_before.get("status") == "VALID":
        provenance_impact = (
            "preserved"
            if raw_before == raw_after and provenance_after.get("status") == "VALID"
            else "invalidated"
        )
    else:
        provenance_impact = "unchanged" if raw_before == raw_after else "not_applicable"

    return {
        "schema_version": SCHEMA_VERSION,
        "file": str(source),
        "sanitized_path": str(destination),
        "sha256_before": _sha256(raw_before),
        "sha256_after": _sha256(raw_after),
        "changed": raw_before != raw_after,
        "changes": changes,
        "diff": diff,
        "original_preserved": not in_place,
        "sanitization_status": "NO_OP_UNSUPPORTED" if is_binary else "SANITIZED",
        "provenance_before": provenance_before,
        "provenance_after": provenance_after,
        "provenance_impact": provenance_impact,
    }
