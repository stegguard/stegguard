# SPDX-License-Identifier: Apache-2.0
"""Safe public decoding and sanitization operations."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from stegguard.binary_ops import decode_lsb, extract_metadata, sanitize_binary
from stegguard.detector import (
    BINARY_EXTENSIONS,
    HOMOGLYPH_CHARS,
    ZERO_WIDTH_CHARS,
    analyze_file,
    attempt_decode_zero_width,
    result_is_flagged,
    result_is_incomplete,
)
from stegguard.limits import ScanLimits, read_limited, resolve_limits
from stegguard.schema import SCHEMA_VERSION


SANITIZE_PROFILES = ("conservative", "destructive")
TEXT_SANITIZE_CHANNELS = ("zero_width", "bidi", "homoglyphs", "trailing_whitespace", "line_endings")
BINARY_SANITIZE_CHANNELS = ("metadata", "lsb")
SANITIZE_CHANNELS = TEXT_SANITIZE_CHANNELS + BINARY_SANITIZE_CHANNELS
SEVERITY_LEVELS = ("low", "medium", "high", "critical")

_BIDI_CHARS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}
_HOMOGLYPH_REPLACEMENTS: dict[str, str | int | None] = {
    char: details[1] for char, details in HOMOGLYPH_CHARS.items()
}
_ZERO_WIDTH_PATTERN = re.compile("[" + "".join(ZERO_WIDTH_CHARS) + "]")
_WORD_PATTERN = re.compile(r"[^\W\d_]+")
_MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdown", ".mkd", ".mdx"}
_PROSE_SUFFIXES = _MARKDOWN_SUFFIXES | {".txt", ".rst", ".adoc", ".html", ".htm", ".svg", ".xml"}

# Scripts that use a joiner or non-joiner to choose letter forms.
_JOINING_SCRIPT_RANGES = (
    (0x0600, 0x08FF),  # Arabic, Syriac, and extensions
    (0x0900, 0x0DFF),  # Indic scripts
    (0x0F00, 0x0FFF),  # Tibetan
    (0x1000, 0x109F),  # Myanmar
    (0x1780, 0x17FF),  # Khmer
    (0xFB50, 0xFDFF),  # Arabic presentation forms
    (0xFE70, 0xFEFC),
)
# Scripts written without spaces, where a zero-width space marks a word boundary.
_UNSPACED_SCRIPT_RANGES = (
    (0x0E00, 0x0EFF),  # Thai, Lao
    (0x1000, 0x109F),  # Myanmar
    (0x1780, 0x17FF),  # Khmer
)
_EMOJI_RANGES = (
    (0x2190, 0x2BFF),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3299),
    (0xFE0F, 0xFE0F),  # emoji presentation selector
    (0x1F000, 0x1FAFF),
)


def _in_ranges(char: str, ranges: tuple[tuple[int, int], ...]) -> bool:
    return bool(char) and any(low <= ord(char) <= high for low, high in ranges)


def _is_script_letter(char: str, ranges: tuple[tuple[int, int], ...]) -> bool:
    return _in_ranges(char, ranges) and unicodedata.category(char)[0] in "LM"


def _has_legitimate_use(text: str, index: int) -> bool:
    """Return whether the conservative profile keeps the hidden character at index."""
    char = text[index]
    before = text[index - 1] if index else ""
    after = text[index + 1] if index + 1 < len(text) else ""
    if char == "\ufeff":
        return index == 0
    if char == "\u200d" and _in_ranges(before, _EMOJI_RANGES) and _in_ranges(after, _EMOJI_RANGES):
        return True
    if char in "\u200c\u200d":
        return _is_script_letter(before, _JOINING_SCRIPT_RANGES) and _is_script_letter(
            after, _JOINING_SCRIPT_RANGES
        )
    if char == "\u200b":
        return _is_script_letter(before, _UNSPACED_SCRIPT_RANGES) and _is_script_letter(
            after, _UNSPACED_SCRIPT_RANGES
        )
    if char in "\u200e\u200f":
        return any(
            neighbor and unicodedata.bidirectional(neighbor) in ("R", "AL")
            for neighbor in (before, after)
        )
    return False


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
    """Decode recognized hidden signals without modifying the source."""
    policy = resolve_limits(limits)
    source = Path(path)
    if source.suffix.lower() in BINARY_EXTENSIONS:
        raw = read_limited(source, policy)
        metadata = extract_metadata(raw, source.suffix.lower(), policy)
        lsb = decode_lsb(source, policy)
        if metadata is None and lsb is None:
            return {
                "schema_version": SCHEMA_VERSION,
                "file": str(source),
                "sha256": _sha256(raw),
                "status": "NOT_SUPPORTED",
                "errors": ["This binary format is not supported or the file did not parse."],
            }
        return {
            "schema_version": SCHEMA_VERSION,
            "file": str(source),
            "sha256": _sha256(raw),
            "status": "DECODED",
            "metadata": metadata,
            "lsb": lsb,
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


def _resolve_policy(
    profile: str, channels: Iterable[str] | None, is_binary: bool = False
) -> tuple[str, ...]:
    if profile not in SANITIZE_PROFILES:
        raise ValueError(f"unknown sanitization profile: {profile}")
    if channels is None:
        return BINARY_SANITIZE_CHANNELS if is_binary else TEXT_SANITIZE_CHANNELS
    selected = set(channels)
    unknown = selected.difference(SANITIZE_CHANNELS)
    if unknown:
        raise ValueError(f"unknown sanitization channel: {', '.join(sorted(unknown))}")
    if not selected:
        raise ValueError("select at least one sanitization channel")
    return tuple(channel for channel in SANITIZE_CHANNELS if channel in selected)


def _remove_zero_width(text: str, conservative: bool) -> str:
    def keep_or_remove(match: re.Match[str]) -> str:
        keep = conservative and _has_legitimate_use(text, match.start())
        return match.group() if keep else ""

    return _ZERO_WIDTH_PATTERN.sub(keep_or_remove, text)


def _replace_homoglyphs(text: str, conservative: bool) -> str:
    table = str.maketrans(_HOMOGLYPH_REPLACEMENTS)
    if not conservative:
        return text.translate(table)

    def repair_mixed_word(match: re.Match[str]) -> str:
        word = match.group()
        has_latin = any(char.isascii() for char in word)
        only_latin_and_lookalikes = all(
            char.isascii() or char in _HOMOGLYPH_REPLACEMENTS for char in word
        )
        return word.translate(table) if has_latin and only_latin_and_lookalikes else word

    return _WORD_PATTERN.sub(repair_mixed_word, text)


def _line_ending_of(line: str) -> str:
    return line[len(line.rstrip("\r\n")) :]


def _clean_lines(
    text: str,
    channels: tuple[str, ...],
    conservative: bool,
    is_markdown: bool,
) -> tuple[str, int, int, int]:
    lines = text.splitlines(keepends=True)
    endings = [ending for ending in map(_line_ending_of, lines) if ending]
    target = "\n"
    if conservative and endings:
        # Prefer LF on a tie, so an evenly mixed file cannot choose a covert ending.
        target = max(Counter(endings).items(), key=lambda item: (item[1], item[0] == "\n"))[0]

    output_lines: list[str] = []
    trailing_removed = 0
    hard_breaks = 0
    endings_normalized = 0
    for index, line in enumerate(lines):
        ending = _line_ending_of(line)
        body = line[: len(line) - len(ending)]
        if "trailing_whitespace" in channels:
            clean_body = body.rstrip(" \t")
            trailing = body[len(clean_body) :]
            following = lines[index + 1].strip() if index + 1 < len(lines) else ""
            if (
                conservative
                and is_markdown
                and clean_body
                and following
                and len(trailing) >= 2
                and not trailing.strip(" ")
            ):
                clean_body += "  "
                hard_breaks += 1
            trailing_removed += len(body) - len(clean_body)
            body = clean_body
        if "line_endings" in channels and ending and ending != target:
            ending = target
            endings_normalized += 1
        output_lines.append(body + ending)
    return "".join(output_lines), trailing_removed, hard_breaks, endings_normalized


def _sanitize_text(
    text: str,
    channels: tuple[str, ...] = SANITIZE_CHANNELS,
    profile: str = "conservative",
    suffix: str = "",
) -> tuple[str, dict[str, int]]:
    conservative = profile == "conservative"
    cleaned = text
    bidi_removed = 0
    if "bidi" in channels:
        bidi_removed = sum(cleaned.count(char) for char in _BIDI_CHARS)
        cleaned = cleaned.translate({ord(char): None for char in _BIDI_CHARS})

    zero_width_before = sum(cleaned.count(char) for char in ZERO_WIDTH_CHARS)
    if "zero_width" in channels:
        cleaned = _remove_zero_width(cleaned, conservative)
    zero_width_preserved = sum(cleaned.count(char) for char in ZERO_WIDTH_CHARS)

    homoglyphs_before = sum(cleaned.count(char) for char in _HOMOGLYPH_REPLACEMENTS)
    if "homoglyphs" in channels:
        cleaned = _replace_homoglyphs(cleaned, conservative)
    homoglyphs_preserved = sum(cleaned.count(char) for char in _HOMOGLYPH_REPLACEMENTS)

    cleaned, trailing_removed, hard_breaks, endings_normalized = _clean_lines(
        cleaned, channels, conservative, suffix in _MARKDOWN_SUFFIXES
    )
    return cleaned, {
        "zero_width_removed": zero_width_before - zero_width_preserved,
        "zero_width_preserved": zero_width_preserved,
        "bidi_removed": bidi_removed,
        "homoglyphs_replaced": homoglyphs_before - homoglyphs_preserved,
        "homoglyphs_preserved": homoglyphs_preserved,
        "trailing_whitespace_removed": trailing_removed,
        "hard_breaks_preserved": hard_breaks,
        "line_endings_normalized": endings_normalized,
    }


def _applied_channels(changes: dict[str, int]) -> list[str]:
    counters = {
        "zero_width": ("zero_width_removed",),
        "bidi": ("bidi_removed",),
        "homoglyphs": ("homoglyphs_replaced",),
        "trailing_whitespace": ("trailing_whitespace_removed",),
        "line_endings": ("line_endings_normalized",),
        "metadata": ("metadata_removed", "trailing_bytes_removed"),
        "lsb": ("lsb_samples_cleared",),
    }
    return [
        channel
        for channel in SANITIZE_CHANNELS
        if any(changes.get(counter) for counter in counters[channel])
    ]


def _sanitize_warnings(
    changes: dict[str, int], profile: str, suffix: str, changed: bool
) -> list[str]:
    warnings = []
    if changes["zero_width_preserved"]:
        warnings.append(
            f"Kept {changes['zero_width_preserved']} zero-width character(s) in text where they "
            "have a legitimate use; they can still carry data. "
            "Use --profile destructive to remove them."
        )
    if changes["homoglyphs_preserved"]:
        warnings.append(
            f"Kept {changes['homoglyphs_preserved']} letter(s) that look like Latin letters; "
            "they can still carry data. Use --profile destructive to replace them."
        )
    if changes["hard_breaks_preserved"]:
        warnings.append(
            f"Kept {changes['hard_breaks_preserved']} Markdown hard break(s); they can still "
            "carry data. Use --profile destructive to remove them."
        )
    if changed and profile == "destructive":
        warnings.append(
            "The destructive profile can change legitimate text, including non-Latin words "
            "and emoji. Review the diff."
        )
    if changed and suffix not in _PROSE_SUFFIXES:
        warnings.append(
            "Changes to source code can alter its behavior, including string literals. "
            "Review the diff."
        )
    return warnings


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
    profile: str = "conservative",
    channels: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Sanitize a file, copying by default and reporting every change.

    The conservative profile keeps hidden characters where they have a legitimate
    use. The destructive profile removes all of them and can change legitimate text.
    channels limits which transformations run; by default all of them do.

    Binary files use the metadata and lsb channels. Conservative removes text metadata
    but keeps color and provenance data, and clears pixel LSBs only when there is
    evidence of a payload. Destructive also removes those and always clears pixel LSBs.
    """
    if in_place != confirm:
        raise ValueError("overwriting requires both --in-place and --confirm")
    if in_place and output_path is not None:
        raise ValueError("output_path cannot be combined with --in-place")
    policy = resolve_limits(limits)
    source = Path(path)
    suffix = source.suffix.lower()
    source_mode = stat.S_IMODE(source.stat().st_mode)
    is_binary = suffix in BINARY_EXTENSIONS
    selected_channels = _resolve_policy(profile, channels, is_binary)
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
    binary_result = None
    if is_binary:
        clean_text = ""
        binary_result = sanitize_binary(source, raw_before, selected_channels, profile, policy)
        raw_after = binary_result.data
        changes = {
            **dict.fromkeys(_sanitize_text("")[1], 0),
            "metadata_removed": len(binary_result.metadata_removed),
            "trailing_bytes_removed": binary_result.trailing_bytes_removed,
            "lsb_samples_cleared": binary_result.lsb_samples_cleared,
        }
    else:
        clean_text, changes = _sanitize_text(text, selected_channels, profile, suffix)
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

    warnings = _sanitize_warnings(changes, profile, suffix, raw_before != raw_after)
    if binary_result is not None:
        # The text warnings about reviewing a diff do not apply to binary output.
        warnings = binary_result.warnings

    report = {
        "schema_version": SCHEMA_VERSION,
        "file": str(source),
        "sanitized_path": str(destination),
        "sha256_before": _sha256(raw_before),
        "sha256_after": _sha256(raw_after),
        "changed": raw_before != raw_after,
        "policy": {
            "profile": profile,
            "channels": list(selected_channels),
            "applied": _applied_channels(changes),
        },
        "changes": changes,
        "warnings": warnings,
        "diff": diff,
        "original_preserved": not in_place,
        "sanitization_status": binary_result.status if binary_result else "SANITIZED",
        "provenance_before": provenance_before,
        "provenance_after": provenance_after,
        "provenance_impact": provenance_impact,
    }
    if binary_result is not None:
        report["binary"] = {
            "metadata_removed": binary_result.metadata_removed,
            "lsb_method": binary_result.lsb_method,
        }
    return report


def _load_findings(path: Path, policy: ScanLimits) -> list[dict[str, Any]]:
    """Read a detector JSON report, rejecting anything that is not a supported one."""
    try:
        report = json.loads(read_limited(path, policy).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"findings file is not UTF-8 JSON: {path}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError(f"not a StegGuard findings report: {path}")
    version = str(report.get("schema_version", SCHEMA_VERSION))
    if version.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        raise ValueError(f"unsupported findings schema version: {version}")
    return report["results"]


def _meets_severity(severity: Any, minimum: str) -> bool:
    """Compare severities, treating an unknown value as serious rather than skipping it."""
    if severity == "clean":
        return False
    if severity not in SEVERITY_LEVELS:
        return True
    return SEVERITY_LEVELS.index(severity) >= SEVERITY_LEVELS.index(minimum)


def _batch_destination(source: Path, output_dir: Path) -> Path:
    """Mirror a source path under output_dir, refusing any path that would escape it."""
    parts = source.parts[1:] if source.anchor else source.parts
    destination = output_dir.joinpath(*parts)
    if not destination.resolve().is_relative_to(output_dir.resolve()):
        raise ValueError(f"refusing to write outside the output directory: {source}")
    return destination


def _is_clean_after(path: Path, policy: ScanLimits) -> bool:
    outcome = analyze_file(path, limits=policy)
    return not result_is_flagged(outcome) and not result_is_incomplete(outcome)


def process_findings(
    findings_path: str | Path,
    operation: str,
    *,
    min_severity: str = "low",
    output_dir: str | Path | None = None,
    in_place: bool = False,
    confirm: bool = False,
    profile: str = "conservative",
    channels: Iterable[str] | None = None,
    limits: ScanLimits | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Decode or sanitize every flagged file named in a detector JSON report.

    A failure on one file is recorded and the batch continues. Files that are missing,
    and files whose scan never finished, are reported rather than silently skipped.
    """
    if operation not in ("decode", "sanitize"):
        raise ValueError(f"unknown batch operation: {operation}")
    if min_severity not in SEVERITY_LEVELS:
        raise ValueError(f"unknown severity: {min_severity}")
    if in_place != confirm:
        raise ValueError("overwriting requires both --in-place and --confirm")
    if in_place and output_dir is not None:
        raise ValueError("output_dir cannot be combined with --in-place")
    if operation == "decode" and (in_place or output_dir is not None):
        raise ValueError("decode does not write files")

    policy = resolve_limits(limits)
    selected = list(channels) if channels is not None else None
    _resolve_policy(profile, selected)
    target_dir = Path(output_dir) if output_dir is not None else None

    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    below_threshold = 0
    for entry in _load_findings(Path(findings_path), policy):
        name = entry.get("file") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name:
            items.append({"file": None, "status": "ERROR", "error": "report entry has no file"})
            continue
        if name in seen:
            continue
        seen.add(name)
        severity = entry.get("severity")
        if not _meets_severity(severity, min_severity):
            if entry.get("incomplete_reasons") or entry.get("error"):
                items.append(
                    {
                        "file": name,
                        "severity": severity,
                        "status": "SCAN_INCOMPLETE",
                        "error": "the detector did not finish scanning this file",
                    }
                )
            else:
                below_threshold += 1
            continue
        item: dict[str, Any] = {"file": name, "severity": severity}
        items.append(item)
        source = Path(name)
        try:
            if not source.exists():
                item.update(status="MISSING", error="file no longer exists")
            elif operation == "decode":
                item.update(status="OK", result=decode_file(source, limits=policy))
            else:
                destination = _batch_destination(source, target_dir) if target_dir else None
                outcome = sanitize_file(
                    source,
                    destination,
                    in_place=in_place,
                    confirm=confirm,
                    limits=policy,
                    profile=profile,
                    channels=selected,
                )
                item.update(
                    status="OK",
                    result=outcome,
                    clean_after=_is_clean_after(Path(outcome["sanitized_path"]), policy),
                )
        except (OSError, TypeError, ValueError) as exc:
            item.update(status="ERROR", error=str(exc))

    failed = sum(item["status"] != "OK" for item in items)
    return {
        "schema_version": SCHEMA_VERSION,
        "operation": operation,
        "findings_file": str(findings_path),
        "min_severity": min_severity,
        "selected": len(items),
        "succeeded": len(items) - failed,
        "failed": failed,
        "below_threshold": below_threshold,
        "results": items,
    }
