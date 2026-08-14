# SPDX-License-Identifier: Apache-2.0
"""Shared resource budgets for processing attacker-controlled files."""

from __future__ import annotations

import time
import zlib
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Mapping


class ResourceLimitError(ValueError):
    """Raised when a scan would exceed its configured resource budget."""


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Configurable limits applied consistently across scan entry points."""

    max_file_bytes: int = 100 * 1024 * 1024
    max_decompressed_bytes: int = 50 * 1024 * 1024
    max_image_pixels: int = 40_000_000
    max_archive_members: int = 500
    max_nesting_depth: int = 3
    max_scan_seconds: float = 30.0
    max_findings: int = 10_000

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


DEFAULT_SCAN_LIMITS = ScanLimits()
_READ_CHUNK_BYTES = 1024 * 1024

_CLI_LIMIT_FIELDS = (
    ("max_file_bytes", int, "Maximum bytes read from one top-level file"),
    ("max_decompressed_bytes", int, "Maximum decompressed bytes per scan"),
    ("max_image_pixels", int, "Maximum decoded pixels in one image"),
    ("max_archive_members", int, "Maximum archive members inspected"),
    ("max_nesting_depth", int, "Maximum nested container depth"),
    ("max_scan_seconds", float, "Maximum elapsed seconds per file"),
    ("max_findings", int, "Maximum findings retained per result"),
)


def add_limit_arguments(parser: Any) -> None:
    """Add the shared resource-budget options to an argparse parser."""
    group = parser.add_argument_group("resource limits")
    for name, value_type, help_text in _CLI_LIMIT_FIELDS:
        group.add_argument(
            "--" + name.replace("_", "-"),
            dest=name,
            type=value_type,
            default=None,
            help=help_text,
        )


def limits_from_namespace(namespace: Any) -> ScanLimits:
    """Build limits from argparse values, retaining defaults when omitted."""
    overrides = {
        name: getattr(namespace, name)
        for name, _, _ in _CLI_LIMIT_FIELDS
        if getattr(namespace, name, None) is not None
    }
    return resolve_limits(overrides)


def resolve_limits(limits: ScanLimits | Mapping[str, Any] | None) -> ScanLimits:
    """Normalize a policy object or partial mapping into ``ScanLimits``."""
    if limits is None:
        return DEFAULT_SCAN_LIMITS
    if isinstance(limits, ScanLimits):
        return limits
    if not isinstance(limits, Mapping):
        raise TypeError("limits must be a ScanLimits instance, mapping, or None")
    allowed = {item.name for item in fields(ScanLimits)}
    unknown = sorted(set(limits) - allowed)
    if unknown:
        raise ValueError(f"unknown scan limit(s): {', '.join(unknown)}")
    return ScanLimits(**{**asdict(DEFAULT_SCAN_LIMITS), **dict(limits)})


def read_limited(path: Path, limits: ScanLimits) -> bytes:
    """Read at most ``max_file_bytes`` and reject larger inputs."""
    size = path.stat().st_size
    if size > limits.max_file_bytes:
        raise ResourceLimitError(f"max_file_bytes exceeded: {size} > {limits.max_file_bytes}")
    with path.open("rb") as stream:
        return read_stream_limited(stream, limits.max_file_bytes, "max_file_bytes")


def read_stream_limited(stream: Any, max_bytes: int, limit_name: str) -> bytes:
    """Read a binary stream without preallocating the entire configured budget."""
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = max_bytes - total
        chunk = stream.read(min(_READ_CHUNK_BYTES, remaining + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ResourceLimitError(f"{limit_name} exceeded: input is larger than {max_bytes}")
        chunks.append(chunk)
    return b"".join(chunks)


def decompress_limited(data: bytes, max_bytes: int) -> bytes:
    """Decompress zlib data without permitting unbounded output allocation."""
    decompressor = zlib.decompressobj()
    output = decompressor.decompress(data, max_bytes + 1)
    if len(output) > max_bytes or decompressor.unconsumed_tail:
        raise ResourceLimitError(
            f"max_decompressed_bytes exceeded: output is larger than {max_bytes}"
        )
    remaining = decompressor.flush(max_bytes + 1 - len(output))
    output += remaining
    if len(output) > max_bytes:
        raise ResourceLimitError(
            f"max_decompressed_bytes exceeded: output is larger than {max_bytes}"
        )
    return output


def validate_image_size(width: int, height: int, limits: ScanLimits) -> None:
    """Reject invalid or oversized declared image dimensions."""
    if width <= 0 or height <= 0:
        raise ResourceLimitError("image dimensions must be positive")
    pixels = width * height
    if pixels > limits.max_image_pixels:
        raise ResourceLimitError(f"max_image_pixels exceeded: {pixels} > {limits.max_image_pixels}")


def deadline_for(limits: ScanLimits) -> float:
    return time.monotonic() + limits.max_scan_seconds


def check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise ResourceLimitError("max_scan_seconds exceeded")
