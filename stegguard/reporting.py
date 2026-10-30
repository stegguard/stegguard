# SPDX-License-Identifier: Apache-2.0
"""Crash-safe output primitives shared by machine and human reports."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

_REPLACE_ATTEMPTS = 10
_IS_WINDOWS = os.name == "nt"


def atomic_write_text(path: str | Path, content: str, *, encoding: str = "utf-8") -> Path:
    """Replace a report only after its complete content is durable on disk."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding, newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _replace(temporary, destination)
        return destination
    finally:
        if temporary.exists():
            temporary.unlink()


def _replace(source: Path, destination: Path) -> None:
    """os.replace, retrying the transient PermissionError Windows raises when another
    writer is replacing the same destination at that moment."""
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(source, destination)
            return
        except PermissionError:
            if not _IS_WINDOWS or attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(0.01 * (attempt + 1))
