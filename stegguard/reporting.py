# SPDX-License-Identifier: Apache-2.0
"""Crash-safe output primitives shared by machine and human reports."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


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
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary.exists():
            temporary.unlink()
