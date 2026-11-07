# Copyright 2025 Aditya Arakeri
# SPDX-License-Identifier: Apache-2.0

"""
Shared ANSI colour constants and color() helper for StegGuard.

StegGuard has no required dependencies, so this file must use only the standard library.
"""

import os
import sys

RED = "\x1b[91m"
YELLOW = "\x1b[93m"
GREEN = "\x1b[92m"
CYAN = "\x1b[96m"
DARK_CYAN = "\x1b[36m"  # Stays readable on light terminal themes, unlike bright CYAN.
MAGENTA = "\x1b[95m"
WHITE = "\x1b[97m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RESET = "\x1b[0m"


def use_utf8_output() -> None:
    """Emit UTF-8 on stdout/stderr so findings print on non-UTF-8 consoles (e.g. cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def color(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI escape codes.

    Returns plain text when stdout is not a TTY, or when NO_COLOR is set to a non-empty
    value (https://no-color.org).
    """
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return str(text)
    return "".join(codes) + str(text) + RESET
