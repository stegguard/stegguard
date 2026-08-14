# Copyright 2025 Aditya Arakeri
# SPDX-License-Identifier: Apache-2.0

"""
steg_common.py — Shared ANSI colour constants and color() helper for StegGuard.

Imported by steg_detector.py and steg_decoder.py.  Neither script has external
dependencies, so this file must also use only the standard library.
"""

import sys

RED = "\x1b[91m"
YELLOW = "\x1b[93m"
GREEN = "\x1b[92m"
CYAN = "\x1b[96m"
MAGENTA = "\x1b[95m"
WHITE = "\x1b[97m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RESET = "\x1b[0m"


def color(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI escape codes.  Returns plain text when stdout is not a TTY."""
    if not sys.stdout.isatty():
        return str(text)
    return "".join(codes) + str(text) + RESET
