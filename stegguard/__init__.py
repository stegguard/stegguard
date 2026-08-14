# Copyright 2025 Aditya Arakeri
# SPDX-License-Identifier: Apache-2.0

"""StegGuard: hidden-content detection, decoding, and sanitization toolkit."""

from stegguard._version import __version__
from stegguard.limits import ResourceLimitError, ScanLimits
from stegguard.schema import SCHEMA_VERSION

__author__ = "StegGuard"
__license__ = "Apache-2.0"

from stegguard.detector import analyze_file  # primary public API
from stegguard.operations import decode_file, sanitize_file
from stegguard.watermark import scan_file

__all__ = [
    "SCHEMA_VERSION",
    "ResourceLimitError",
    "ScanLimits",
    "analyze_file",
    "decode_file",
    "sanitize_file",
    "scan_file",
]
