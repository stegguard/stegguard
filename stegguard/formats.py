# SPDX-License-Identifier: Apache-2.0
"""File format capabilities shared by detection, decoding, and sanitization."""

from pathlib import Path

TEXT_EXTENSIONS: set[str] = {
    ".txt",
    ".md",
    ".tex",
    ".rtf",
    ".log",
    ".csv",
    ".tsv",
    ".svg",
    ".xml",
    ".html",
    ".htm",
    ".asp",
    ".jsp",
    ".htaccess",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".conf",
    ".env",
    ".gitignore",
    ".kubeconfig",
    "dockerfile",
    ".py",
    ".js",
    ".ts",
    ".java",
    ".cpp",
    ".c",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".css",
    ".scss",
    ".jsx",
    ".tsx",
    ".vue",
    ".sh",
    ".bat",
    ".tf",
    ".gradle",
    ".pom",
}

BINARY_EXTENSIONS: set[str] = {
    ".doc",
    ".docx",
    ".pptx",
    ".epub",
    ".sqlite",
    ".jar",
    ".xls",
    ".xlsx",
    ".odt",
    ".ods",
    ".pages",
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tiff",
    ".tif",
    ".webp",
    ".ico",
    ".heic",
    ".psd",
    ".mp4",
    ".mkv",
    ".avi",
    ".mov",
    ".wmv",
    ".flv",
    ".webm",
    ".m4v",
    ".mpg",
    ".mpeg",
    ".3gp",
    ".mp3",
    ".wav",
    ".aac",
    ".flac",
    ".ogg",
    ".m4a",
    ".wma",
    ".aiff",
    ".opus",
    ".mid",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
    ".iso",
    ".dmg",
    ".pkg",
    ".deb",
    ".exe",
    ".msi",
    ".app",
    ".dll",
    ".sys",
    ".bin",
    ".wasm",
    ".apk",
    ".ipa",
    ".parquet",
    ".avro",
}

ALL_EXTENSIONS: set[str] = TEXT_EXTENSIONS | BINARY_EXTENSIONS

# Formats that support pixel-level LSB steganalysis
LSB_FORMATS: set[str] = {".png", ".bmp", ".gif", ".tif", ".tiff"}

ARCHIVE_DECODE_FORMATS = frozenset({
    ".zip", ".jar", ".apk", ".docx", ".xlsx", ".odt", ".ods",
})
BINARY_DECODE_FORMATS = ARCHIVE_DECODE_FORMATS | LSB_FORMATS | {
    ".jpg", ".jpeg", ".mp3", ".pdf",
}
PLAIN_TEXT_REWRITE_FORMATS = frozenset({".txt", ".log"})


def format_name(path: Path) -> str:
    name = path.name.lower()
    return name if name in TEXT_EXTENSIONS else path.suffix.lower()

# These formats have signatures that can be checked before selecting a handler.
BINARY_SIGNATURES = {
    ".png": (b"\x89PNG",),
    ".jpg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".bmp": (b"BM",),
    ".tif": (b"II*\0", b"MM\0*"),
    ".pdf": (b"%PDF-",),
    ".flac": (b"fLaC",),
    ".ogg": (b"OggS",),
    ".sqlite": (b"SQLite format 3\0",),
}
FORMAT_ALIASES = {".jpeg": ".jpg", ".tiff": ".tif"}
STRUCTURED_ARCHIVES = {".docx", ".pptx", ".xlsx", ".epub", ".odt"}


def signature_format(raw: bytes) -> str | None:
    for kind, prefixes in BINARY_SIGNATURES.items():
        if raw.startswith(prefixes):
            return kind
    if raw.startswith(b"RIFF") and raw[8:12] == b"WAVE":
        return ".wav"
    if raw.startswith(b"RIFF") and raw[8:12] == b"WEBP":
        return ".webp"
    return None
