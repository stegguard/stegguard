# Copyright 2025 Aditya Arakeri
# SPDX-License-Identifier: Apache-2.0

"""
StegGuard CLI — unified entry point for the detect, decode, sanitize, and watermark commands.
"""

import argparse
import json
import sys

from stegguard.common import DARK_CYAN, color, use_utf8_output
from stegguard.help_format import CommandListFormatter, StyledParser
from stegguard.operations import (
    BINARY_SANITIZE_CHANNELS,
    SANITIZE_CHANNELS,
    SANITIZE_PROFILES,
    SEVERITY_LEVELS,
    TEXT_SANITIZE_CHANNELS,
)
from stegguard.limits import add_limit_arguments, limits_from_namespace
from stegguard._version import __version__
from stegguard.reporting import atomic_write_text

# Plain ASCII and under 80 columns, so it renders on any console.
BANNER = "\n".join(
    (
        r" ____  _____ _____ ____  ____ _   _   _    ____  ____  ",
        r"/ ___||_   _| ____/ ___|/ ___| | | | / \  |  _ \|  _ \ ",
        r"\___ \  | | |  _|| |  _| |  _| | | |/ _ \ | |_) | | | |",
        r" ___) | | | | |__| |_| | |_| | |_| / ___ \|  _ <| |_| |",
        r"|____/  |_| |_____\____|\____|\___/_/   \_\_| \_\____/ ",
    )
)


def cmd_detect(args):
    """Run the steganography detector."""
    from stegguard.detector import main as detector_main

    detector_args = args if isinstance(args, list) else args.detect_args
    return detector_main(detector_args)


def cmd_decode(args):
    """Decode recognized hidden payloads."""
    from stegguard.operations import decode_file, process_findings

    if args.from_findings:
        report = process_findings(
            args.from_findings,
            "decode",
            min_severity=args.min_sev,
            limits=limits_from_namespace(args),
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 2 if report["failed"] else 0
    print(
        json.dumps(
            decode_file(args.input, limits=limits_from_namespace(args)),
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def cmd_sanitize(args):
    """Write a sanitized copy, or overwrite only with dual confirmation."""
    from stegguard.operations import process_findings, sanitize_file

    if args.from_findings:
        report = process_findings(
            args.from_findings,
            "sanitize",
            min_severity=args.min_sev,
            output_dir=args.output_dir,
            in_place=args.in_place,
            confirm=args.confirm,
            profile=args.profile,
            channels=args.channels,
            limits=limits_from_namespace(args),
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 2 if report["failed"] else 0
    result = sanitize_file(
        args.input,
        args.output,
        in_place=args.in_place,
        confirm=args.confirm,
        limits=limits_from_namespace(args),
        profile=args.profile,
        channels=args.channels,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_watermark(args):
    """Run categorized watermark and provenance analysis."""
    from pathlib import Path

    from stegguard.detector import (
        analyze_file,
        generate_html_report,
        result_is_incomplete,
        watermark_scan_errors,
    )
    from stegguard.integrations import C2paToolValidator, RemoteManifestLoader
    from stegguard.watermark import scan_file

    validator = C2paToolValidator(args.c2pa_tool) if args.c2pa_tool else None
    remote_loader = RemoteManifestLoader() if args.allow_remote_manifests else None
    policy = limits_from_namespace(args)
    result = scan_file(
        args.input,
        provenance_validator=validator,
        remote_manifest_loader=remote_loader,
        limits=policy,
    )
    if args.json_output:
        atomic_write_text(
            args.json_output,
            json.dumps(result, indent=2, ensure_ascii=False),
        )
    incomplete = bool(watermark_scan_errors(result))
    if args.html:
        detector_result = analyze_file(Path(args.input), limits=policy)
        detector_result["watermark"] = result
        generate_html_report([detector_result], args.html)
        incomplete = result_is_incomplete(detector_result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 2 if incomplete else 0


def _add_batch_arguments(parser):
    parser.add_argument(
        "--from-findings",
        metavar="FILE.json",
        help="Process every flagged file in a report from 'stegguard detect --json'",
    )
    parser.add_argument(
        "--min-sev",
        choices=SEVERITY_LEVELS,
        help="With --from-findings, only process files at or above this severity (default: low)",
    )


def _validate_batch_arguments(parser, args):
    """Enforce that a command has exactly one input and only compatible options."""
    if bool(args.input) == bool(args.from_findings):
        parser.error("provide either an input file or --from-findings, not both or neither")
    if args.from_findings:
        if args.command == "sanitize" and args.output:
            parser.error("--output cannot be combined with --from-findings; use --output-dir")
        if args.min_sev is None:
            args.min_sev = "low"
        return
    if args.min_sev is not None:
        parser.error("--min-sev requires --from-findings")
    if args.command == "sanitize" and args.output_dir:
        parser.error("--output-dir requires --from-findings")


class _BannerParser(StyledParser):
    """Top-level parser that prints the banner above its help, but not above errors."""

    def format_help(self) -> str:
        return f"{color(BANNER, DARK_CYAN)}\n\n{super().format_help()}"


_MAIN_DESCRIPTION = """\
Find, read, and remove hidden content in text and binary files.

typical workflow:
  stegguard detect . -r --json findings.json
  stegguard decode --from-findings findings.json
  stegguard sanitize --from-findings findings.json --output-dir clean/
"""

_MAIN_EPILOG = """\
exit codes:
  0  Finished (for detect: nothing found)
  1  Hidden content found (detect only)
  2  Invalid input, or the run couldn't finish

Run 'stegguard COMMAND --help' for options and examples.
"""

_DECODE_DESCRIPTION = """\
Extract hidden payloads and print them as JSON, without changing the file.

Text files: zero-width characters, trailing whitespace, and line endings.
Binary files: metadata from PNG, JPEG, GIF, TIFF, ZIP, MP3, and PDF, plus
readable text in the pixel LSBs of PNG, BMP, GIF, and TIFF.

An empty result doesn't prove a file is clean: encrypted or scattered payloads
can't be read.
"""

_DECODE_EPILOG = """\
examples:
  stegguard decode suspicious.txt
  stegguard decode photo.png
  stegguard decode --from-findings findings.json --min-sev high

exit codes:
  0  Finished, even if nothing was found or the format isn't supported
  2  Invalid input, or a file couldn't be read
"""

_SANITIZE_DESCRIPTION = """\
Write a cleaned copy and print a JSON report of every change.

The copy is saved next to the input as NAME.sanitized.EXT, and an existing file
is never overwritten. The original stays untouched unless you pass --in-place
--confirm.
"""

_SANITIZE_EPILOG = """\
examples:
  stegguard sanitize suspicious.txt
  stegguard sanitize photo.png --profile destructive
  stegguard sanitize --from-findings findings.json --output-dir clean/

exit codes:
  0  Finished. This doesn't mean the file is clean: check "sanitization_status"
     in the report, where anything but SANITIZED means hidden content may remain
  2  Invalid input, or a file couldn't be processed
"""

_WATERMARK_DESCRIPTION = """\
Check a file for watermark signals and Content Credentials, and print the
analysis as JSON. Optionally validate C2PA with the official c2patool
executable.
"""

_WATERMARK_EPILOG = """\
examples:
  stegguard watermark image.png
  stegguard watermark image.png --json report.json --html report.html
  stegguard watermark image.png --c2pa-tool c2patool

exit codes:
  0  Analysis finished, whether or not any signals were found
  2  Invalid input, or the analysis couldn't finish
"""


def build_parser():
    parser = _BannerParser(
        prog="stegguard",
        description=_MAIN_DESCRIPTION,
        formatter_class=CommandListFormatter,
        epilog=_MAIN_EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="COMMAND",
        # argparse gives subparsers the parent's class by default; keep the banner off them.
        parser_class=StyledParser,
    )
    sub.required = True

    # --- detect subcommand ---
    # main() sends "detect" straight to the detector's own parser; this entry lists it.
    p_detect = sub.add_parser("detect", help="Scan files and folders for hidden content")
    p_detect.add_argument(
        "detect_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the detector (paths, flags, etc.)",
    )
    p_detect.set_defaults(func=cmd_detect)

    # --- decode subcommand ---
    p_decode = sub.add_parser(
        "decode",
        help="Extract hidden payloads without changing the file",
        description=_DECODE_DESCRIPTION,
        epilog=_DECODE_EPILOG,
    )
    p_decode.add_argument(
        "input", nargs="?", help="File to decode (or use --from-findings instead)"
    )
    _add_batch_arguments(p_decode)
    add_limit_arguments(p_decode)
    p_decode.set_defaults(func=cmd_decode)

    p_sanitize = sub.add_parser(
        "sanitize",
        help="Write cleaned copies and leave the originals alone",
        description=_SANITIZE_DESCRIPTION,
        epilog=_SANITIZE_EPILOG,
    )
    p_sanitize.add_argument(
        "input", nargs="?", help="File to sanitize (or use --from-findings instead)"
    )
    _add_batch_arguments(p_sanitize)
    p_sanitize.add_argument(
        "--output-dir",
        help="With --from-findings, write sanitized copies under this directory",
    )
    p_sanitize.add_argument("-o", "--output", help="Sanitized output path")
    p_sanitize.add_argument(
        "--in-place", action="store_true", help="Overwrite the input (requires --confirm)"
    )
    p_sanitize.add_argument(
        "--confirm",
        action="store_true",
        help="Required together with --in-place",
    )
    p_sanitize.add_argument(
        "--profile",
        choices=SANITIZE_PROFILES,
        default="conservative",
        help=(
            "conservative (default) keeps hidden characters with a legitimate use and color "
            "or C2PA data, and clears pixel LSBs only when it finds evidence of a payload, "
            "warning if it keeps them. destructive removes all of these, including LSBs, "
            "and can change legitimate text"
        ),
    )
    p_sanitize.add_argument(
        "--channel",
        dest="channels",
        action="append",
        choices=SANITIZE_CHANNELS,
        metavar="CHANNEL",
        help=(
            "Run only this transformation; repeat to select several (default: all for the "
            f"file type). Text files: {', '.join(TEXT_SANITIZE_CHANNELS)}. "
            f"Binary files: {', '.join(BINARY_SANITIZE_CHANNELS)}"
        ),
    )
    add_limit_arguments(p_sanitize)
    p_sanitize.set_defaults(func=cmd_sanitize)

    p_watermark = sub.add_parser(
        "watermark",
        help="Check watermark signals and Content Credentials",
        description=_WATERMARK_DESCRIPTION,
        epilog=_WATERMARK_EPILOG,
    )
    p_watermark.add_argument("input", help="File to analyze")
    p_watermark.add_argument(
        "--c2pa-tool",
        nargs="?",
        const="c2patool",
        metavar="PATH",
        help="Validate Content Credentials using c2patool (optional executable path)",
    )
    p_watermark.add_argument(
        "--allow-remote-manifests",
        action="store_true",
        help="Allow bounded HTTPS retrieval of remote C2PA manifests",
    )
    p_watermark.add_argument(
        "--json", dest="json_output", metavar="OUTPUT.json", help="Write JSON analysis"
    )
    p_watermark.add_argument("--html", metavar="OUTPUT.html", help="Write an HTML report")
    add_limit_arguments(p_watermark)
    p_watermark.set_defaults(func=cmd_watermark)

    return parser


def main(argv: list[str] | None = None) -> int:
    use_utf8_output()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "detect":
        return cmd_detect(arguments[1:])
    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.command in ("decode", "sanitize"):
        _validate_batch_arguments(parser, args)
    if args.command == "sanitize" and args.in_place != args.confirm:
        parser.error("overwriting requires both --in-place and --confirm")
    try:
        return args.func(args)
    except (OSError, TypeError, ValueError) as exc:
        print(f"stegguard: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
