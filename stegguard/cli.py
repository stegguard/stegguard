# Copyright 2025 Aditya Arakeri
# SPDX-License-Identifier: Apache-2.0

"""
StegGuard CLI — unified entry point for detect and decode subcommands.
"""

import argparse
import json
import sys

from stegguard.limits import add_limit_arguments, limits_from_namespace
from stegguard._version import __version__
from stegguard.reporting import atomic_write_text


def cmd_detect(args):
    """Run the open-source steganography detector."""
    from stegguard.detector import main as detector_main

    detector_args = args if isinstance(args, list) else args.detect_args
    return detector_main(detector_args)


def cmd_decode(args):
    """Decode recognized hidden payloads using the OSS decoder."""
    from stegguard.operations import decode_file

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
    from stegguard.operations import sanitize_file

    result = sanitize_file(
        args.input,
        args.output,
        in_place=args.in_place,
        confirm=args.confirm,
        limits=limits_from_namespace(args),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_watermark(args):
    """Run categorized watermark and provenance analysis."""
    from pathlib import Path

    from stegguard.detector import analyze_file, generate_html_report
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
    if args.html:
        detector_result = analyze_file(Path(args.input), limits=policy)
        detector_result["watermark"] = result
        generate_html_report([detector_result], args.html)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="stegguard",
        description="StegGuard — steganography detection toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  stegguard detect suspicious.txt
  stegguard detect suspicious.txt --html report.html
  stegguard detect . -r --json findings.json
  stegguard decode suspicious.txt
  stegguard sanitize suspicious.txt
  stegguard watermark image.png --c2pa-tool c2patool --html report.html
        """,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # --- detect subcommand ---
    p_detect = sub.add_parser(
        "detect",
        help="Detect steganographic content (OSS)",
        description="Analyse a file or directory for hidden steganographic signals. "
        "Accepts all flags from steg_detector: paths, -v, -d, -r, --ext, "
        "--html, --html-per-folder, --json, --no-venv.",
    )
    p_detect.add_argument(
        "detect_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the detector (paths, flags, etc.)",
    )
    p_detect.set_defaults(func=cmd_detect)

    # --- decode subcommand ---
    p_decode = sub.add_parser(
        "decode",
        help="Decode recognized hidden payloads (OSS)",
        description="Extract recognized hidden payloads without changing the input.",
    )
    p_decode.add_argument("input", help="File to decode")
    add_limit_arguments(p_decode)
    p_decode.set_defaults(func=cmd_decode)

    p_sanitize = sub.add_parser(
        "sanitize",
        help="Remove recognized hidden content safely (OSS)",
        description="Write a sanitized copy by default and emit a JSON change report.",
    )
    p_sanitize.add_argument("input", help="File to sanitize")
    p_sanitize.add_argument("-o", "--output", help="Sanitized output path")
    p_sanitize.add_argument("--in-place", action="store_true", help="Overwrite the input")
    p_sanitize.add_argument(
        "--confirm",
        action="store_true",
        help="Required together with --in-place",
    )
    add_limit_arguments(p_sanitize)
    p_sanitize.set_defaults(func=cmd_sanitize)

    p_watermark = sub.add_parser(
        "watermark",
        help="Analyze watermark signals and Content Credentials (OSS)",
        description=(
            "Run categorized watermark analysis. Optionally validate C2PA with "
            "the official c2patool executable."
        ),
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
    p_watermark.add_argument("--json", dest="json_output", help="Write JSON analysis")
    p_watermark.add_argument("--html", help="Write an HTML report")
    add_limit_arguments(p_watermark)
    p_watermark.set_defaults(func=cmd_watermark)

    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "detect":
        return cmd_detect(arguments[1:])
    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.command == "sanitize" and args.in_place != args.confirm:
        parser.error("overwriting requires both --in-place and --confirm")
    try:
        return args.func(args)
    except (OSError, TypeError, ValueError) as exc:
        print(f"stegguard: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
