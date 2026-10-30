#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the dependency-free StegGuard end-to-end demonstration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from create_samples import create_samples


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DemoError(RuntimeError):
    """Raised when a real CLI command fails during the demonstration."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_cli(arguments: list[str], *, findings_ok: bool = False) -> str:
    environment = os.environ.copy()
    environment["NO_COLOR"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "stegguard", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    allowed_exit_codes = {0, 1} if findings_ok else {0}
    if result.returncode not in allowed_exit_codes:
        command = "stegguard " + " ".join(arguments)
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise DemoError(f"{command} failed with exit code {result.returncode}: {detail}")
    return result.stdout


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run_demo(output_dir: Path, *, color: bool = True) -> dict[str, Any]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise DemoError(f"output directory is not empty: {output_dir}")

    samples_dir = output_dir / "samples"
    reports_dir = output_dir / "reports"
    sanitized_dir = output_dir / "sanitized"
    reports_dir.mkdir(parents=True, exist_ok=True)
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    create_samples(samples_dir)

    suspicious = samples_dir / "suspicious.txt"
    image = samples_dir / "watermarked.png"
    sanitized = sanitized_dir / "suspicious.sanitized.txt"
    original_sha256 = _sha256(suspicious)

    steps = [
        "Detecting hidden text signals",
        "Decoding the zero-width demonstration payload",
        "Writing a safe sanitized copy",
        "Verifying the sanitized copy",
        "Analyzing watermark and provenance signals",
    ]
    for index, label in enumerate(steps, start=1):
        prefix = f"\033[36m[{index}/{len(steps)}]\033[0m" if color else f"[{index}/{len(steps)}]"
        print(f"{prefix} {label}")
        if index == 1:
            _run_cli(
                [
                    "detect",
                    str(suspicious),
                    "--json",
                    str(reports_dir / "detect.json"),
                    "--html",
                    str(reports_dir / "detect.html"),
                ],
                findings_ok=True,
            )
        elif index == 2:
            decode_output = _run_cli(["decode", str(suspicious)])
            (reports_dir / "decode.json").write_text(decode_output, encoding="utf-8")
        elif index == 3:
            sanitize_output = _run_cli(["sanitize", str(suspicious), "--output", str(sanitized)])
            (reports_dir / "sanitize.json").write_text(sanitize_output, encoding="utf-8")
        elif index == 4:
            _run_cli(
                [
                    "detect",
                    str(sanitized),
                    "--json",
                    str(reports_dir / "sanitized-detect.json"),
                ]
            )
        else:
            _run_cli(
                [
                    "watermark",
                    str(image),
                    "--json",
                    str(reports_dir / "watermark.json"),
                    "--html",
                    str(reports_dir / "watermark.html"),
                ]
            )

    decode = _load_json(reports_dir / "decode.json")
    sanitize = _load_json(reports_dir / "sanitize.json")
    sanitized_report = _load_json(reports_dir / "sanitized-detect.json")
    sanitized_detection = sanitized_report["results"][0]
    watermark = _load_json(reports_dir / "watermark.json")
    original_preserved = _sha256(suspicious) == original_sha256
    decoded_text = decode["zero_width"]["decoded"]
    sanitized_occurrences = len(sanitized_detection["zero_width"])

    checks = {
        "decoded_expected_text": decoded_text == "DEMO",
        "original_preserved": original_preserved,
        "sanitized_copy_changed": sanitize["changed"] is True,
        "sanitized_zero_width_removed": sanitized_occurrences == 0,
        "sanitized_scan_clean": sanitized_detection["total_hidden"] == 0,
        "watermark_findings_present": bool(watermark["findings"]),
    }
    summary: dict[str, Any] = {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "safe_demo": True,
        "network_used": False,
        "original_preserved": original_preserved,
        "decoded_zero_width": decoded_text,
        "sanitized_changed": sanitize["changed"],
        "sanitized_zero_width_occurrences": sanitized_occurrences,
        "sanitized_total_hidden": sanitized_detection["total_hidden"],
        "original_sha256": original_sha256,
        "sanitized_sha256": _sha256(sanitized),
        "watermark_finding_count": len(watermark["findings"]),
        "checks": checks,
        "reports": sorted(path.name for path in reports_dir.iterdir()),
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    if summary["status"] != "PASS":
        failed = ", ".join(name for name, passed in checks.items() if not passed)
        raise DemoError(f"demo verification failed: {failed}")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "demo-output",
        help="New or empty output directory (default: demo-output)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored progress output")
    args = parser.parse_args()
    try:
        summary = run_demo(args.output.resolve(), color=not args.no_color)
    except (DemoError, FileExistsError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Demo failed: {exc}", file=sys.stderr)
        return 2

    print("\nDemo completed successfully")
    print(f"Decoded hidden text: {summary['decoded_zero_width']}")
    print(f"Original preserved: {summary['original_preserved']}")
    print(f"Reports: {args.output.resolve() / 'reports'}")
    print(f"Summary: {args.output.resolve() / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
