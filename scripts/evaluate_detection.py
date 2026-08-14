#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate a versioned, harmless StegGuard corpus manifest."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from stegguard.detector import analyze_file
from stegguard.watermark import scan_file


def _payload(case: dict[str, Any]) -> bytes:
    encoding = case["encoding"]
    if encoding == "utf-8":
        return case["content"].encode("utf-8")
    if encoding == "hex":
        return bytes.fromhex(case["content"])
    raise ValueError(f"unsupported corpus encoding: {encoding}")


def _family_detected(family: str, detector: dict[str, Any], watermark: dict[str, Any]) -> bool:
    if family in {"TEXT", "BINARY"}:
        return bool(
            detector.get("total_hidden")
            or detector.get("trailing_whitespace_lines")
            or detector.get("mixed_line_endings")
        )
    return any(finding.get("category") == family for finding in watermark["findings"])


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(row["expected"] and row["observed"] for row in rows)
    tn = sum(not row["expected"] and not row["observed"] for row in rows)
    fp = sum(not row["expected"] and row["observed"] for row in rows)
    fn = sum(row["expected"] and not row["observed"] for row in rows)

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 6) if denominator else None

    return {
        "samples": len(rows),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, fn + tp),
    }


def evaluate(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="stegguard-corpus-") as directory:
        root = Path(directory)
        for case in manifest["cases"]:
            source = root / case["filename"]
            source.write_bytes(_payload(case))
            detector = analyze_file(source)
            watermark = scan_file(str(source))
            rows.append(
                {
                    "id": case["id"],
                    "family": case["family"],
                    "format": source.suffix.lower() or source.name.lower(),
                    "expected": bool(case["expected_detected"]),
                    "observed": _family_detected(case["family"], detector, watermark),
                }
            )

    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_family[row["family"]].append(row)
    return {
        "corpus_version": manifest["corpus_version"],
        "formats": sorted({row["format"] for row in rows}),
        "overall": _metrics(rows),
        "families": {
            family: _metrics(family_rows) for family, family_rows in sorted(by_family.items())
        },
        "cases": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate(args.manifest)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 1 if result["overall"]["false_positives"] or result["overall"]["false_negatives"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
