#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate a versioned, harmless StegGuard corpus manifest."""

from __future__ import annotations

import argparse
import io
import json
import math
import random
import struct
import wave
import zipfile
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from stegguard.detector import analyze_file, result_is_flagged, result_is_incomplete


def _payload(case: dict[str, Any]) -> bytes:
    encoding = case["encoding"]
    if encoding == "utf-8":
        return case["content"].encode("utf-8")
    if encoding == "hex":
        return bytes.fromhex(case["content"])
    if encoding == "zip":
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w") as archive:
            for name, content in case.get("members", {}).items():
                archive.writestr(name, content.encode("utf-8"))
            archive.comment = case.get("comment", "").encode("utf-8")
        return result.getvalue()
    if encoding == "wav":
        result = io.BytesIO()
        rate = 8000
        if case["content"] == "tone":
            samples = [int(10000 * math.sin(2 * math.pi * 440 * i / rate)) for i in range(rate * 2)]
        else:
            rng = random.Random(1)
            dry = [rng.randint(-5000, 5000) for _ in range(rate * 2)]
            samples = [
                sample + int(0.7 * dry[i - 320]) if i >= 320 else sample
                for i, sample in enumerate(dry)
            ]
        with wave.open(result, "wb") as output:
            output.setparams((1, 2, rate, 0, "NONE", "not compressed"))
            output.writeframes(struct.pack(f"<{len(samples)}h", *samples))
        return result.getvalue()
    raise ValueError(f"unsupported corpus encoding: {encoding}")


def _family_detected(family: str, detector: dict[str, Any], watermark: dict[str, Any]) -> bool:
    if family in {"TEXT", "BINARY"}:
        return bool(
            detector.get("total_hidden")
            or detector.get("trailing_whitespace_lines")
            or detector.get("mixed_line_endings")
        )
    return any(
        finding.get("category") == family
        and (family not in {"TEXT_PATTERN", "STRUCTURAL"} or finding.get("risk") != "informational")
        for finding in watermark["findings"]
    ) or any(
        _family_detected(family, detector, nested["result"])
        for nested in watermark.get("nested_results", [])
    )


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
    verdicts: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="stegguard-corpus-") as directory:
        root = Path(directory)
        for case in manifest["cases"]:
            source = root / case["filename"]
            source.write_bytes(_payload(case))
            detector = analyze_file(source)
            watermark = detector.get("watermark", {"findings": []})
            rows.append(
                {
                    "id": case["id"],
                    "family": case["family"],
                    "format": source.suffix.lower() or source.name.lower(),
                    "expected": bool(case["expected_detected"]),
                    "observed": _family_detected(case["family"], detector, watermark),
                }
            )

            verdicts.append(
                {
                    **rows[-1],
                    "expected": case.get("expected_flagged", case["expected_detected"]),
                    "observed": result_is_flagged(detector),
                    "incomplete": result_is_incomplete(detector),
                }
            )

    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_family[row["family"]].append(row)
    verdict_groups = {}
    for key in ("format", "family"):
        groups = defaultdict(list)
        for row in verdicts:
            groups[row[key]].append(row)
        verdict_groups[f"{key}s" if key == "format" else "families"] = {
            name: _metrics(group) for name, group in sorted(groups.items())
        }
    return {
        "corpus_version": manifest["corpus_version"],
        "formats": sorted({row["format"] for row in rows}),
        "overall": _metrics(rows),
        "families": {
            family: _metrics(family_rows) for family, family_rows in sorted(by_family.items())
        },
        "cases": rows,
        "final_verdicts": {
            "overall": _metrics(verdicts),
            "incomplete_files": sum(row["incomplete"] for row in verdicts),
            **verdict_groups,
        },
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
