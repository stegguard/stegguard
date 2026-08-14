# SPDX-License-Identifier: Apache-2.0
"""Compatibility tests for public versions, APIs, and serialized reports."""

from __future__ import annotations

import importlib.resources
import json
import tomllib
from pathlib import Path

import stegguard
from stegguard.detector import analyze_file, write_json_output


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_package_uses_one_dynamic_version_source():
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["dynamic"] == ["version"]
    assert "version" not in metadata["project"]
    assert metadata["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "stegguard._version.__version__"
    }
    assert "0.3.0" not in (PROJECT_ROOT / "stegguard" / "cli.py").read_text()
    assert "0.3.0" not in (PROJECT_ROOT / "stegguard" / "detector.py").read_text()


def test_resource_policy_and_schema_version_are_public():
    assert stegguard.SCHEMA_VERSION == "1.0"
    assert stegguard.ScanLimits().max_file_bytes > 0
    assert issubclass(stegguard.ResourceLimitError, ValueError)


def test_public_api_results_include_schema_version(tmp_path):
    source = tmp_path / "plain.txt"
    source.write_text("plain\n", encoding="utf-8", newline="")
    sanitized = tmp_path / "plain.cleaned.txt"

    assert stegguard.analyze_file(source)["schema_version"] == stegguard.SCHEMA_VERSION
    assert stegguard.decode_file(source)["schema_version"] == stegguard.SCHEMA_VERSION
    assert stegguard.sanitize_file(source, sanitized)["schema_version"] == stegguard.SCHEMA_VERSION
    assert stegguard.scan_file(str(source))["schema_version"] == stegguard.SCHEMA_VERSION


def test_aggregate_detector_report_declares_schema_version(tmp_path):
    source = tmp_path / "plain.txt"
    source.write_text("plain\n", encoding="utf-8", newline="")
    output = tmp_path / "report.json"

    write_json_output([analyze_file(source)], str(output))

    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "1.0"


def test_packaged_report_schema_describes_required_contract():
    schema_text = (
        importlib.resources.files("stegguard")
        .joinpath("schemas/report-v1.schema.json")
        .read_text(encoding="utf-8")
    )
    schema = json.loads(schema_text)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert {"schema_version", "stegguard_version", "results"} <= set(schema["required"])
    assert schema["properties"]["schema_version"]["const"] == "1.0"
