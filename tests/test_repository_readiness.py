# SPDX-License-Identifier: Apache-2.0
"""Repository configuration checks that prevent readiness regressions."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (PROJECT_ROOT / relative).read_text(encoding="utf-8")


def test_ci_covers_supported_python_and_major_operating_systems():
    workflow = _read(".github/workflows/ci.yml")

    assert "ubuntu-latest" in workflow
    assert "windows-latest" in workflow
    assert "macos-latest" in workflow
    for version in ("3.12", "3.13", "3.14"):
        assert version in workflow
    assert "3.8" not in workflow
    assert "3.10" not in workflow
    assert "timeout-minutes:" in workflow
    assert "permissions:\n  contents: read" in workflow


def test_workflows_pin_third_party_actions_to_full_commit_shas():
    workflows = list((PROJECT_ROOT / ".github/workflows").glob("*.yml"))
    assert workflows

    for workflow in workflows:
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "uses:" in line:
                reference = line.split("@", 1)[-1].split("#", 1)[0].strip()
                assert re.fullmatch(r"[0-9a-f]{40}", reference), (workflow, line)


def test_release_workflow_builds_attests_and_uses_trusted_publishing():
    workflow = _read(".github/workflows/release.yml")

    assert "id-token: write" in workflow
    assert "attest-build-provenance" in workflow
    assert "gh-action-pypi-publish" in workflow
    assert "environment:" in workflow and "pypi" in workflow


def test_dependabot_tracks_actions_and_python_dependencies():
    config = _read(".github/dependabot.yml")

    assert 'package-ecosystem: "github-actions"' in config
    assert 'package-ecosystem: "pip"' in config


def test_python_support_is_bounded_and_classified():
    metadata = tomllib.loads(_read("pyproject.toml"))["project"]

    assert metadata["requires-python"] == ">=3.12,<3.15"
    for classifier in (
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Operating System :: OS Independent",
    ):
        assert classifier in metadata["classifiers"]


def test_development_extra_contains_release_and_quality_tools():
    metadata = tomllib.loads(_read("pyproject.toml"))
    dependencies = " ".join(metadata["project"]["optional-dependencies"]["dev"])

    for package in ("build", "twine", "ruff", "mypy", "bandit", "pip-audit"):
        assert package in dependencies


def test_ci_enforces_formatting_and_tests_an_isolated_wheel_install():
    workflow = _read(".github/workflows/ci.yml")

    assert "ruff format --check stegguard tests demo scripts benchmarks" in workflow
    assert "python -m venv" in workflow
    assert "--force-reinstall --no-deps dist/" in workflow
    assert "import stegguard" in workflow


def test_project_metadata_names_people_and_repository_resources():
    metadata = tomllib.loads(_read("pyproject.toml"))["project"]

    assert metadata["authors"]
    assert metadata["maintainers"]
    for label in ("Source", "Documentation", "Changelog", "Issues"):
        assert metadata["urls"][label].startswith("https://github.com/stegguard/stegguard")


def test_pillow_behavior_is_an_explicit_optional_extra():
    metadata = tomllib.loads(_read("pyproject.toml"))["project"]

    assert any(
        dependency.startswith("Pillow>=")
        for dependency in metadata["optional-dependencies"]["images"]
    )
    assert 'python -m pip install -e ".[dev,images]"' in _read(".github/workflows/ci.yml")


def test_repository_health_documents_and_templates_exist():
    required = (
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SUPPORT.md",
        "GOVERNANCE.md",
        "MAINTAINERS.md",
        "CHANGELOG.md",
        "RELEASING.md",
        ".github/pull_request_template.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/false_positive.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        "docs/platform-support.md",
        "docs/compatibility.md",
        "docs/detection-quality.md",
        "docs/detection-baseline-v1.json",
        "docs/resource-limits.md",
        "tests/corpus/manifest-v1.json",
        "benchmarks/benchmark_scan.py",
        "benchmarks/BASELINE.md",
    )

    for relative in required:
        assert (PROJECT_ROOT / relative).is_file(), relative


def test_cross_platform_text_file_policy_is_declared():
    attributes = _read(".gitattributes")
    editorconfig = _read(".editorconfig")

    assert "* text=auto eol=lf" in attributes
    assert "end_of_line = lf" in editorconfig


def test_showcase_page_documents_install_scan_and_html_reporting():
    page = _read("docs/index.html")

    assert "<!doctype html>" in page.lower()
    assert "python3 -m pip install stegguard" in page
    assert "stegguard detect suspicious.py" in page
    assert "stegguard detect ./repo -r --json findings.json --html report.html" in page
    assert "stegguard watermark image.png --json watermark.json --html watermark.html" in page
    for category in (
        "Hidden text and source signals",
        "Media and LSB steganalysis",
        "Documents and containers",
        "Watermarks and provenance",
    ):
        assert category in page
    assert "Evidence classification, not an AI verdict" in page
    assert "NOT_CHECKED" in page
    assert "A clean result is not proof that a file is safe" in page
    assert "steg_banner.png" not in page
    assert "brand-banner" not in page
    assert 'name="viewport"' in page


def test_readme_displays_the_project_banner():
    readme = _read("README.md")

    assert 'src="images/steg_banner.png"' in readme
    assert 'alt="StegGuard: Uncovering Hidden Data"' in readme
    assert (PROJECT_ROOT / "images/steg_banner.png").is_file()
