# SPDX-License-Identifier: Apache-2.0
"""Repository configuration checks that prevent readiness regressions."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from stegguard import __version__


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (PROJECT_ROOT / relative).read_text(encoding="utf-8")


def _ci_test_matrix() -> str:
    test_job = _read(".github/workflows/ci.yml").split("\n  test:\n", 1)[1]
    return test_job.split("matrix:\n", 1)[1].split("\n    steps:", 1)[0]


def _matrix_values(key: str) -> list[str]:
    found = re.search(rf"^\s*{key}: \[(.+)\]$", _ci_test_matrix(), re.M)
    assert found, f"CI test matrix does not list {key} as an inline sequence"
    return [value.strip().strip('"') for value in found.group(1).split(",")]


def test_ci_test_job_runs_on_linux_windows_and_macos():
    assert _matrix_values("os") == ["ubuntu-latest", "windows-latest", "macos-latest"]


def test_ci_test_job_runs_every_python_version_classified_in_package_metadata():
    classifiers = tomllib.loads(_read("pyproject.toml"))["project"]["classifiers"]
    classified = [
        classifier.rsplit(" ", 1)[1]
        for classifier in classifiers
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", classifier)
    ]

    assert classified == ["3.12", "3.13", "3.14"]
    assert _matrix_values("python-version") == classified


def test_ci_test_matrix_does_not_add_or_remove_individual_combinations():
    matrix = _ci_test_matrix()

    assert "include:" not in matrix
    assert "exclude:" not in matrix


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
    for label in ("Source", "Documentation", "Issues"):
        assert metadata["urls"][label].startswith("https://github.com/stegguard/stegguard")


def test_project_urls_do_not_include_a_changelog_link():
    metadata = tomllib.loads(_read("pyproject.toml"))["project"]

    assert "Changelog" not in metadata["urls"]
    assert not any("CHANGELOG.md" in url for url in metadata["urls"].values())


def test_changelog_lists_the_current_version_directly_below_unreleased():
    changelog = _read("CHANGELOG.md")
    headings = re.findall(r"^## (.+)$", changelog, re.M)

    assert changelog.startswith("# Changelog\n")
    assert headings[0] == "Unreleased"
    assert headings[1] == __version__


def test_readme_install_section_leads_with_pypi_as_an_available_release():
    readme = _read("README.md")
    install = readme.split("## Install\n", 1)[1].split("\n## ", 1)[0]

    assert install.startswith("\nInstall from PyPI:\n\n```bash\npython3 -m pip install stegguard\n")
    assert "When a release is available" not in install


def test_readme_does_not_describe_hosted_platform_results_as_outstanding():
    assert "hosted results are required" not in _read("README.md")


def test_readme_links_and_images_resolve_outside_github():
    readme = _read("README.md")
    targets = re.findall(r"\]\(([^)\s]+)\)", readme) + re.findall(r'(?:src|href)="([^"]+)"', readme)

    relative = [target for target in targets if not target.startswith(("https://", "#"))]
    assert relative == []


def test_readme_repository_links_point_at_files_in_the_repository():
    readme = _read("README.md")
    prefixes = (
        "https://github.com/stegguard/stegguard/blob/main/",
        "https://raw.githubusercontent.com/stegguard/stegguard/main/",
    )
    linked = {
        target.removeprefix(prefix)
        for target in re.findall(r"(https://[^)\s\"]+)", readme)
        for prefix in prefixes
        if target.startswith(prefix)
    }

    assert linked
    assert [path for path in sorted(linked) if not (PROJECT_ROOT / path).is_file()] == []


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

    assert (
        'src="https://raw.githubusercontent.com/stegguard/stegguard/main/images/steg_banner.png"'
        in readme
    )
    assert 'alt="StegGuard: Uncovering Hidden Data"' in readme
    assert (PROJECT_ROOT / "images/steg_banner.png").is_file()
