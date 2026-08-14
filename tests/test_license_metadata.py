# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import tomllib

import stegguard


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_distribution_declares_apache_2_consistently():
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

    assert metadata["project"]["license"] == "Apache-2.0"
    assert metadata["project"]["license-files"] == ["LICENSE", "NOTICE"]
    assert stegguard.__license__ == "Apache-2.0"
    license_text = (PROJECT_ROOT / "LICENSE").read_text()
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text


def test_distributed_python_sources_have_no_conflicting_license_notice():
    conflicting_terms = (
        "GNU General Public " + "License",
        "MIT " + "License",
    )
    python_files = sorted((PROJECT_ROOT / "stegguard").glob("*.py"))
    python_files += sorted((PROJECT_ROOT / "tests").glob("*.py"))
    python_files += sorted((PROJECT_ROOT / "demo").glob("*.py"))

    conflicts = {
        path.relative_to(PROJECT_ROOT).as_posix(): term
        for path in python_files
        for term in conflicting_terms
        if term in path.read_text()
    }

    assert conflicts == {}
