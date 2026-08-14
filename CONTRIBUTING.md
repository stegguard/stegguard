# Contributing to StegGuard

Thank you for helping make StegGuard more dependable. Detector changes can
affect both security decisions and ordinary files, so small, evidenced changes
are much easier to review than heroic rewrites.

## Set up a development environment

StegGuard supports Python 3.12 through 3.14. Install `uv`, clone the repository,
then run:

```bash
uv sync --extra dev
uv run pytest
```

To exercise the optional Pillow-backed image path:

```bash
uv sync --extra dev --extra images
```

## Before opening a pull request

Run the same local gates used in CI:

```bash
uv run pytest --cov=stegguard --cov-report=term-missing
uv run ruff check stegguard tests demo scripts benchmarks
uv run mypy stegguard/limits.py stegguard/schema.py stegguard/_version.py
uv run bandit -q -r stegguard -ll
```

Behavior changes need a regression test. Keep public result fields compatible,
or explain the migration and update the versioned JSON Schema. New CLI failures
must use the documented exit-code contract.

Branch coverage currently has an 82 percent floor against an observed 82.47
percent baseline. New critical error paths should raise that floor instead of
using it as a destination.

## Fixture safety

- Generate suspicious byte patterns in a test or describe them as escaped data
  in `tests/corpus/manifest-v1.json`.
- Do not commit live malware, weaponized documents, credentials, personal data,
  copyrighted sample sets, or unexplained binary blobs.
- Keep corpus licenses and origins recorded.
- Add realistic benign cases for every new positive detector rule.
- Report false positives and false negatives through the dedicated issue form.

See [docs/detection-quality.md](docs/detection-quality.md) for the evaluation
process.

## Pull requests and review

Keep each pull request focused. Describe risk, compatibility impact, tests, and
platforms exercised. At least one maintainer review is required for detector,
network, parser, release, or security-policy changes. The author should not
approve their own release.

Use the pull-request checklist, respond to review findings, and update
documentation in the same change. Dependency updates should include the reason
for the version range and any relevant advisory.

## Releases

Only maintainers publish releases. The build, Trusted Publishing, attestation,
SBOM, rollback, and verification process is in [RELEASING.md](RELEASING.md).

By contributing, you agree that your contribution is licensed under Apache
License 2.0 and that you will follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
