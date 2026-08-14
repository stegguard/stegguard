# Releasing StegGuard

## One-time repository setup

An administrator must create a protected GitHub environment named `pypi`, add
PyPI Trusted Publishing for the repository and `release.yml`, protect `main`
and `v*` tags, and require the CI test, quality, optional-image, and package
jobs. Require at least one approving review and dismiss stale approvals.

These settings live outside the repository. Do not mark them complete until an
administrator captures their current configuration.

## Prepare a release

1. Confirm the supported Python and platform jobs are green.
2. Run the full local gates in `CONTRIBUTING.md`.
3. Audit dependencies and review Dependabot changes.
4. Update `CHANGELOG.md`, compatibility notes, and the single version in
   `stegguard/_version.py`.
5. Build an sdist and wheel, run `twine check` and `check-wheel-contents`, then
   install the wheel in a clean environment and run `stegguard --version`.
6. Obtain a maintainer review and create a signed `vX.Y.Z` tag.

Pushing the tag starts `.github/workflows/release.yml`. The workflow builds once,
generates an SBOM, creates GitHub provenance attestations, and publishes the same
artifacts through PyPI Trusted Publishing.

## Verify

Compare the PyPI files with the workflow artifacts, verify the GitHub
attestation, inspect the SBOM, install the exact release into a clean
environment, and run the documented CLI smoke commands. Then create the GitHub
release from the matching changelog section.

## Roll back

PyPI releases are immutable and cannot be replaced. If a release is bad:

1. Stop the publishing environment and mark the GitHub release as affected.
2. Yank the PyPI version when installation should be discouraged.
3. Revert or fix the defect on `main` with a regression test.
4. Publish a new patch version through the normal workflow.
5. Record the affected and replacement versions in the changelog and, for a
   vulnerability, the GitHub security advisory.

Never reuse or move a published version tag.

