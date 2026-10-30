# Changelog

Notable changes are recorded here. StegGuard follows Semantic Versioning for
the Python API, CLI contract, and versioned report schema.

## Unreleased

## 0.4.0

### Added

- Resource budgets for input bytes, decompression, pixels, archive members,
  nesting, scan duration, and finding counts.
- Versioned JSON reports and a packaged JSON Schema.
- Linux, macOS, Windows, Python 3.12 through 3.14, package, quality, and optional
  Pillow CI jobs.
- Trusted Publishing, artifact attestation, SBOM, and dependency-update
  automation.
- Project security, support, governance, contribution, compatibility, platform,
  release, benchmark, and detection-quality documentation.

### Changed

- The HTML report loads no external resources and follows the system light or
  dark color scheme.
- CLI output is always UTF-8, including on Windows consoles and pipes that
  default to a legacy code page.

### Fixed

- Unified flagged-result aggregation, including LSB and watermark findings.
- Binary routing for WebAssembly and matching for extensionless `Dockerfile`.
- Detector option forwarding and stable CLI exit statuses.
- Bounded PNG and nested-container processing.
- Remote-manifest resolve-then-connect races and external-tool launch failures.
- Cross-platform external-tool integration fixtures and output creation races.
- Concurrent report writes on Windows no longer fail with `PermissionError`.
- The decompression budget is enforced when images are decoded with Pillow.

### Security

- Added explicit scan budgets and bounded external interactions for untrusted
  inputs.
- Pinned workflow actions to reviewed commit identifiers and added dependency
  auditing.

## 0.3.0

- Initial alpha version represented by this source snapshot. Historical release
  tags and published artifact provenance still require verification from a
  complete Git repository.

