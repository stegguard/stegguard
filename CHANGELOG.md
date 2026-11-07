# Changelog

Notable changes are recorded here. StegGuard follows Semantic Versioning for
the Python API, CLI contract, and versioned report schema.

## Unreleased

## 0.5.0

### Added

- `stegguard decode` reads metadata fields from PNG, JPEG, GIF, TIFF, ZIP, MP3, and
  PDF files, and readable pixel LSB payloads from PNG, BMP, GIF, and TIFF images.
- `stegguard sanitize` removes that metadata and clears pixel LSBs through new
  `metadata` and `lsb` channels.
- `--from-findings`, `--min-sev`, and `--output-dir` process every flagged file in a
  detector report, also available as `stegguard.process_findings`.
- A `PARTIAL` sanitization status for files with a known remaining gap.
- An ASCII banner, the detect-decode-sanitize workflow, and exit codes on `stegguard --help`.
- Examples and exit codes on every command's `--help`.
- `--help-all` on every command, which also lists the resource limit options and
  their defaults.
- Bold headings and a colored banner in help shown on a terminal.
- Colored output now honors the `NO_COLOR` environment variable.

### Changed

- The `--max-*` resource limit options are hidden from `--help`; they still work and
  are listed by `--help-all`.
- Sanitizing a supported binary format now writes a cleaned copy instead of an
  identical one. Unsupported and unparseable files are still copied unchanged and
  marked `NO_OP_UNSUPPORTED`. To keep the old behavior for a format, select only
  text channels with `--channel`.
- CI now tests Python 3.13 and 3.14 on Windows and macOS, in addition to Linux.
- **Security-relevant default:** `sanitize` now uses a `conservative` profile that
  keeps non-Latin text, emoji sequences, script joiners, Markdown hard breaks, and
  consistent CRLF files, which 0.4.0 damaged. Kept characters can still carry data,
  so reports warn about them and a later scan can still flag them. For the 0.4.0
  behavior, pass `--profile destructive`. See `docs/compatibility.md`.
- `sanitize` adds `--profile` and `--channel`, and reports add `policy`, `warnings`,
  and counts of what was kept.
- `sanitize` now also removes U+2068, First Strong Isolate.

### Fixed

- `detect` no longer reports a container as clean when a nested member has an
  actionable watermark or provenance finding, or when a scan stopped early at a
  nested level. These containers now exit `1` or `2`, count as flagged or
  incomplete, and name the member path in terminal and HTML output, so scans
  that previously passed may now fail.
- `detect` no longer reports a file as clean when LSB image analysis, a configured
  analyzer, or the JSON report's file hash fails. These results exit `2`, and JSON
  results list the cause in the new `incomplete_reasons` field. Valid images the
  built-in decoder cannot read, such as interlaced PNGs, are now incomplete unless
  Pillow can decode them; install `stegguard[images]` to scan them.
- `watermark` now exits `2` on an incomplete scan, as documented.
- Per-folder mode no longer reports an incomplete folder as clean, and it scans
  each file once instead of repeating the scan for JSON and combined reports.
- LSB error text is now escaped in HTML reports.

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

