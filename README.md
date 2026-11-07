# StegGuard

<p align="center">
  <img src="https://raw.githubusercontent.com/stegguard/stegguard/main/images/steg_banner.png" alt="StegGuard: Uncovering Hidden Data" width="630">
</p>

**Find what is hiding in plain sight.**

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-4EAA25)](https://github.com/stegguard/stegguard/blob/main/LICENSE)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime_dependencies-0-2F855A)](https://github.com/stegguard/stegguard/blob/main/pyproject.toml)

StegGuard is a local-first toolkit for finding, decoding, and safely removing
hidden content from files. It looks beyond ordinary metadata and scans for
invisible Unicode, whitespace channels, homoglyphs, suspicious media
structures, watermark signals, fingerprints, and Content Credentials.

It runs on the Python standard library, stays offline by default, and explains
what it found in JSON and HTML reports you can actually hand to another person.

StegGuard is alpha software. Treat its findings as investigative evidence, not
as an infallible verdict.

## See it work

The repository includes a deterministic, harmless demo. It hides the word
`DEMO` in zero-width characters, detects and decodes it, writes a sanitized
copy, verifies the result, and analyzes a synthetic PNG for watermark and
provenance signals.

```bash
python3 demo/run_demo.py
```

Expected ending:

```text
Demo completed successfully
Decoded hidden text: DEMO
Original preserved: True
Reports: .../demo-output/reports
Summary: .../demo-output/summary.json
```

The demo makes no network requests and contains no executable or malicious
payload. Open `demo-output/reports/detect.html` after the run to inspect the
report. See [the demo guide](https://github.com/stegguard/stegguard/blob/main/demo/README.md) for every generated artifact.

## Why StegGuard exists

Hidden content is rarely one neat payload in one neat format. It can be a
zero-width message in a prompt, a Cyrillic character in a source file, trailing
spaces in a document, bytes after a media container, a private PNG chunk, or a
provenance claim that exists but has never been cryptographically validated.

Most tools handle one of those cases. StegGuard gives them a shared workflow:

```text
untrusted file -> detect -> inspect -> decode -> sanitize a copy -> verify
```

The original stays untouched unless you explicitly authorize an in-place
replacement.

## Install

When a release is available on PyPI:

```bash
python3 -m pip install stegguard
```

From source:

```bash
git clone https://github.com/stegguard/stegguard.git
cd stegguard
python3 -m pip install -e .
```

StegGuard requires Python 3.12 or newer and has no mandatory runtime
dependencies.

For wider image-format decoding through the explicitly tested Pillow path:

```bash
python3 -m pip install "stegguard[images]"
```

The supported Python range is 3.12 through 3.14. CI is configured for Linux,
macOS, and Windows; hosted results are required before those targets are
described as verified. Architecture details and current evidence are in
[docs/platform-support.md](https://github.com/stegguard/stegguard/blob/main/docs/platform-support.md).

## Quick start

Scan one file:

```bash
stegguard detect suspicious.py
```

Scan a repository and save both report formats:

```bash
stegguard detect ./repo -r --json findings.json --html report.html
```

Decode recognized channels without modifying the source. Text files report
zero-width, whitespace, and line-ending payloads. Binary files report metadata
fields and readable pixel LSB payloads:

```bash
stegguard decode suspicious.txt
```

Write a sanitized copy and receive hashes, change counts, and a unified diff:

```bash
stegguard sanitize suspicious.txt
```

Analyze watermark and provenance signals:

```bash
stegguard watermark image.png --json watermark.json --html watermark.html
```

Validate Content Credentials with the official `c2patool` executable:

```bash
stegguard watermark image.png --c2pa-tool c2patool --html provenance.html
```

## Commands

| Command | What it does |
| --- | --- |
| `stegguard detect` | Scans files or directories for hidden-content signals |
| `stegguard decode` | Extracts recognized payloads without changing the input |
| `stegguard sanitize` | Writes a safer copy and reports every change |
| `stegguard watermark` | Analyzes watermark, fingerprint, and provenance evidence |

Run `stegguard COMMAND --help` for options, examples, and exit codes, or
`stegguard COMMAND --help-all` to include the resource limit options. Set
`NO_COLOR` to turn off colored terminal output.

For `detect`, exit status `0` means a completed clean scan, `1` means a
completed scan with findings, and `2` means invalid input or an incomplete
scan. The complete compatibility contract is in
[docs/compatibility.md](https://github.com/stegguard/stegguard/blob/main/docs/compatibility.md).

## What it detects

### Text and source files

- Zero-width and invisible Unicode characters
- Bidirectional controls and suspicious formatting characters
- Cyrillic and Greek homoglyphs
- Trailing-space and tab channels, including SNOW-style patterns
- Mixed and encoded line-ending patterns
- Repeated punctuation, spacing, and layout intervals

### Images, audio, and structured media

- Pixel-level LSB anomalies as a distinct detection category
- Transform and block-correlation signals in decodable lossless images
- Phase, echo, spectral, spread-spectrum, and silence-interval statistics in
  PCM WAV audio
- PNG metadata, private chunks, and appended data
- JPEG EXIF, XMP, and IPTC indicators
- RIFF trailing data, ISO BMFF private boxes, and PSD structures
- Pluggable analyzers for compressed codecs, keyed schemes, and video

### Documents and containers

- PDF embedded files and active or hidden structures
- DOCX, PPTX, XLSX, ZIP, and compatible archive members
- Nested media and archives with bounded member and decompression limits
- SVG and HTML comments, hidden styles, and external references

### Watermarks and provenance

- Metadata, structural, text-pattern, and layout evidence
- Robust image, audio, and video signal families
- Device, camera, printer, encoder, and codec fingerprints
- Embedded and sidecar C2PA manifests
- Content Credentials validated through `c2patool`
- External manifest references with opt-in, bounded HTTPS retrieval
- Pluggable AI text-watermark verifiers

Detection categories remain separate in the output. An LSB anomaly is not
reported as a robust watermark, and the presence of a C2PA manifest is not
reported as cryptographic validation.

## Sanitization is deliberately cautious

By default, this command:

```bash
stegguard sanitize suspicious.txt
```

writes `suspicious.sanitized.txt`. It will not overwrite an existing output and
it reports:

- SHA-256 hashes before and after
- A unified text diff
- The profile and channels used, and counts for every change
- Warnings about anything it kept that could still carry data
- Whether the original was preserved
- Provenance status before and after
- Whether a content change invalidated provenance

Overwriting the original requires both flags:

```bash
stegguard sanitize suspicious.txt --in-place --confirm
```

The default `conservative` profile removes hidden characters only where they have
no legitimate use. It keeps Russian and other non-Latin text, emoji sequences,
joiners in scripts such as Persian and Hindi, Markdown hard breaks, and files that
consistently use CRLF. It still repairs a lookalike letter inside a Latin word, so
`pаypal` with a Cyrillic `а` becomes `paypal`. Anything it keeps can still carry
data, so the report warns about it and a later scan can still flag it.

When the text is hostile and matters less than removing every channel, ask for the
destructive profile. It removes all of these characters and can change legitimate
text, such as turning `Привет` into mixed-script `Пpивeт`:

```bash
stegguard sanitize suspicious.txt --profile destructive
```

To run only some transformations, repeat `--channel` with `zero_width`, `bidi`,
`homoglyphs`, `trailing_whitespace`, `line_endings`, `metadata`, or `lsb`. Changes to source code can
alter its behavior, including string literals, so review the diff.

### Binary files

Binary sanitization understands each format and never deletes bytes it cannot
identify. It uses the `metadata` and `lsb` channels:

| Format | Metadata | Pixel LSBs |
| --- | --- | --- |
| PNG | Removes text and unknown chunks, and data after `IEND` | Cleared; palette images become RGB or RGBA so colors survive |
| BMP | None | Cleared in place for uncompressed 24- and 32-bit images |
| TIFF | Blanks ASCII, XMP, and IPTC tags in the first directory | Cleared in place for uncompressed 8-bit strips |
| GIF | Removes comments, plain text, application blocks, and appended data | Not cleared: palette indices cannot lose a bit without changing colors |
| JPEG | Removes comments and EXIF, XMP, and IPTC segments, and appended data | Not applicable: pixels are transform-coded |
| ZIP, DOCX, XLSX, PPTX | Removes archive and entry comments | Not applicable |
| MP3 | Removes ID3v1 and ID3v2 tags | Not applicable |
| PDF | Blanks Info strings and uncompressed XMP at the same length | Not applicable |

The `conservative` profile keeps color management and C2PA provenance data, and
clears pixel LSBs only when analysis or decoding finds evidence of a payload. The
`destructive` profile removes that data too and always clears pixel LSBs.

`sanitization_status` says how far this went:

- `SANITIZED`: every channel the format exposes was handled
- `PARTIAL`: something was removed or kept with a known gap, such as files inside
  a ZIP or JPEG image data; `warnings` names each gap
- `NO_OP_UNSUPPORTED`: the format is unsupported or the file did not parse, so the
  copy is byte-for-byte identical

LSB decoding finds readable text that starts at the first sample. Encrypted,
compressed, length-prefixed, or randomly spread payloads look like noise, so an
empty result does not prove an image is clean.

### Batch processing

Pass a detector report to process every flagged file:

```bash
stegguard detect . -r --json findings.json
stegguard decode --from-findings findings.json --min-sev high
stegguard sanitize --from-findings findings.json --output-dir clean/
```

One file failing does not stop the batch. Files that are missing, or whose scan
never finished, are reported rather than skipped, and the command then exits `2`.
Each sanitized file reports `clean_after`, the result of re-scanning its output.

## Reports built for review

JSON findings are machine-readable, JSON-compatible, and designed for downstream tools.
HTML reports include:

- Executive severity and provenance summaries
- Per-file evidence with locations and confidence
- Nested container findings
- Signer, source type, manifest location, and validation errors
- C2PA actions, timestamps, edits, and ingredients
- Clear disclaimers around authorship and missing watermarks

Valid provenance is informational. Tampered or untrusted provenance raises the
reported risk.

Machine-readable reports carry `schema_version`. The supported schema is
packaged at `stegguard/schemas/report-v1.schema.json` and its evolution policy
is documented in [docs/compatibility.md](https://github.com/stegguard/stegguard/blob/main/docs/compatibility.md).

## Python API

The core workflows are also available as Python functions:

```python
from stegguard import analyze_file, decode_file, sanitize_file, scan_file

detection = analyze_file("suspicious.txt")
decoded = decode_file("suspicious.txt")
sanitized = sanitize_file("suspicious.txt")
watermarks = scan_file("image.png")
```

Each function returns JSON-compatible data.

## Trust and network model

StegGuard does not make unsolicited network requests. Remote C2PA manifests are
disabled unless `--allow-remote-manifests` is supplied. When enabled, retrieval
is HTTPS-only, rejects redirects and non-global addresses, and enforces timeout
and response-size limits.

C2PA states are explicit: `VALID`, `TAMPERED`, `UNTRUSTED_SIGNER`, `MISSING`,
`UNSUPPORTED`, or `NOT_CHECKED`. If cryptographic validation did not happen,
StegGuard says so.

Scans have configurable limits for input bytes, decompression, image pixels,
archive members, nesting depth, elapsed time, and retained findings. See
[docs/resource-limits.md](https://github.com/stegguard/stegguard/blob/main/docs/resource-limits.md) before processing uploads or
running StegGuard as a service.

## Current limitations

- `c2patool` is optional and installed separately. Without a validator, an
  embedded C2PA claim remains `NOT_CHECKED`.
- Keyed and proprietary watermark schemes require their corresponding analyzer.
- Generic robust-media statistics are leads, not cryptographic proof.
- Video and compressed-codec analysis require a configured analyzer. Missing
  analysis is reported as `NOT_CHECKED`, not clean.
- No official Anthropic text-watermark verifier is bundled. StegGuard does not
  replace one with a home-grown guess.
- Valid provenance means an asset passed the configured validation. It does not
  prove authorship. A missing mark does not prove human authorship either.

## Development

```bash
git clone https://github.com/stegguard/stegguard.git
cd stegguard
uv run pytest
uv run pytest --cov=stegguard --cov-report=term-missing
uv run ruff check stegguard tests demo scripts benchmarks
```

The project intentionally keeps its runtime dependency-free. Tests may use
development dependencies declared in `pyproject.toml`. Contributor setup,
fixture safety, review expectations, and all local gates are in
[CONTRIBUTING.md](https://github.com/stegguard/stegguard/blob/main/CONTRIBUTING.md).

## Contributing

Bug reports, new fixtures, detector improvements, and careful false-positive
reports are welcome. Please include a minimal reproducible sample generated at
test time. Do not commit suspicious payloads, credentials, or generated reports.

Open an issue or pull request at
[github.com/stegguard/stegguard](https://github.com/stegguard/stegguard).

Project policies: [security](https://github.com/stegguard/stegguard/blob/main/SECURITY.md), [support](https://github.com/stegguard/stegguard/blob/main/SUPPORT.md),
[governance](https://github.com/stegguard/stegguard/blob/main/GOVERNANCE.md), [releases](https://github.com/stegguard/stegguard/blob/main/RELEASING.md),
[detection quality](https://github.com/stegguard/stegguard/blob/main/docs/detection-quality.md), and [changelog](https://github.com/stegguard/stegguard/blob/main/CHANGELOG.md).

## License

StegGuard is licensed under Apache License 2.0. See [LICENSE](https://github.com/stegguard/stegguard/blob/main/LICENSE) and
[NOTICE](https://github.com/stegguard/stegguard/blob/main/NOTICE).
