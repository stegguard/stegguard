# Compatibility Policy

StegGuard uses Semantic Versioning. Until 1.0, minor releases may intentionally
change experimental detectors, but documented public contracts still require a
migration note and tests.

## Python API

The names exported by `stegguard.__all__`, their required arguments, and their
top-level result fields are public. Additive optional parameters and result
fields are backward-compatible. Removing or renaming a public name, changing a
default with security consequences, or changing an existing field's meaning is
breaking.

Deprecations remain available for at least one minor release and emit a
`DeprecationWarning`. Security defects may require faster removal; that exception
must be documented in the security advisory and changelog.

## CLI

Command names, long option names, JSON field meanings, and exit codes are
public. Human-readable terminal and HTML presentation may improve without a
major release if machine contracts remain stable.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed and no flagged finding was detected |
| `1` | Scan completed and at least one finding was detected |
| `2` | Invocation was invalid or the scan was incomplete |

`decode`, `sanitize`, and `watermark` return `0` on a completed operation and
`2` on invalid input or an incomplete operation. With `--from-findings`, any file
that could not be processed makes the operation incomplete. Findings from `watermark` are
reported in JSON; only `detect` currently uses `1` for a positive result.

### What counts as an incomplete scan

| Analysis | When it does not finish | Effect |
| --- | --- | --- |
| Required: file reading, text and binary scans, nested container scans, LSB analysis of `.png`, `.bmp`, `.gif`, and `.tif`/`.tiff` files, and the JSON report's file hash | Malformed input, an exhausted resource limit, or an image the available decoders cannot read | Incomplete, exit `2` |
| Configured: a robust-media analyzer or AI text verifier that was set up to run | The analyzer raises or returns `ERROR` | Incomplete, exit `2` |
| Optional: a robust-media analyzer with none configured or a format outside the built-in analyzer's scope | Status stays `NOT_CHECKED` | Not a failure; robust media is listed as not checked in terminal and HTML output |
| Optional: AI text verifier with none configured, C2PA validation | Status stays `NOT_CHECKED` | Not a failure; reported in JSON and HTML |

The built-in PNG decoder reads non-interlaced 8-bit images only. Other valid
images are incomplete unless Pillow can decode them, so install
`stegguard[images]` to scan them. An incomplete result takes precedence over
findings. Each JSON result lists the reasons in `incomplete_reasons`, and its
`severity` only describes findings, so check that list or `incomplete_files`
before treating `clean` as conclusive.

### Sanitization profiles

| Channel | `conservative` (default) | `destructive` |
| --- | --- | --- |
| `zero_width` | Keeps emoji joiners, joiners between letters of scripts that use them, zero-width spaces in unspaced scripts, direction marks beside right-to-left text, and a leading byte order mark. Removes the rest | Removes all |
| `bidi` | Removes all | Removes all |
| `homoglyphs` | Replaces lookalikes only inside words otherwise made of Latin letters | Replaces all, including in non-Latin words |
| `trailing_whitespace` | Removes it, except two spaces for a hard break in Markdown files | Removes all |
| `line_endings` | Converts mixed files to their most common ending and leaves consistent files alone | Converts all to LF |

The conservative profile is not a guarantee that a file is free of hidden data.
Kept characters can still carry a payload, so the report's `warnings` list them,
and scanning the output can still flag them. Use `destructive` for hostile input
when keeping the text exact does not matter.

#### Migrating from 0.4.0

`sanitize` and `sanitize_file()` previously behaved like `destructive`. To keep
that behavior, pass `--profile destructive` or `profile="destructive"`. Reports add
`policy`, `warnings`, and the `changes` keys `zero_width_preserved`,
`homoglyphs_preserved`, and `hard_breaks_preserved`.

## Reports and schemas

Machine-readable reports contain `schema_version`. Schema `1.x` may add
optional fields but will not remove fields or change their type or meaning.
Breaking report changes increment the schema major version and ship a new file
under `stegguard/schemas/`. Readers should reject unsupported major versions and
ignore unknown optional fields within a supported major version.

Golden contract tests cover package version consistency, public exports, CLI
exit codes, representative JSON fields, and the packaged schema. Compatibility
changes belong in `CHANGELOG.md`.

