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
`2` on invalid input or an incomplete operation. Findings from `watermark` are
reported in JSON; only `detect` currently uses `1` for a positive result.

## Reports and schemas

Machine-readable reports contain `schema_version`. Schema `1.x` may add
optional fields but will not remove fields or change their type or meaning.
Breaking report changes increment the schema major version and ship a new file
under `stegguard/schemas/`. Readers should reject unsupported major versions and
ignore unknown optional fields within a supported major version.

Golden contract tests cover package version consistency, public exports, CLI
exit codes, representative JSON fields, and the packaged schema. Compatibility
changes belong in `CHANGELOG.md`.

