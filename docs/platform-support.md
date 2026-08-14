# Platform Support

StegGuard's pure-Python core is intended for CPython 3.12 through 3.14. The
package metadata deliberately excludes newer Python versions until they have a
CI job.

## Validation matrix

| Platform | Python | CI configuration | Current evidence |
| --- | --- | --- | --- |
| Linux, GitHub-hosted runner | 3.12, 3.13, 3.14 | Required test matrix | Local Linux 3.12 passes; hosted results require GitHub |
| Windows, GitHub-hosted runner | 3.12 | Required test matrix | Configured; hosted result pending |
| macOS, GitHub-hosted runner | 3.12 | Required test matrix | Configured; hosted result pending |

The wheel is platform-independent Python code. CI builds it, checks its
contents, installs it over the source installation, and runs a CLI smoke test.
That does not make every optional external analyzer platform-independent.

## Architecture status

Linux x86-64 is the local development baseline. Linux ARM64, macOS Apple
Silicon, Windows ARM64, 32-bit systems, PyPy, and alternative Python runtimes
are unverified. Reports from those environments are welcome, but they are not
support claims yet.

GitHub-hosted runner labels may change their underlying CPU architecture. When
architecture matters, record `platform.machine()` in the CI evidence instead of
inferring it from `macos-latest` or another label.

## Filesystem and process behavior

Repository text files use LF endings, while Windows command files use CRLF.
Tests use `pathlib`, preserve byte-level fixtures explicitly, and skip POSIX
permission assertions on Windows. Unicode paths and portable command-prefix
execution are covered by tests.

`c2patool` is optional. Pass an explicit path when it is not on `PATH`:

```text
stegguard watermark asset.jpg --c2pa-tool /path/to/c2patool
stegguard watermark asset.jpg --c2pa-tool C:\Tools\c2patool.exe
```

The subprocess is started without a shell. Launch, permission, timeout, invalid
output, and missing-executable failures produce `NOT_CHECKED` provenance rather
than an uncaught exception.

