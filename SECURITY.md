# Security Policy

## Supported versions

StegGuard is alpha software. Security fixes are provided for the latest
released minor version only. Older releases may receive a notice directing
users to upgrade, but they are not maintained as separate security branches.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |
| Unreleased `main` branch | Best effort |

## Report a vulnerability privately

Do not open a public issue for a vulnerability or include a live malicious
sample in a pull request. Use GitHub's
[private vulnerability reporting form](https://github.com/stegguard/stegguard/security/advisories/new).

Include the affected version, operating system, reproduction steps, expected
impact, and the smallest safe proof of concept you can provide. Encrypt or
redact credentials and personal data. A maintainer will acknowledge a complete
report within five business days and coordinate validation, remediation, and
disclosure with the reporter.

If private reporting is unavailable, contact a maintainer through the accounts
listed in [MAINTAINERS.md](MAINTAINERS.md) and ask for a private channel. Do not
send the vulnerability details in that first public message.

## Response and release process

Maintainers will:

1. Reproduce and classify the issue without exposing the report.
2. Prepare a regression test using a harmless generated fixture where possible.
3. Audit supported release lines and relevant dependencies.
4. Publish a patched release and GitHub security advisory.
5. Record the fix and affected versions in `CHANGELOG.md`.

Release rollback and artifact verification are documented in
[RELEASING.md](RELEASING.md).

## Scope

Crashes, resource exhaustion, unsafe file replacement, sandbox escapes,
network-policy bypasses, report injection, and supply-chain compromise are in
scope. A detector miss or false positive without a security boundary bypass is
usually better reported with the false-positive issue form.

