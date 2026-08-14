# SPDX-License-Identifier: Apache-2.0
import json
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

from stegguard import cli
from stegguard.integrations import C2paToolValidator, RemoteManifestLoader
from stegguard.watermark import scan_file


def _fake_c2patool(tmp_path: Path, payload: dict, exit_code: int = 0) -> list[str]:
    executable = tmp_path / "fake_c2patool.py"
    executable.write_text(
        f"import json, sys\nprint(json.dumps({payload!r}))\nraise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    return [sys.executable, str(executable)]


def test_c2patool_validator_normalizes_valid_claim(tmp_path):
    asset = tmp_path / "claude.jpg"
    asset.write_bytes(b"\xff\xd8content\xff\xd9")
    tool = _fake_c2patool(
        tmp_path,
        {
            "active_manifest": "urn:test",
            "manifests": {
                "urn:test": {
                    "claim_generator": "Claude/1.0",
                    "signature_info": {
                        "issuer": "Anthropic",
                        "time": "2026-08-12T00:00:00Z",
                        "cert_trust": "trusted",
                    },
                    "assertions": [
                        {
                            "label": "c2pa.actions",
                            "data": {"actions": [{"action": "c2pa.created"}]},
                        }
                    ],
                    "ingredients": [{"title": "source.png", "relationship": "parentOf"}],
                }
            },
            "validation_status": [],
        },
    )

    result = scan_file(
        str(asset),
        provenance_validator=C2paToolValidator(executable=tool),
    )

    provenance = result["provenance"]
    assert provenance["status"] == "VALID"
    assert provenance["provider"] == "Anthropic"
    assert provenance["claim_generator"] == "Claude/1.0"
    assert provenance["signer_identity"] == "Anthropic"
    assert provenance["certificate_trust"] == "trusted"
    assert provenance["timestamps"] == ["2026-08-12T00:00:00Z"]
    assert provenance["actions"] == [{"action": "c2pa.created"}]
    assert provenance["ingredients"] == [{"title": "source.png", "relationship": "parentOf"}]


def test_c2patool_validator_maps_validation_failure_to_tampered(tmp_path):
    asset = tmp_path / "edited.png"
    asset.write_bytes(b"\x89PNG\r\n\x1a\n")
    tool = _fake_c2patool(
        tmp_path,
        {
            "active_manifest": "urn:test",
            "manifests": {"urn:test": {}},
            "validation_status": [
                {
                    "code": "assertion.dataHash.mismatch",
                    "explanation": "content hash mismatch",
                }
            ],
        },
        exit_code=1,
    )

    result = scan_file(
        str(asset),
        provenance_validator=C2paToolValidator(executable=tool),
    )

    assert result["provenance"]["status"] == "TAMPERED"
    assert "content hash mismatch" in result["provenance"]["validation_errors"]


def test_c2patool_validator_reports_untrusted_signer_separately(tmp_path):
    asset = tmp_path / "unknown.svg"
    asset.write_text("<svg/>", encoding="utf-8")
    tool = _fake_c2patool(
        tmp_path,
        {
            "active_manifest": "urn:test",
            "manifests": {"urn:test": {"signature_info": {"issuer": "Unknown"}}},
            "validation_status": [
                {
                    "code": "signingCredential.untrusted",
                    "explanation": "certificate chain is not trusted",
                }
            ],
        },
    )

    result = scan_file(
        str(asset),
        provenance_validator=C2paToolValidator(executable=tool),
    )

    assert result["provenance"]["status"] == "UNTRUSTED_SIGNER"


def test_c2patool_missing_manifest_is_missing_not_valid(tmp_path):
    asset = tmp_path / "plain.jpg"
    asset.write_bytes(b"\xff\xd8content\xff\xd9")
    tool = _fake_c2patool(tmp_path, {"manifests": {}, "validation_status": []})

    result = scan_file(
        str(asset),
        provenance_validator=C2paToolValidator(executable=tool),
    )

    assert result["provenance"]["status"] == "MISSING"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/manifest.c2pa",
        "https://127.0.0.1/manifest.c2pa",
        "https://[::1]/manifest.c2pa",
        "https://localhost/manifest.c2pa",
        "https://169.254.169.254/latest/meta-data",
    ],
)
def test_remote_manifest_loader_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        RemoteManifestLoader()(url)


def test_remote_manifest_loader_enforces_content_limit(monkeypatch):
    class Response:
        headers = {"Content-Length": "99999999"}

        def geturl(self):
            return "https://credentials.example/manifest.c2pa"

        def read(self, amount):
            return b"x" * amount

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(
        "stegguard.integrations.socket.getaddrinfo",
        lambda *args: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ],
    )
    with pytest.raises(ValueError, match="size limit"):
        RemoteManifestLoader(max_bytes=1024, opener=lambda *args, **kwargs: Response())(
            "https://credentials.example/manifest.c2pa"
        )


def test_remote_manifest_loader_returns_bounded_binary_manifest(monkeypatch):
    class Response:
        headers = {"Content-Length": "4"}

        def geturl(self):
            return "https://credentials.example/manifest.c2pa"

        def read(self, amount):
            return b"c2pa"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(
        "stegguard.integrations.socket.getaddrinfo",
        lambda *args: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ],
    )
    loader = RemoteManifestLoader(opener=lambda *args, **kwargs: Response())
    assert loader("https://credentials.example/manifest.c2pa") == b"c2pa"


def test_remote_manifest_loader_connects_to_the_validated_address():
    calls = {}

    class Response:
        status = 200
        reason = "OK"
        headers = {"Content-Length": "4"}

        def read(self, amount):
            return b"c2pa"

    class Connection:
        def request(self, method, target, headers):
            calls["request"] = (method, target, headers)

        def getresponse(self):
            return Response()

        def close(self):
            calls["closed"] = True

    def connection_factory(hostname, address, timeout):
        calls["connection"] = (hostname, address, timeout)
        return Connection()

    resolver = lambda *args: [(2, 1, 6, "", ("93.184.216.34", 443))]
    loader = RemoteManifestLoader(
        resolver=resolver,
        connection_factory=connection_factory,
    )

    assert loader("https://credentials.example/manifest.c2pa?x=1") == b"c2pa"
    assert calls["connection"][:2] == ("credentials.example", "93.184.216.34")
    assert calls["request"][:2] == ("GET", "/manifest.c2pa?x=1")
    assert calls["request"][2]["Host"] == "credentials.example"
    assert calls["closed"] is True


def test_watermark_cli_uses_c2patool_and_writes_html(tmp_path, monkeypatch, capsys):
    asset = tmp_path / "claude.jpg"
    asset.write_bytes(b"\xff\xd8content\xff\xd9")
    report = tmp_path / "report.html"
    tool = _fake_c2patool(
        tmp_path,
        {
            "active_manifest": "urn:test",
            "manifests": {
                "urn:test": {
                    "claim_generator": "Claude/1.0",
                    "signature_info": {"issuer": "Anthropic", "cert_trust": "trusted"},
                }
            },
            "validation_status": [],
        },
    )
    validator = C2paToolValidator(executable=tool)
    monkeypatch.setattr(
        "stegguard.integrations.C2paToolValidator",
        lambda executable: validator,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "stegguard",
            "watermark",
            str(asset),
            "--c2pa-tool",
            "c2patool",
            "--html",
            str(report),
        ],
    )

    cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["provenance"]["status"] == "VALID"
    html = report.read_text(encoding="utf-8")
    assert "processed by Claude" in html
    assert "Provenance Valid" in html


def test_c2patool_validates_nested_media_from_temporary_asset(tmp_path):
    chunk_type = b"c2pa"
    manifest = b'{"provider":"Anthropic"}'
    crc = zlib.crc32(chunk_type + manifest) & 0xFFFFFFFF
    png = (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", len(manifest))
        + chunk_type
        + manifest
        + struct.pack(">I", crc)
    )
    archive_path = tmp_path / "container.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("media/claude.png", png)
    tool = tmp_path / "fake_c2patool.py"
    tool.write_text(
        "import json, pathlib, sys\n"
        "assert pathlib.Path(sys.argv[1]).is_file()\n"
        "print(json.dumps({"
        "'active_manifest':'urn:test',"
        "'manifests':{'urn:test':{'claim_generator':'Claude/1.0'}},"
        "'validation_status':[]"
        "}))\n",
        encoding="utf-8",
    )

    result = scan_file(
        str(archive_path),
        provenance_validator=C2paToolValidator(executable=[sys.executable, str(tool)]),
    )

    assert result["nested_results"][0]["result"]["provenance"]["status"] == "VALID"


def test_c2patool_timeout_is_reported_without_exception(tmp_path, monkeypatch):
    asset = tmp_path / "asset.jpg"
    asset.write_bytes(b"asset")
    monkeypatch.setattr(
        "stegguard.integrations.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(args[0], timeout=0.01)
        ),
    )

    result = C2paToolValidator("c2patool", timeout=0.01).validate_file(asset)

    assert result["status"] == "NOT_CHECKED"
    assert "timeout" in result["validation_errors"][0]


def test_c2patool_invalid_output_is_reported_without_exception(tmp_path, monkeypatch):
    asset = tmp_path / "asset.jpg"
    asset.write_bytes(b"asset")
    monkeypatch.setattr(
        "stegguard.integrations.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, b"not-json", b"bad format"),
    )

    result = C2paToolValidator("c2patool").validate_file(asset)

    assert result["status"] == "NOT_CHECKED"
    assert "invalid JSON" in result["validation_errors"][0]
    assert "bad format" in result["validation_errors"][1]


def test_c2patool_oversized_output_is_reported_without_parsing(tmp_path, monkeypatch):
    asset = tmp_path / "asset.jpg"
    asset.write_bytes(b"asset")
    monkeypatch.setattr(
        "stegguard.integrations.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            b"x" * (10 * 1024 * 1024 + 1),
            b"",
        ),
    )

    result = C2paToolValidator("c2patool").validate_file(asset)

    assert result["status"] == "NOT_CHECKED"
    assert "output exceeded" in result["validation_errors"][0]


def test_c2patool_preserves_explicit_windows_executable_path(tmp_path, monkeypatch):
    asset = tmp_path / "asset.jpg"
    asset.write_bytes(b"asset")
    command = {}

    def run(arguments, **kwargs):
        command["arguments"] = arguments
        return subprocess.CompletedProcess(arguments, 0, b'{"manifests": {}}', b"")

    monkeypatch.setattr("stegguard.integrations.subprocess.run", run)
    executable = r"C:\Program Files\C2PA Tool\c2patool.exe"

    result = C2paToolValidator(executable).validate_file(asset)

    assert command["arguments"] == [executable, str(asset), "-d"]
    assert result["status"] == "MISSING"
