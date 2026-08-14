# SPDX-License-Identifier: Apache-2.0
"""Optional adapters for external verification tools.

These adapters keep the core package dependency-free. They execute explicitly
configured binaries without a shell and normalize their output into StegGuard's
JSON-compatible provenance contract.
"""

from __future__ import annotations

import json
import http.client
import ipaddress
import socket
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


_MAX_TOOL_OUTPUT = 10 * 1024 * 1024
_UNTRUSTED_CODES = (
    "untrusted",
    "unknownsigner",
    "credential.nottrusted",
    "signingcredential.untrusted",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            newurl, code, "Remote manifest redirects are disabled", headers, fp
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection whose TCP peer is a previously validated IP address."""

    def __init__(self, hostname: str, address: str, timeout: float) -> None:
        self._tls_context = ssl.create_default_context()
        super().__init__(hostname, port=443, timeout=timeout, context=self._tls_context)
        self._validated_address = address

    def connect(self) -> None:
        plain_socket = socket.create_connection(
            (self._validated_address, self.port),
            self.timeout,
        )
        self.sock = self._tls_context.wrap_socket(plain_socket, server_hostname=self.host)


class RemoteManifestLoader:
    """Load an explicitly allowed remote C2PA manifest with SSRF limits."""

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        max_bytes: int = 2 * 1024 * 1024,
        opener: Any = None,
        resolver: Any = None,
        connection_factory: Any = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._opener = opener
        self._resolver = resolver
        self._connection_factory = connection_factory or _PinnedHTTPSConnection

    def _validate_url(
        self, url: str
    ) -> tuple[Any, list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("remote C2PA manifests require an HTTPS URL")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("remote C2PA manifest URL contains disallowed components")
        if parsed.port not in (None, 443):
            raise ValueError("remote C2PA manifests require HTTPS port 443")
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise ValueError("remote C2PA manifest host is not public")
        try:
            addresses = [ipaddress.ip_address(hostname)]
        except ValueError:
            try:
                addresses = [
                    ipaddress.ip_address(entry[4][0])
                    for entry in (self._resolver or socket.getaddrinfo)(
                        hostname, 443, 0, socket.SOCK_STREAM
                    )
                ]
            except socket.gaierror as exc:
                raise ValueError(f"remote C2PA manifest host could not be resolved: {exc}") from exc
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError("remote C2PA manifest host resolves to a non-public address")
        return parsed, addresses

    def _read_response(self, response: Any) -> bytes:
        declared = response.headers.get("Content-Length")
        if declared:
            try:
                if int(declared) > self.max_bytes:
                    raise ValueError("remote C2PA manifest exceeds the size limit")
            except ValueError as exc:
                if "size limit" in str(exc):
                    raise
                raise ValueError("remote C2PA manifest has an invalid Content-Length") from exc
        content = response.read(self.max_bytes + 1)
        if len(content) > self.max_bytes:
            raise ValueError("remote C2PA manifest exceeds the size limit")
        return content

    def __call__(self, url: str) -> bytes:
        parsed, addresses = self._validate_url(url)
        if self._opener is None:
            hostname = parsed.hostname.rstrip(".").lower()
            connection = self._connection_factory(
                hostname,
                addresses[0].compressed,
                self.timeout,
            )
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            try:
                connection.request(
                    "GET",
                    target,
                    headers={
                        "Host": hostname,
                        "Accept": "application/c2pa, application/octet-stream, application/json",
                    },
                )
                response = connection.getresponse()
                if 300 <= response.status < 400:
                    raise ValueError("remote C2PA manifest redirects are disabled")
                if response.status >= 400:
                    raise urllib.error.HTTPError(
                        url,
                        response.status,
                        response.reason,
                        response.headers,
                        None,
                    )
                return self._read_response(response)
            finally:
                connection.close()

        request = urllib.request.Request(
            url,
            headers={"Accept": "application/c2pa, application/octet-stream, application/json"},
            method="GET",
        )
        with self._opener(request, timeout=self.timeout) as response:
            final_url = response.geturl()
            if final_url != url:
                raise ValueError("remote C2PA manifest redirects are disabled")
            return self._read_response(response)


def _validation_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            if key in {"validation_status", "validationStatus"}:
                visit(list(value.values()))
                return
            if "code" in value and (
                "validation" in key.lower() or "explanation" in value or "url" in value
            ):
                entries.append(value)
            for child_key, child in value.items():
                visit(child, child_key)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, dict) and "code" in child:
                    entries.append(child)
                else:
                    visit(child, key)

    visit(payload)
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        identity = (str(entry.get("code", "")), str(entry.get("explanation", "")))
        if identity not in seen:
            seen.add(identity)
            unique.append(entry)
    return unique


def _active_manifest(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    manifests = payload.get("manifests") or {}
    if not isinstance(manifests, dict) or not manifests:
        return "", {}
    label = str(payload.get("active_manifest") or payload.get("activeManifest") or "")
    if label and isinstance(manifests.get(label), dict):
        return label, manifests[label]
    first_label, first_manifest = next(iter(manifests.items()))
    return str(first_label), first_manifest if isinstance(first_manifest, dict) else {}


def _manifest_actions(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for assertion in manifest.get("assertions", []) or []:
        if not isinstance(assertion, dict):
            continue
        label = str(assertion.get("label", ""))
        data = assertion.get("data") or {}
        if label.startswith("c2pa.actions") and isinstance(data, dict):
            actions.extend(item for item in data.get("actions", []) if isinstance(item, dict))
    return actions


class C2paToolValidator:
    """Validate assets with the official ``c2patool`` command-line utility."""

    def __init__(
        self,
        executable: str | Path | Sequence[str | Path] = "c2patool",
        *,
        timeout: float = 30.0,
    ) -> None:
        if isinstance(executable, (str, Path)):
            self.command_prefix = [str(executable)]
        else:
            self.command_prefix = [str(part) for part in executable]
            if not self.command_prefix:
                raise ValueError("C2PA tool command must not be empty")
        self.executable = " ".join(self.command_prefix)
        self.timeout = timeout

    def validate_file(self, source: Path, manifest_location: str = "") -> dict[str, Any]:
        command = [*self.command_prefix, str(source), "-d"]
        if (
            manifest_location
            and manifest_location != "embedded"
            and not manifest_location.startswith(("http://", "https://"))
            and Path(manifest_location).suffix.lower() == ".c2pa"
        ):
            command.extend(["--external-manifest", manifest_location])
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError:
            return {
                "status": "NOT_CHECKED",
                "validation_errors": [f"C2PA tool not found: {self.executable}"],
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "NOT_CHECKED",
                "validation_errors": [f"C2PA tool exceeded {self.timeout:g}s timeout"],
            }
        except OSError as exc:
            return {
                "status": "NOT_CHECKED",
                "validation_errors": [f"C2PA tool could not be launched: {exc}"],
            }

        if len(completed.stdout) > _MAX_TOOL_OUTPUT:
            return {
                "status": "NOT_CHECKED",
                "validation_errors": ["C2PA tool output exceeded the 10 MiB safety limit"],
            }
        try:
            payload = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            return {
                "status": "NOT_CHECKED",
                "validation_errors": [f"C2PA tool returned invalid JSON: {exc}", stderr][:2],
            }
        if not isinstance(payload, dict):
            return {
                "status": "NOT_CHECKED",
                "validation_errors": ["C2PA tool JSON root must be an object"],
            }

        label, manifest = _active_manifest(payload)
        validation = _validation_entries(payload)
        errors = [
            str(entry.get("explanation") or entry.get("code") or "C2PA validation error")
            for entry in validation
        ]
        codes = [str(entry.get("code", "")).lower() for entry in validation]
        if not label:
            status = "MISSING"
        elif any(any(token in code for token in _UNTRUSTED_CODES) for code in codes):
            status = "UNTRUSTED_SIGNER"
        elif validation or completed.returncode != 0:
            status = "TAMPERED"
            if not errors:
                errors.append(
                    completed.stderr.decode("utf-8", errors="replace").strip()
                    or f"c2patool exited with status {completed.returncode}"
                )
        else:
            status = "VALID"

        signature = manifest.get("signature_info") or manifest.get("signatureInfo") or {}
        if not isinstance(signature, dict):
            signature = {}
        actions = _manifest_actions(manifest)
        ingredients = [
            ingredient
            for ingredient in manifest.get("ingredients", []) or []
            if isinstance(ingredient, dict)
        ]
        source_types = [
            str(action.get("digitalSourceType"))
            for action in actions
            if action.get("digitalSourceType")
        ]
        timestamps = [
            str(value)
            for value in (
                signature.get("time"),
                signature.get("timestamp"),
                manifest.get("claim_generator_time"),
            )
            if value
        ]
        claim_generator = str(
            manifest.get("claim_generator") or manifest.get("claimGenerator") or ""
        )
        signer = str(
            signature.get("issuer")
            or signature.get("common_name")
            or signature.get("commonName")
            or ""
        )
        provider = signer
        if "anthropic" in signer.lower() or "claude" in claim_generator.lower():
            provider = "Anthropic"
        return {
            "status": status,
            "provider": provider,
            "claim_generator": claim_generator,
            "signer_identity": signer,
            "certificate_trust": str(
                signature.get("cert_trust")
                or signature.get("certificate_trust")
                or (
                    "untrusted"
                    if status == "UNTRUSTED_SIGNER"
                    else "trusted"
                    if status == "VALID"
                    else "unknown"
                )
            ),
            "digital_source_type": source_types[0] if source_types else "",
            "timestamps": timestamps,
            "validation_errors": errors,
            "actions": actions,
            "ingredients": ingredients,
            "manifest_label": label,
        }

    def validate_content(
        self,
        source: Path,
        content: bytes,
        manifest_location: str = "",
    ) -> dict[str, Any]:
        """Validate an on-disk or nested in-memory asset."""
        try:
            if source.is_file() and source.read_bytes() == content:
                return self.validate_file(source, manifest_location)
        except OSError:
            pass
        with tempfile.TemporaryDirectory(prefix="stegguard-c2pa-") as directory:
            temporary = Path(directory) / (source.name or "nested.bin")
            temporary.write_bytes(content)
            local_location = manifest_location
            if manifest_location not in ("", "embedded") and not manifest_location.startswith(
                ("http://", "https://")
            ):
                local_location = "embedded"
            return self.validate_file(temporary, local_location)
