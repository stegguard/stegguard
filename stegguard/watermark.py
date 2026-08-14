# SPDX-License-Identifier: Apache-2.0
"""Watermark, fingerprint, and provenance detection primitives."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import struct
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from stegguard.limits import (
    ResourceLimitError,
    ScanLimits,
    check_deadline,
    deadline_for,
    read_limited,
    read_stream_limited,
    resolve_limits,
)
from stegguard.schema import SCHEMA_VERSION


DETECTION_CATEGORIES = {
    "METADATA",
    "STRUCTURAL",
    "TEXT_PATTERN",
    "LAYOUT",
    "IMAGE_ROBUST",
    "AUDIO_ROBUST",
    "VIDEO_ROBUST",
    "FINGERPRINT",
    "PROVENANCE",
    "NETWORK_OR_EXTERNAL",
    "AI_TEXT_WATERMARK",
    "C2PA_PROVENANCE",
    "LSB",
}

PROVENANCE_STATUSES = {
    "VALID",
    "TAMPERED",
    "UNTRUSTED_SIGNER",
    "MISSING",
    "UNSUPPORTED",
    "NOT_CHECKED",
}


@dataclass(frozen=True)
class DetectionFinding:
    """A stable JSON-compatible description of one detection signal."""

    category: str
    detector: str
    description: str
    confidence: float
    location: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    risk: str = "informational"

    def __post_init__(self) -> None:
        if self.category not in DETECTION_CATEGORIES:
            raise ValueError(f"Unknown detection category: {self.category}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProvenanceRecord:
    """Validation outcome and normalized C2PA claim information."""

    status: str = "NOT_CHECKED"
    provider: str = ""
    claim_generator: str = ""
    signer_identity: str = ""
    certificate_trust: str = "unknown"
    digital_source_type: str = ""
    timestamps: list[str] = field(default_factory=list)
    manifest_location: str = ""
    validation_errors: list[str] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    ingredients: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in PROVENANCE_STATUSES:
            raise ValueError(f"Unknown provenance status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _finding(
    category: str,
    detector: str,
    description: str,
    confidence: float,
    *,
    location: str = "",
    evidence: dict[str, Any] | None = None,
    risk: str = "informational",
) -> DetectionFinding:
    return DetectionFinding(
        category=category,
        detector=detector,
        description=description,
        confidence=confidence,
        location=location,
        evidence=evidence or {},
        risk=risk,
    )


def _scan_png(raw: bytes) -> list[DetectionFinding]:
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return []
    findings: list[DetectionFinding] = []
    position = 8
    iend_end = 0
    while position + 12 <= len(raw):
        length = struct.unpack_from(">I", raw, position)[0]
        chunk_type = raw[position + 4 : position + 8]
        chunk_end = position + length + 12
        if chunk_end > len(raw):
            findings.append(
                _finding(
                    "STRUCTURAL",
                    "png_malformed_chunk",
                    "PNG chunk extends beyond the file boundary.",
                    0.95,
                    location=f"byte:{position}",
                    risk="high",
                )
            )
            break
        if chunk_type in {b"tEXt", b"zTXt", b"iTXt", b"eXIf"}:
            findings.append(
                _finding(
                    "METADATA",
                    "png_metadata_chunk",
                    "PNG contains a text or EXIF metadata field.",
                    0.7,
                    location=chunk_type.decode("ascii"),
                    evidence={"chunk_type": chunk_type.decode("ascii"), "length": length},
                )
            )
        position = chunk_end
        if chunk_type == b"IEND":
            iend_end = chunk_end
            break
    if iend_end and iend_end < len(raw):
        findings.append(
            _finding(
                "STRUCTURAL",
                "png_appended_data",
                "Data exists after the PNG IEND chunk.",
                0.98,
                location=f"byte:{iend_end}",
                evidence={"appended_bytes": len(raw) - iend_end},
                risk="high",
            )
        )
    return findings


def _scan_pdf(raw: bytes) -> list[DetectionFinding]:
    if not raw.startswith(b"%PDF"):
        return []
    markers = {
        b"/EmbeddedFile": "embedded file",
        b"/Filespec": "file specification",
        b"/OCG": "optional hidden-content group",
        b"/JavaScript": "embedded JavaScript",
        b"/Launch": "launch action",
    }
    present = [label for marker, label in markers.items() if marker in raw]
    if not present:
        return []
    return [
        _finding(
            "STRUCTURAL",
            "pdf_hidden_structure",
            "PDF contains structures capable of carrying hidden or active content.",
            0.9,
            evidence={"structures": present},
            risk="high",
        )
    ]


def _scan_structural(source: Path, raw: bytes) -> list[DetectionFinding]:
    """Parse format boundaries and inventory hidden/private structures."""
    findings: list[DetectionFinding] = []
    suffix = source.suffix.lower()

    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        position = 8
        private_chunks: list[str] = []
        while position + 12 <= len(raw):
            length = struct.unpack_from(">I", raw, position)[0]
            chunk_type = raw[position + 4 : position + 8]
            chunk_end = position + length + 12
            if chunk_end > len(raw):
                break
            if len(chunk_type) == 4 and 97 <= chunk_type[1] <= 122:
                private_chunks.append(chunk_type.decode("ascii", errors="replace"))
            position = chunk_end
            if chunk_type == b"IEND":
                break
        if private_chunks:
            findings.append(
                _finding(
                    "STRUCTURAL",
                    "png_private_chunk",
                    "PNG contains private ancillary chunks that may carry application-specific data.",
                    0.75,
                    evidence={"chunk_types": private_chunks},
                    risk="medium",
                )
            )

    if suffix in _ZIP_CONTAINER_EXTENSIONS:
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = [member.filename for member in archive.infolist() if not member.is_dir()]
                nested_archives = [
                    name
                    for name in members
                    if Path(name).suffix.lower()
                    in {".zip", ".docx", ".pptx", ".xlsx", ".jar", ".apk"}
                ]
                encrypted = [
                    member.filename for member in archive.infolist() if member.flag_bits & 0x1
                ]
            if members:
                findings.append(
                    _finding(
                        "STRUCTURAL",
                        "archive_embedded_files",
                        "Archive or Office container embeds file members.",
                        0.65 if not nested_archives and not encrypted else 0.9,
                        evidence={
                            "file_count": len(members),
                            "nested_archives": nested_archives,
                            "encrypted_members": encrypted,
                            "sample_members": members[:20],
                        },
                        risk="high" if nested_archives or encrypted else "informational",
                    )
                )
        except (OSError, zipfile.BadZipFile):
            pass

    if len(raw) >= 12 and raw[:4] in {b"RIFF", b"RIFX", b"RF64"}:
        byte_order = ">" if raw[:4] == b"RIFX" else "<"
        declared_end = struct.unpack_from(f"{byte_order}I", raw, 4)[0] + 8
        if declared_end < len(raw):
            findings.append(
                _finding(
                    "STRUCTURAL",
                    "riff_appended_data",
                    "RIFF media contains bytes beyond its declared container size.",
                    0.95,
                    location=f"byte:{declared_end}",
                    evidence={"appended_bytes": len(raw) - declared_end},
                    risk="high",
                )
            )

    if suffix in {".mp4", ".mov", ".m4v", ".3gp"} and len(raw) >= 8:
        position = 0
        private_boxes: list[str] = []
        while position + 8 <= len(raw):
            size = struct.unpack_from(">I", raw, position)[0]
            box_type = raw[position + 4 : position + 8]
            header_size = 8
            if size == 1 and position + 16 <= len(raw):
                size = struct.unpack_from(">Q", raw, position + 8)[0]
                header_size = 16
            elif size == 0:
                size = len(raw) - position
            if size < header_size or position + size > len(raw):
                break
            if box_type in {b"uuid", b"free", b"skip"}:
                private_boxes.append(box_type.decode("ascii"))
            position += size
        if private_boxes:
            findings.append(
                _finding(
                    "STRUCTURAL",
                    "bmff_private_box",
                    "ISO BMFF media contains private or padding boxes.",
                    0.75,
                    evidence={"box_types": private_boxes},
                    risk="medium",
                )
            )
        if position < len(raw):
            findings.append(
                _finding(
                    "STRUCTURAL",
                    "bmff_appended_data",
                    "ISO BMFF media contains bytes outside parsed box boundaries.",
                    0.9,
                    location=f"byte:{position}",
                    evidence={"appended_bytes": len(raw) - position},
                    risk="high",
                )
            )

    if suffix == ".psd" and raw.startswith(b"8BPS") and b"8BIM" in raw:
        resource_count = raw.count(b"8BIM")
        findings.append(
            _finding(
                "STRUCTURAL",
                "psd_layer_structure",
                "Photoshop document contains layer or image-resource records.",
                0.7,
                evidence={"resource_markers": resource_count},
                risk="informational",
            )
        )
    return findings


def _scan_format_metadata(source: Path, raw: bytes) -> list[DetectionFinding]:
    suffix = source.suffix.lower()
    fields: set[str] = set()
    lowered = raw.lower()
    if suffix in {".jpg", ".jpeg"}:
        if b"exif\x00\x00" in lowered:
            fields.add("exif")
        if b"http://ns.adobe.com/xap/1.0/" in lowered or b"<x:xmpmeta" in lowered:
            fields.add("xmp")
        if b"photoshop 3.0" in lowered:
            fields.add("iptc")
    elif suffix in {".mp3", ".aac"} and raw.startswith(b"ID3"):
        fields.add("id3")
    elif suffix in {".flac", ".ogg", ".opus"}:
        if any(marker in lowered for marker in (b"title=", b"artist=", b"comment=")):
            fields.add("vorbis_comment")
    elif suffix == ".pdf":
        for key in (b"/author", b"/title", b"/subject", b"/keywords", b"/creator", b"/producer"):
            if key in lowered:
                fields.add(key[1:].decode("ascii"))
    elif suffix in {".svg", ".html", ".htm"} and re.search(rb"<!--.*?-->", raw, re.S):
        fields.add("text_comment")

    if suffix in _ZIP_CONTAINER_EXTENSIONS:
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                if archive.comment:
                    fields.add("archive_comment")
                if any(name.startswith("docProps/") for name in archive.namelist()):
                    fields.add("office_properties")
        except (OSError, zipfile.BadZipFile):
            pass

    if not fields:
        return []
    return [
        _finding(
            "METADATA",
            "format_metadata_fields",
            "File contains format-specific metadata or comment fields.",
            0.65,
            evidence={"fields": sorted(fields)},
        )
    ]


def _scan_text(text: str) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    double_spaces = len(re.findall(r"(?<! ) {2}(?! )", text))
    punctuation_intervals = len(re.findall(r"[.!?](?:\s+\w+){1,4}\s{2}", text))
    if double_spaces >= 3 or punctuation_intervals >= 2:
        findings.append(
            _finding(
                "TEXT_PATTERN",
                "typography_interval_pattern",
                "Repeated typography intervals may encode a text watermark.",
                min(0.95, 0.45 + double_spaces * 0.1),
                evidence={
                    "double_space_intervals": double_spaces,
                    "punctuation_intervals": punctuation_intervals,
                },
            )
        )

    layout_patterns = {
        "display_none": r"display\s*:\s*none",
        "zero_opacity": r"opacity\s*:\s*0(?:[;\"']|\s)",
        "zero_font": r"font-size\s*:\s*0(?:px|pt|em|rem|%)?",
        "visibility_hidden": r"visibility\s*:\s*hidden",
        "off_canvas": r"(?:left|top)\s*:\s*-\d{3,}(?:px|pt)",
    }
    matched_layout = [
        name for name, pattern in layout_patterns.items() if re.search(pattern, text, re.I)
    ]
    if matched_layout:
        findings.append(
            _finding(
                "LAYOUT",
                "hidden_layout_style",
                "Document styling hides or moves content out of view.",
                0.92,
                evidence={"patterns": matched_layout},
                risk="high",
            )
        )

    external_urls = sorted(
        {match.rstrip(".,;:!?)]}") for match in re.findall(r"https?://[^\s\"'<>]+", text, re.I)}
    )
    if external_urls:
        findings.append(
            _finding(
                "NETWORK_OR_EXTERNAL",
                "external_payload_reference",
                "Content references an external resource that may carry watermark data.",
                0.55,
                evidence={"urls": external_urls[:20]},
            )
        )
    return findings


def _scan_media_signals(source: Path, raw: bytes) -> list[DetectionFinding]:
    lowered = raw.lower()
    suffix = source.suffix.lower()
    findings: list[DetectionFinding] = []
    robust_groups = (
        (
            "IMAGE_ROBUST",
            {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"},
            {
                b"dct-watermark": "transform_domain",
                b"dwt-watermark": "transform_domain",
                b"correlation-template": "correlation",
                b"spread-spectrum-image": "spread_spectrum",
            },
        ),
        (
            "AUDIO_ROBUST",
            {".wav", ".mp3", ".flac", ".ogg", ".aac", ".m4a", ".opus", ".aiff"},
            {
                b"phase_watermark": "phase",
                b"echo-hiding": "echo",
                b"spread-spectrum-audio": "spread_spectrum",
                b"spectral_watermark": "spectral",
                b"silence-interval-watermark": "silence_interval",
            },
        ),
        (
            "VIDEO_ROBUST",
            {".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v", ".mpeg", ".mpg"},
            {
                b"frame_watermark": "frame",
                b"motion_vector_watermark": "motion_vector",
                b"chroma-watermark": "chroma",
                b"audio_track_watermark": "audio_track",
            },
        ),
    )
    for category, extensions, markers in robust_groups:
        if suffix not in extensions:
            continue
        matched = sorted({label for marker, label in markers.items() if marker in lowered})
        if matched:
            findings.append(
                _finding(
                    category,
                    "declared_robust_watermark_signal",
                    "Media contains a robust-watermark declaration or recognizable signal marker.",
                    0.65,
                    evidence={"signal_families": matched, "proof": False},
                )
            )

    fingerprint_markers = {
        b"make=": "camera_make",
        b"model=": "camera_model",
        b"software=": "codec_or_software",
        b"encoder=": "codec_encoder",
        b"device_fingerprint=": "device_fingerprint",
        b"printer_fingerprint=": "printer_fingerprint",
        b"camera_fingerprint=": "camera_fingerprint",
    }
    matched_fingerprints = sorted(
        {label for marker, label in fingerprint_markers.items() if marker in lowered}
    )
    if matched_fingerprints:
        findings.append(
            _finding(
                "FINGERPRINT",
                "device_codec_fingerprint",
                "File carries device, printer, camera, or codec fingerprint indicators.",
                0.6,
                evidence={"markers": matched_fingerprints},
            )
        )
    return findings


_C2PA_EXTENSIONS = {".svg", ".png", ".jpg", ".jpeg"}


def _embedded_c2pa_manifest(source: Path, raw: bytes) -> Any:
    if source.suffix.lower() == ".png" and raw.startswith(b"\x89PNG\r\n\x1a\n"):
        position = 8
        while position + 12 <= len(raw):
            length = struct.unpack_from(">I", raw, position)[0]
            chunk_type = raw[position + 4 : position + 8]
            chunk_end = position + length + 12
            if chunk_end > len(raw):
                break
            if chunk_type in {b"c2pa", b"caBX"}:
                payload = raw[position + 8 : position + 8 + length]
                try:
                    return json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return {"raw_manifest_hex": payload.hex()}
            position = chunk_end
    lowered = raw.lower()
    if b"c2pa" in lowered or b"content credentials" in lowered:
        return {"embedded_claim_container": True}
    return None


def _locate_c2pa_manifest(
    source: Path,
    raw: bytes,
    remote_loader: Any = None,
) -> tuple[Any, str, list[str]]:
    for sidecar in (
        source.with_name(source.name + ".c2pa.json"),
        source.with_suffix(".c2pa.json"),
        source.with_name(source.name + ".c2pa"),
    ):
        if not sidecar.is_file():
            continue
        try:
            if sidecar.suffix.lower() == ".json":
                manifest = json.loads(sidecar.read_text(encoding="utf-8"))
            else:
                manifest = sidecar.read_bytes()
            return manifest, str(sidecar), []
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return None, str(sidecar), [f"Malformed sidecar manifest: {exc}"]
    embedded = _embedded_c2pa_manifest(source, raw)
    if embedded is not None:
        if isinstance(embedded, dict) and embedded.get("remote_url"):
            remote_url = str(embedded["remote_url"])
            if remote_loader is None:
                return None, remote_url, ["Remote C2PA manifest was not loaded."]
            try:
                return remote_loader(remote_url), remote_url, []
            except Exception as exc:
                return None, remote_url, [f"Remote C2PA manifest load failed: {exc}"]
        return embedded, "embedded", []
    return None, "", []


def _provenance_for_file(
    source: Path,
    raw: bytes,
    validator: Any,
    remote_loader: Any = None,
) -> tuple[ProvenanceRecord, list[DetectionFinding]]:
    if source.suffix.lower() not in _C2PA_EXTENSIONS:
        return ProvenanceRecord(status="UNSUPPORTED"), []

    if validator is not None and (
        hasattr(validator, "validate_content") or hasattr(validator, "validate_file")
    ):
        manifest, location, location_errors = _locate_c2pa_manifest(source, raw, remote_loader)
        manifest_location = location if manifest is not None or location_errors else "embedded"
        try:
            if hasattr(validator, "validate_content"):
                validated = validator.validate_content(source, raw, manifest_location)
            else:
                validated = validator.validate_file(source, manifest_location)
        except Exception as exc:
            validated = {
                "status": "NOT_CHECKED",
                "validation_errors": [f"C2PA validator failed: {exc}"],
            }
        record = ProvenanceRecord(
            status=validated.get("status", "NOT_CHECKED"),
            provider=validated.get("provider", ""),
            claim_generator=validated.get("claim_generator", ""),
            signer_identity=validated.get("signer_identity", ""),
            certificate_trust=validated.get("certificate_trust", "unknown"),
            digital_source_type=validated.get("digital_source_type", ""),
            timestamps=list(validated.get("timestamps", [])),
            manifest_location=(
                "" if validated.get("status") == "MISSING" else location or manifest_location
            ),
            validation_errors=list(validated.get("validation_errors", [])),
            actions=list(validated.get("actions", [])),
            ingredients=list(validated.get("ingredients", [])),
        )
        return record, _provenance_findings(record)

    manifest, location, location_errors = _locate_c2pa_manifest(source, raw, remote_loader)
    if location_errors:
        remote_error = any(error.startswith("Remote C2PA") for error in location_errors)
        record = ProvenanceRecord(
            status="NOT_CHECKED" if remote_error else "TAMPERED",
            manifest_location=location,
            validation_errors=location_errors,
        )
    elif manifest is None:
        return ProvenanceRecord(status="MISSING"), []
    elif validator is None:
        provider = manifest.get("provider", "") if isinstance(manifest, dict) else ""
        record = ProvenanceRecord(
            status="NOT_CHECKED",
            provider=str(provider),
            manifest_location=location,
            validation_errors=["No cryptographic C2PA validator was configured."],
        )
    else:
        try:
            validated = validator(manifest, raw, location)
            if not isinstance(validated, dict):
                raise TypeError("validator must return a dictionary")
            record = ProvenanceRecord(
                status=validated.get("status", "NOT_CHECKED"),
                provider=validated.get("provider", ""),
                claim_generator=validated.get("claim_generator", ""),
                signer_identity=validated.get("signer_identity", ""),
                certificate_trust=validated.get("certificate_trust", "unknown"),
                digital_source_type=validated.get("digital_source_type", ""),
                timestamps=list(validated.get("timestamps", [])),
                manifest_location=location,
                validation_errors=list(validated.get("validation_errors", [])),
                actions=list(validated.get("actions", [])),
                ingredients=list(validated.get("ingredients", [])),
            )
        except Exception as exc:
            record = ProvenanceRecord(
                status="NOT_CHECKED",
                manifest_location=location,
                validation_errors=[f"C2PA validator failed: {exc}"],
            )

    return record, _provenance_findings(record)


def _provenance_findings(record: ProvenanceRecord) -> list[DetectionFinding]:
    if record.status in {"MISSING", "UNSUPPORTED"}:
        return []
    if record.status == "VALID":
        claude = (
            record.provider.lower() == "anthropic" or "claude" in record.claim_generator.lower()
        )
        description = (
            "Valid provenance indicates this asset was processed by Claude."
            if claude
            else "The file carries valid informational provenance."
        )
        risk = "informational"
        confidence = 1.0
    elif record.status in {"TAMPERED", "UNTRUSTED_SIGNER"}:
        description = "Provenance is tampered, malformed, or signed by an untrusted identity."
        risk = "high"
        confidence = 0.95
    else:
        description = (
            "A provenance manifest was found but has not been cryptographically validated."
        )
        risk = "medium"
        confidence = 0.7
    findings = [
        _finding(
            "C2PA_PROVENANCE",
            "c2pa_validation",
            description,
            confidence,
            location=record.manifest_location,
            evidence={"status": record.status},
            risk=risk,
        ),
        _finding(
            "PROVENANCE",
            "content_credentials",
            description,
            confidence,
            location=record.manifest_location,
            evidence={"status": record.status},
            risk=risk,
        ),
    ]
    return findings


def _verify_ai_text(
    verifier: Any,
    text: str,
    source: Path,
) -> tuple[dict[str, Any], list[DetectionFinding]]:
    if verifier is None:
        return {
            "status": "NOT_CHECKED",
            "provider": "",
            "confidence": 0.0,
            "evidence": {},
            "errors": ["No official AI text-watermark verifier was configured."],
        }, []
    try:
        if hasattr(verifier, "verify"):
            result = verifier.verify(text, path=str(source))
        else:
            result = verifier(text, path=str(source))
        if not isinstance(result, dict):
            raise TypeError("verifier must return a dictionary")
        confidence = float(result.get("confidence", 0.0))
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("verifier confidence must be between 0 and 1")
        detected = bool(result.get("detected", False))
        normalized: dict[str, Any] = {
            "status": "DETECTED" if detected else "NOT_DETECTED",
            "provider": str(result.get("provider", "")),
            "confidence": confidence,
            "evidence": dict(result.get("evidence", {})),
            "errors": [],
        }
        json.dumps(normalized)
        if not detected:
            return normalized, []
        normalized_evidence = normalized["evidence"]
        if not isinstance(normalized_evidence, dict):
            raise TypeError("verifier evidence must be a dictionary")
        finding = _finding(
            "AI_TEXT_WATERMARK",
            "pluggable_ai_text_verifier",
            "The configured verifier detected an AI text-watermark signal.",
            confidence,
            evidence={
                "provider": normalized["provider"],
                **normalized_evidence,
            },
        )
        return normalized, [finding]
    except Exception as exc:
        return {
            "status": "ERROR",
            "provider": "",
            "confidence": 0.0,
            "evidence": {},
            "errors": [str(exc)],
        }, []


def _scan_content(
    source: Path,
    raw: bytes,
    ai_text_verifier: Any,
    provenance_validator: Any,
    remote_manifest_loader: Any,
    media_analyzers: dict[str, Any] | None,
) -> dict[str, Any]:
    from stegguard.robust import analyze_media

    provenance, provenance_findings = _provenance_for_file(
        source,
        raw,
        provenance_validator,
        remote_manifest_loader,
    )
    findings = (
        _scan_png(raw)
        + _scan_pdf(raw)
        + _scan_structural(source, raw)
        + _scan_format_metadata(source, raw)
        + _scan_media_signals(source, raw)
        + provenance_findings
    )
    robust_media = analyze_media(source, raw, media_analyzers)
    for category, analysis in robust_media.items():
        if analysis.get("status") != "DETECTED":
            continue
        detected_families = analysis.get("detected_families") or analysis.get("families", [])
        findings.append(
            _finding(
                category,
                "robust_media_analyzer",
                "A robust-media analyzer detected watermark-related signal evidence.",
                float(analysis.get("confidence", 0.0)),
                evidence={
                    "signal_families": detected_families,
                    "metrics": analysis.get("metrics", {}),
                },
                risk="medium",
            )
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text:
        findings.extend(_scan_text(text))
    ai_text_watermark, ai_findings = _verify_ai_text(ai_text_verifier, text, source)
    findings.extend(ai_findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "file": str(source),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "findings": [finding.to_dict() for finding in findings],
        "provenance": provenance.to_dict(),
        "ai_text_watermark": ai_text_watermark,
        "robust_media": robust_media,
        "nested_results": [],
    }


_NESTED_MEDIA_EXTENSIONS = {
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".zip",
    ".docx",
    ".pptx",
    ".xlsx",
    ".pdf",
    ".html",
    ".htm",
}
_ZIP_CONTAINER_EXTENSIONS = {".zip", ".docx", ".pptx", ".xlsx"}
_MAX_NESTED_MEMBERS = 500
_MAX_NESTED_MEMBER_BYTES = 10 * 1024 * 1024
_MAX_NESTED_TOTAL_BYTES = 50 * 1024 * 1024


def _extract_media_signatures(raw: bytes) -> list[tuple[str, bytes]]:
    extracted: list[tuple[str, bytes]] = []
    position = 0
    while True:
        start = raw.find(b"\x89PNG\r\n\x1a\n", position)
        if start < 0:
            break
        cursor = start + 8
        end = 0
        while cursor + 12 <= len(raw):
            length = struct.unpack_from(">I", raw, cursor)[0]
            chunk_end = cursor + length + 12
            if chunk_end > len(raw):
                break
            if raw[cursor + 4 : cursor + 8] == b"IEND":
                end = chunk_end
                break
            cursor = chunk_end
        if not end:
            break
        extracted.append(("png", raw[start:end]))
        position = end

    position = 0
    while True:
        start = raw.find(b"\xff\xd8", position)
        if start < 0:
            break
        end_marker = raw.find(b"\xff\xd9", start + 2)
        if end_marker < 0:
            break
        end = end_marker + 2
        extracted.append(("jpg", raw[start:end]))
        position = end

    for match in re.finditer(rb"<svg\b.*?</svg\s*>", raw, re.I | re.S):
        extracted.append(("svg", match.group(0)))
    return extracted


def _scan_nested(
    source: Path,
    raw: bytes,
    ai_text_verifier: Any,
    provenance_validator: Any,
    remote_manifest_loader: Any,
    media_analyzers: dict[str, Any] | None,
    limits: ScanLimits,
    deadline: float,
    depth: int = 0,
) -> tuple[list[dict[str, Any]], list[str]]:
    nested: list[dict[str, Any]] = []
    errors: list[str] = []
    candidates: list[tuple[str, bytes]] = []
    suffix = source.suffix.lower()
    if depth >= limits.max_nesting_depth:
        return [], ["Nested depth limit reached."]
    check_deadline(deadline)

    if suffix in _ZIP_CONTAINER_EXTENSIONS:
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                total_bytes = 0
                for index, member in enumerate(archive.infolist()):
                    check_deadline(deadline)
                    if index >= limits.max_archive_members:
                        errors.append("Nested member limit reached.")
                        break
                    member_suffix = Path(member.filename).suffix.lower()
                    if member.is_dir() or member_suffix not in _NESTED_MEDIA_EXTENSIONS:
                        continue
                    member_limit = min(
                        _MAX_NESTED_MEMBER_BYTES,
                        limits.max_decompressed_bytes,
                    )
                    if member.file_size > member_limit:
                        errors.append(f"Skipped oversized member: {member.filename}")
                        continue
                    total_bytes += member.file_size
                    if total_bytes > limits.max_decompressed_bytes:
                        errors.append("Nested decompressed-size limit reached.")
                        break
                    try:
                        with archive.open(member) as member_stream:
                            content = read_stream_limited(
                                member_stream,
                                member_limit,
                                "max_decompressed_bytes",
                            )
                    except ResourceLimitError:
                        errors.append(f"Skipped oversized member: {member.filename}")
                        continue
                    candidates.append((member.filename, content))
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            errors.append(f"Container scan failed: {exc}")
    elif suffix == ".pdf":
        candidates.extend(
            (f"embedded-{index}.{extension}", content)
            for index, (extension, content) in enumerate(_extract_media_signatures(raw), 1)
        )
    elif suffix in {".html", ".htm"}:
        pattern = re.compile(
            rb"data:image/(png|jpeg|svg\+xml);base64,([A-Za-z0-9+/=\r\n]+)",
            re.I,
        )
        for index, match in enumerate(pattern.finditer(raw), 1):
            extension = match.group(1).lower().replace(b"jpeg", b"jpg").replace(b"svg+xml", b"svg")
            try:
                encoded = re.sub(rb"\s+", b"", match.group(2))
                content = base64.b64decode(encoded, validate=True)
            except ValueError:
                errors.append(f"Invalid base64 data URI at item {index}.")
                continue
            if len(content) <= min(_MAX_NESTED_MEMBER_BYTES, limits.max_decompressed_bytes):
                candidates.append((f"data-uri-{index}.{extension.decode()}", content))

    for member_name, content in candidates:
        check_deadline(deadline)
        member_result = _scan_content(
            Path(member_name),
            content,
            ai_text_verifier,
            provenance_validator,
            remote_manifest_loader,
            media_analyzers,
        )
        if len(member_result["findings"]) > limits.max_findings:
            member_result["findings"] = member_result["findings"][: limits.max_findings]
            member_result.setdefault("scan_errors", []).append("Finding limit reached.")
        nested_results, nested_errors = _scan_nested(
            Path(member_name),
            content,
            ai_text_verifier,
            provenance_validator,
            remote_manifest_loader,
            media_analyzers,
            limits,
            deadline,
            depth + 1,
        )
        member_result["nested_results"] = nested_results
        member_result["nested_scan_errors"] = nested_errors
        nested.append(
            {
                "container": str(source),
                "path": member_name,
                "result": member_result,
            }
        )
    return nested, errors


def scan_file(
    path: str,
    *,
    ai_text_verifier: Any = None,
    provenance_validator: Any = None,
    remote_manifest_loader: Any = None,
    media_analyzers: dict[str, Any] | None = None,
    limits: ScanLimits | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan a file for categorized watermark and provenance signals."""
    policy = resolve_limits(limits)
    deadline = deadline_for(policy)
    source = Path(path)
    raw = read_limited(source, policy)
    check_deadline(deadline)
    result = _scan_content(
        source,
        raw,
        ai_text_verifier,
        provenance_validator,
        remote_manifest_loader,
        media_analyzers,
    )
    result["scan_errors"] = []
    if len(result["findings"]) > policy.max_findings:
        result["findings"] = result["findings"][: policy.max_findings]
        result["scan_errors"].append("Finding limit reached.")
    result["nested_results"], result["nested_scan_errors"] = _scan_nested(
        source,
        raw,
        ai_text_verifier,
        provenance_validator,
        remote_manifest_loader,
        media_analyzers,
        policy,
        deadline,
    )
    check_deadline(deadline)
    return result
