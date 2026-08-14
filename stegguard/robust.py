# SPDX-License-Identifier: Apache-2.0
"""Robust-media analyzer contracts and dependency-free WAV analysis."""

from __future__ import annotations

import io
import json
import math
import struct
import wave
from pathlib import Path
from typing import Any, Callable


ROBUST_FAMILIES = {
    "IMAGE_ROBUST": ["transform_domain", "correlation"],
    "AUDIO_ROBUST": ["phase", "echo", "spread_spectrum", "spectral", "silence_interval"],
    "VIDEO_ROBUST": ["frame", "motion_vector", "chroma", "audio_track"],
}

_CATEGORY_EXTENSIONS = {
    "IMAGE_ROBUST": {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"},
    "AUDIO_ROBUST": {".wav", ".mp3", ".flac", ".ogg", ".aac", ".m4a", ".opus", ".aiff"},
    "VIDEO_ROBUST": {".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v", ".mpeg", ".mpg"},
}


def _base_result(status: str, category: str) -> dict[str, Any]:
    return {
        "status": status,
        "confidence": 0.0,
        "families": list(ROBUST_FAMILIES[category]),
        "metrics": {},
        "errors": [],
    }


def _pcm16_mono(raw: bytes) -> tuple[list[float], int] | None:
    try:
        with wave.open(io.BytesIO(raw), "rb") as source:
            if source.getsampwidth() != 2 or source.getcomptype() != "NONE":
                return None
            channels = source.getnchannels()
            rate = source.getframerate()
            frame_count = min(source.getnframes(), rate * 10)
            frames = source.readframes(frame_count)
    except (EOFError, wave.Error):
        return None
    values = struct.unpack(f"<{len(frames) // 2}h", frames)
    if channels == 1:
        mono = list(values)
    else:
        mono = [
            sum(values[index : index + channels]) / channels
            for index in range(0, len(values), channels)
        ]
    peak = max((abs(value) for value in mono), default=1.0) or 1.0
    return [value / peak for value in mono], rate


def _normalized_autocorrelation(samples: list[float], lag: int) -> float:
    if lag <= 0 or lag >= len(samples):
        return 0.0
    left = samples[:-lag]
    right = samples[lag:]
    numerator = sum(a * b for a, b in zip(left, right))
    denominator = math.sqrt(
        sum(value * value for value in left) * sum(value * value for value in right)
    )
    return numerator / denominator if denominator else 0.0


def _spectral_flatness(samples: list[float], rate: int) -> float:
    if len(samples) < 64:
        return 0.0
    window = samples[: min(len(samples), 4096)]
    powers: list[float] = []
    for frequency in range(125, min(rate // 2, 4_000), 125):
        omega = 2.0 * math.pi * frequency / rate
        cosine = sum(value * math.cos(omega * index) for index, value in enumerate(window))
        sine = sum(value * math.sin(omega * index) for index, value in enumerate(window))
        powers.append(cosine * cosine + sine * sine + 1e-15)
    if not powers:
        return 0.0
    geometric = math.exp(sum(math.log(value) for value in powers) / len(powers))
    arithmetic = sum(powers) / len(powers)
    return geometric / arithmetic if arithmetic else 0.0


def _silence_intervals(samples: list[float], rate: int) -> tuple[int, float]:
    window = max(1, rate // 20)
    silent: list[bool] = []
    for start in range(0, len(samples) - window + 1, window):
        block = samples[start : start + window]
        rms = math.sqrt(sum(value * value for value in block) / len(block))
        silent.append(rms < 0.01)
    intervals = 0
    lengths: list[int] = []
    current = 0
    for is_silent in silent + [False]:
        if is_silent:
            current += 1
        elif current:
            intervals += 1
            lengths.append(current)
            current = 0
    regularity = 0.0
    if len(lengths) >= 2:
        mean = sum(lengths) / len(lengths)
        variance = sum((value - mean) ** 2 for value in lengths) / len(lengths)
        regularity = 1.0 / (1.0 + math.sqrt(variance) / max(mean, 1e-9))
    return intervals, regularity


def analyze_wav(source: Path, raw: bytes) -> dict[str, Any]:
    """Analyze PCM WAV audio for phase, echo, spectral, and silence signals."""
    decoded = _pcm16_mono(raw)
    if decoded is None:
        result = _base_result("NOT_CHECKED", "AUDIO_ROBUST")
        result["errors"] = ["Built-in audio analysis supports uncompressed 16-bit PCM WAV only."]
        return result
    samples, rate = decoded
    if len(samples) < max(64, rate // 10):
        result = _base_result("NOT_CHECKED", "AUDIO_ROBUST")
        result["errors"] = ["Audio is too short for robust-watermark statistics."]
        return result

    discontinuities = [abs(samples[index] - samples[index - 1]) for index in range(1, len(samples))]
    phase_score = sum(value > 1.25 for value in discontinuities) / len(discontinuities)
    echo_stride = max(1, math.ceil(len(samples) / 50_000))
    echo_samples = samples[::echo_stride]
    echo_rate = max(1, rate // echo_stride)
    candidate_lags = range(
        max(8, echo_rate // 1000),
        min(echo_rate // 10, len(echo_samples) // 4),
        max(1, echo_rate // 1000),
    )
    echo_score = max(
        (abs(_normalized_autocorrelation(echo_samples, lag)) for lag in candidate_lags),
        default=0.0,
    )
    flatness = _spectral_flatness(samples, rate)
    silence_count, silence_regularity = _silence_intervals(samples, rate)

    detected: list[str] = []
    if phase_score > 0.02:
        detected.append("phase")
    if echo_score > 0.92:
        detected.append("echo")
    if flatness > 0.75:
        detected.extend(["spread_spectrum", "spectral"])
    if silence_count >= 3 and silence_regularity > 0.8:
        detected.append("silence_interval")
    confidence = min(
        0.95,
        max(
            phase_score * 8,
            echo_score - 0.5,
            flatness,
            silence_regularity if silence_count >= 3 else 0.0,
        ),
    )
    return {
        "status": "DETECTED" if detected else "NOT_DETECTED",
        "confidence": round(confidence, 4),
        "families": list(ROBUST_FAMILIES["AUDIO_ROBUST"]),
        "detected_families": sorted(set(detected)),
        "metrics": {
            "phase": {"discontinuity_ratio": round(phase_score, 6)},
            "echo": {"max_autocorrelation": round(echo_score, 6)},
            "spread_spectrum": {"spectral_flatness": round(flatness, 6)},
            "spectral": {"spectral_flatness": round(flatness, 6)},
            "silence_interval": {
                "count": silence_count,
                "regularity": round(silence_regularity, 6),
            },
        },
        "errors": [],
    }


def analyze_image(source: Path, raw: bytes) -> dict[str, Any]:
    """Measure repeated high-frequency block energy and block correlation."""
    from stegguard.detector import (
        _load_image_pixels,
        _load_pixels_bmp,
        _load_pixels_gif,
        _load_pixels_png,
        _load_pixels_tiff,
    )

    raw_loaders = {
        ".bmp": _load_pixels_bmp,
        ".gif": _load_pixels_gif,
        ".png": _load_pixels_png,
        ".tif": _load_pixels_tiff,
        ".tiff": _load_pixels_tiff,
    }
    raw_loader = raw_loaders.get(source.suffix.lower())
    loaded = raw_loader(raw) if raw_loader else _load_image_pixels(source)
    if loaded is None:
        result = _base_result("NOT_CHECKED", "IMAGE_ROBUST")
        result["errors"] = ["Pixel data could not be decoded by the built-in image loader."]
        return result
    channels, width, height, mode, palette, image_format = loaded
    channel = next(iter(channels.values()), b"")
    if width < 16 or height < 16 or len(channel) < width * height:
        result = _base_result("NOT_CHECKED", "IMAGE_ROBUST")
        result["errors"] = ["Image is too small for block transform analysis."]
        return result

    coefficients: list[float] = []
    for top in range(0, height - 7, 8):
        for left in range(0, width - 7, 8):
            block = [channel[(top + y) * width + left + x] for y in range(8) for x in range(8)]
            mean = sum(block) / len(block)
            centered = [value - mean for value in block]
            scale = sum(abs(value) for value in centered)
            if scale <= 1e-9:
                coefficients.append(0.0)
                continue
            checker = sum(
                value * (1 if (index // 8 + index % 8) % 2 else -1)
                for index, value in enumerate(centered)
            )
            coefficients.append(checker / scale)
    nonzero = [value for value in coefficients if abs(value) > 0.02]
    energy = sum(abs(value) for value in coefficients) / len(coefficients)
    sign_agreement = 0.0
    if nonzero:
        positive = sum(value > 0 for value in nonzero)
        sign_agreement = max(positive, len(nonzero) - positive) / len(nonzero)
    detected = len(nonzero) >= 4 and energy > 0.25 and sign_agreement > 0.9
    confidence = min(0.95, energy * sign_agreement) if detected else min(0.5, energy)
    return {
        "status": "DETECTED" if detected else "NOT_DETECTED",
        "confidence": round(confidence, 4),
        "families": list(ROBUST_FAMILIES["IMAGE_ROBUST"]),
        "detected_families": ["transform_domain", "correlation"] if detected else [],
        "metrics": {
            "transform_domain": {
                "basis": "8x8 checkerboard high-frequency projection",
                "checkerboard_energy": round(energy, 6),
                "blocks": len(coefficients),
            },
            "correlation": {
                "block_sign_agreement": round(sign_agreement, 6),
                "correlated_blocks": len(nonzero),
            },
            "pixel_scope": "full_8bit_values_not_lsb",
            "format": image_format,
            "mode": mode,
        },
        "errors": [],
    }


def _normalize_result(category: str, result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise TypeError("media analyzer must return a dictionary")
    status = str(result.get("status", "NOT_CHECKED"))
    if status not in {"DETECTED", "NOT_DETECTED", "NOT_CHECKED", "ERROR"}:
        raise ValueError(f"invalid media analysis status: {status}")
    confidence = float(result.get("confidence", 0.0))
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("media analyzer confidence must be between 0 and 1")
    families = result.get("families") or ROBUST_FAMILIES[category]
    detected_families = result.get("detected_families") or result.get("families") or []
    normalized = {
        "status": status,
        "confidence": confidence,
        "families": list(families),
        "detected_families": list(detected_families if status == "DETECTED" else []),
        "metrics": dict(result.get("metrics", {})),
        "errors": list(result.get("errors", [])),
    }
    json.dumps(normalized)
    return normalized


def analyze_media(
    source: Path,
    raw: bytes,
    analyzers: dict[str, Callable[[Path, bytes], dict[str, Any]]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Run the applicable robust-media analyzer and return explicit status."""
    analyzers = analyzers or {}
    suffix = source.suffix.lower()
    output: dict[str, dict[str, Any]] = {}
    for category, extensions in _CATEGORY_EXTENSIONS.items():
        if suffix not in extensions:
            continue
        analyzer = analyzers.get(category)
        if (
            analyzer is None
            and category == "IMAGE_ROBUST"
            and suffix in {".png", ".bmp", ".gif", ".tif", ".tiff"}
        ):
            analyzer = analyze_image
        if analyzer is None and category == "AUDIO_ROBUST" and suffix == ".wav":
            analyzer = analyze_wav
        if analyzer is None:
            result = _base_result("NOT_CHECKED", category)
            result["errors"] = [
                f"No {category} analyzer is configured for {suffix or 'this format'}. "
            ]
            output[category] = result
            continue
        try:
            output[category] = _normalize_result(category, analyzer(source, raw))
        except Exception as exc:
            result = _base_result("ERROR", category)
            result["errors"] = [str(exc)]
            output[category] = result
    return output
