# SPDX-License-Identifier: Apache-2.0
import math
import struct
import wave

from stegguard.watermark import scan_file


def _checkerboard_bmp(width=32, height=32):
    row_size = (width * 3 + 3) & ~3
    pixels = bytearray()
    for y in range(height):
        row = bytearray()
        for x in range(width):
            value = 128 + (24 if (x + y) % 2 else -24)
            row.extend((value, value, value))
        row.extend(b"\x00" * (row_size - width * 3))
        pixels.extend(row)
    offset = 54
    size = offset + len(pixels)
    return (
        b"BM"
        + struct.pack("<IHHI", size, 0, 0, offset)
        + struct.pack("<IIIHHIIIIII", 40, width, height, 1, 24, 0, len(pixels), 0, 0, 0, 0)
        + bytes(pixels)
    )


def _write_segmented_wav(path):
    sample_rate = 8_000
    samples = []
    segment_size = 400
    for segment in range(12):
        for index in range(segment_size):
            if segment % 2:
                value = 0
            else:
                value = int(12_000 * math.sin(2 * math.pi * 440 * index / sample_rate))
            samples.append(value)
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(sample_rate)
        output.writeframes(struct.pack(f"<{len(samples)}h", *samples))


def test_builtin_wav_analysis_covers_phase_echo_spectral_and_silence_families(tmp_path):
    path = tmp_path / "segmented.wav"
    _write_segmented_wav(path)

    result = scan_file(str(path))

    analysis = result["robust_media"]["AUDIO_ROBUST"]
    assert analysis["status"] == "DETECTED"
    assert {
        "phase",
        "echo",
        "spread_spectrum",
        "spectral",
        "silence_interval",
    } <= set(analysis["metrics"])
    finding = next(item for item in result["findings"] if item["category"] == "AUDIO_ROBUST")
    assert "silence_interval" in finding["evidence"]["signal_families"]


def test_image_analyzer_can_report_transform_and_correlation_evidence(tmp_path):
    path = tmp_path / "image.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n")

    def analyzer(source, content):
        return {
            "status": "DETECTED",
            "confidence": 0.88,
            "families": ["transform_domain", "correlation"],
            "metrics": {"dct_peak": 0.91, "template_correlation": 0.84},
        }

    result = scan_file(str(path), media_analyzers={"IMAGE_ROBUST": analyzer})

    analysis = result["robust_media"]["IMAGE_ROBUST"]
    assert analysis["status"] == "DETECTED"
    assert analysis["metrics"]["dct_peak"] == 0.91
    assert any(
        finding["category"] == "IMAGE_ROBUST" and finding["confidence"] == 0.88
        for finding in result["findings"]
    )


def test_builtin_image_analysis_uses_full_pixel_transform_not_lsb(tmp_path):
    path = tmp_path / "pattern.bmp"
    path.write_bytes(_checkerboard_bmp())

    result = scan_file(str(path))

    analysis = result["robust_media"]["IMAGE_ROBUST"]
    assert analysis["status"] == "DETECTED"
    assert analysis["metrics"]["transform_domain"]["checkerboard_energy"] > 0.1
    assert analysis["metrics"]["correlation"]["block_sign_agreement"] > 0.9
    assert "LSB" not in analysis["families"]


def test_video_analyzer_covers_frame_motion_chroma_and_audio_track(tmp_path):
    path = tmp_path / "video.mp4"
    path.write_bytes(b"\x00\x00\x00\x18ftypisom")

    result = scan_file(
        str(path),
        media_analyzers={
            "VIDEO_ROBUST": lambda source, content: {
                "status": "NOT_DETECTED",
                "confidence": 0.2,
                "families": ["frame", "motion_vector", "chroma", "audio_track"],
                "metrics": {"frames_analyzed": 120},
            }
        },
    )

    analysis = result["robust_media"]["VIDEO_ROBUST"]
    assert analysis["status"] == "NOT_DETECTED"
    assert analysis["families"] == ["frame", "motion_vector", "chroma", "audio_track"]


def test_codec_media_without_analyzer_is_explicitly_not_checked(tmp_path):
    path = tmp_path / "video.mp4"
    path.write_bytes(b"\x00\x00\x00\x18ftypisom")

    result = scan_file(str(path))

    assert result["robust_media"]["VIDEO_ROBUST"]["status"] == "NOT_CHECKED"
    assert result["robust_media"]["VIDEO_ROBUST"]["errors"]


def test_broken_media_analyzer_surfaces_error_without_finding(tmp_path):
    path = tmp_path / "video.mp4"
    path.write_bytes(b"\x00\x00\x00\x18ftypisom")

    def broken(source, content):
        raise RuntimeError("decoder exploded")

    result = scan_file(str(path), media_analyzers={"VIDEO_ROBUST": broken})

    assert result["robust_media"]["VIDEO_ROBUST"]["status"] == "ERROR"
    assert "decoder exploded" in result["robust_media"]["VIDEO_ROBUST"]["errors"]
