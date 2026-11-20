import codecs
import contextlib
import io
import json
import math
import os
import random
import sqlite3
import subprocess
import sys
import wave
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from stegguard.detector import analyze_file, generate_html_report, main, result_is_flagged


def _write_document_headers(archive, suffix):
    if suffix in {"docx", "pptx", "xlsx"}:
        archive.writestr("[Content_Types].xml", "<Types/>")
    if suffix == "pptx":
        archive.writestr("ppt/presentation.xml", "<presentation/>")
    elif suffix == "xlsx":
        archive.writestr("xl/workbook.xml", "<workbook/>")
    elif suffix == "epub":
        archive.writestr("mimetype", "application/epub+zip")
    elif suffix == "odt":
        archive.writestr("mimetype", "application/vnd.oasis.opendocument.text")


class DetectionChecklistTests(unittest.TestCase):
    def test_default_recursive_scan_matches_explicit_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir()
            nested = data / ".nested"
            nested.mkdir()
            paths = [data / "note.txt", data / ".hidden", nested / "README"]
            for path in paths:
                path.write_text("ordinary text", encoding="utf-8")

            inventories = []
            for inputs in [[str(data)], list(map(str, paths))]:
                report = root / "results.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["-r", "--json", str(report), *inputs]), 0)
                payload = json.loads(report.read_text(encoding="utf-8"))
                inventories.append({item["file"] for item in payload["results"]})
            self.assertEqual(inventories[0], inventories[1])

    def test_utf16_marker_reports_original_byte_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "note.txt"
            prefix = "Hello 😀\r\nworld"
            for encoding, bom in [
                ("utf-8", b""),
                ("utf-16-le", codecs.BOM_UTF16_LE),
                ("utf-16-be", codecs.BOM_UTF16_BE),
            ]:
                with self.subTest(encoding=encoding):
                    path.write_bytes(bom + (prefix + "\u200b!").encode(encoding))
                    findings = analyze_file(path)["zero_width"]
                    self.assertEqual(
                        [(hit.char, hit.line, hit.col, hit.byte_off) for hit in findings],
                        [("\u200b", 2, 6, len(bom) + len(prefix.encode(encoding)))],
                    )

    def test_empty_mp4_padding_is_informational(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "video.mp4"
            ftyp = struct.pack(">I4s4sI4s", 20, b"ftyp", b"isom", 0, b"isom")
            path.write_bytes(ftyp + struct.pack(">I4s", 8, b"free"))
            result = analyze_file(path)
            findings = result["watermark"]["findings"]
            self.assertEqual(
                [item["risk"] for item in findings if item["detector"] == "bmff_private_box"],
                ["informational"],
            )
            self.assertFalse(result_is_flagged(result))

    def test_html_summary_counts_matches_and_analyzer_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            note = root / "note.txt"
            note.write_text("one\u200bmatch", encoding="utf-8")
            video = root / "video.mp4"
            video.write_bytes(struct.pack(">I4s", 8, b"free"))
            results = [analyze_file(note), analyze_file(video)]
            report = root / "report.html"
            generate_html_report(results, report)
            html = report.read_text(encoding="utf-8")
            for label in ("Flagged Files", "Character and Byte Matches", "Analyzer Findings"):
                self.assertIn(f'class="sn">1</div><div class="sl">{label}</div>', html)

    def test_layout_rules_require_markup_and_a_hidden_value(self):
        cases = [
            ("note.md", "The display: none declaration hides content.", False),
            ("note.html", '<p style="font-size: 0.875rem">Visible</p>', False),
            ("note.html", '<p style="display: none">Hidden</p>', True),
            ("note.svg", '<svg><text style="font-size:0px">Hidden</text></svg>', True),
            ("note.html", '<p title="display: none">Visible</p>', False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for name, content, hidden in cases:
                with self.subTest(content=content):
                    path = Path(directory) / name
                    path.write_text(content, encoding="utf-8")
                    result = analyze_file(path)
                    self.assertEqual(
                        any(f["category"] == "LAYOUT" for f in result["watermark"]["findings"]),
                        hidden,
                    )
                    self.assertEqual(result_is_flagged(result), hidden)

    def test_mp4_padding_with_contents_uses_payload_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "video.mp4"
            for payload, risk in [(b"\0" * 4, "informational"), (b"data", "medium")]:
                with self.subTest(payload=payload):
                    path.write_bytes(struct.pack(">I4s", 8 + len(payload), b"free") + payload)
                    result = analyze_file(path)
                    self.assertEqual(
                        [
                            f["risk"]
                            for f in result["watermark"]["findings"]
                            if f["detector"] == "bmff_private_box"
                        ],
                        [risk],
                    )

    def test_html_reports_unavailable_checks_on_clean_media(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            photo = root / "photo.jpg"
            photo.write_bytes(b"\xff\xd8\xff\xd9")
            result = analyze_file(photo)
            self.assertFalse(result_is_flagged(result))
            report = root / "report.html"
            generate_html_report([result], report)
            html = report.read_text(encoding="utf-8")
            self.assertIn('class="sn">0</div><div class="sl">Incomplete Files</div>', html)
            self.assertIn("No IMAGE_ROBUST analyzer is configured for .jpg.", html)
            self.assertIn(
                'class="sn">1</div><div class="sl">Files With Unavailable Checks</div>', html
            )

    def test_recursive_scan_reports_each_skipped_path_with_a_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "keep.txt").write_text("ordinary text", encoding="utf-8")
            filtered = root / "other.md"
            filtered.touch()
            dependency = root / ".venv" / "dependency.txt"
            dependency.parent.mkdir()
            dependency.touch()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["-r", "--no-venv", "--ext", ".txt", str(root)]), 0)
            self.assertIn(f"{filtered} (extension filter)", output.getvalue())
            self.assertIn(f"{dependency} (venv/dependency directory)", output.getvalue())

    def test_html_analyzer_total_includes_nested_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "archive.zip"
            with zipfile.ZipFile(archive, "w") as container:
                container.writestr(
                    "note.svg", '<svg><text style="display:none">Hidden</text></svg>'
                )
            result = analyze_file(archive)
            watermark = result["watermark"]
            nested = watermark["nested_results"][0]["result"]["findings"]
            self.assertTrue(nested)
            expected = len(watermark["findings"]) + len(nested)
            report = root / "report.html"
            generate_html_report([result], report)
            self.assertIn(
                f'class="sn">{expected}</div><div class="sl">Analyzer Findings</div>',
                report.read_text(encoding="utf-8"),
            )

    def test_wav_echo_distinguishes_periodic_tone_from_delayed_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "signal.wav"
            rate = 8000
            rng = random.Random(1)
            dry = [rng.randint(-5000, 5000) for _ in range(2 * rate)]
            delay = 320
            echoed = [
                sample + int(0.7 * dry[i - delay]) if i >= delay else sample
                for i, sample in enumerate(dry)
            ]
            tone = [int(10000 * math.sin(2 * math.pi * 440 * i / rate)) for i in range(2 * rate)]
            for samples, expected in [(tone, False), (echoed, True)]:
                with self.subTest(echo=expected):
                    with wave.open(str(path), "wb") as output:
                        output.setparams((1, 2, rate, 0, "NONE", "not compressed"))
                        output.writeframes(struct.pack(f"<{len(samples)}h", *samples))
                    result = analyze_file(path)
                    analysis = result["watermark"]["robust_media"]["AUDIO_ROBUST"]
                    self.assertEqual("echo" in analysis["detected_families"], expected)
                    self.assertEqual(result_is_flagged(result), expected)

    def test_unicode_findings_preserve_offsets_in_context(self):
        cases = [
            ("Καλημέρα κόσμε!", [], []),
            ("👩‍💻", [], []),
            ("👩🏽‍💻", [], []),
            ("😀‍😀", [("‍", 4)], []),
            ("pаypal", [], [("а", 1)]),
            ("a‍b", [("‍", 1)], []),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "note.txt"
            for content, joiners, lookalikes in cases:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    result = analyze_file(path)
                    self.assertEqual([(f.char, f.byte_off) for f in result["zero_width"]], joiners)
                    self.assertEqual(
                        [(f.char, f.byte_off) for f in result["homoglyphs"]], lookalikes
                    )
                    self.assertEqual(result_is_flagged(result), bool(joiners or lookalikes))

    def test_container_routing_uses_content_with_misleading_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, members in [
                (
                    "slides.txt",
                    {"[Content_Types].xml": "<Types/>", "ppt/presentation.xml": "<presentation/>"},
                ),
                (
                    "book.txt",
                    {"mimetype": "application/epub+zip", "META-INF/container.xml": "<container/>"},
                ),
            ]:
                path = root / name
                with zipfile.ZipFile(path, "w") as archive:
                    for member, content in members.items():
                        archive.writestr(member, content)
                result = analyze_file(path)
                self.assertEqual(result["file_mode"], "binary")
                self.assertTrue(
                    any(
                        f["detector"] == "archive_embedded_files"
                        for f in result["watermark"]["findings"]
                    )
                )
            path = root / "database.txt"
            with contextlib.closing(sqlite3.connect(path)) as database:
                database.execute("CREATE TABLE sample (content TEXT)")
            result = analyze_file(path)
            self.assertEqual(result["file_mode"], "binary")
            self.assertTrue(
                any(
                    f["detector"] == "unsupported_container"
                    for f in result["watermark"]["findings"]
                )
            )

    def test_document_text_findings_identify_members_and_locations(self):
        cases = [
            ("docx", "word/document.xml", "<document><p><t>{}</t></p></document>"),
            ("pptx", "ppt/notesSlides/notesSlide1.xml", "<notes><p><t>{}</t></p></notes>"),
            ("xlsx", "xl/sharedStrings.xml", "<sst><si><t>{}</t></si></sst>"),
            ("epub", "OEBPS/chapter.xhtml", "<!DOCTYPE html><html><body><p>{}</p></body></html>"),
            ("odt", "content.xml", "<document><p>{}</p></document>"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for suffix, member, template in cases:
                for marker in ("", "\u200b"):
                    with self.subTest(suffix=suffix, marked=bool(marker)):
                        path = Path(directory) / f"sample.{suffix}"
                        with zipfile.ZipFile(path, "w") as archive:
                            _write_document_headers(archive, suffix)
                            archive.writestr(member, template.format("test" + marker))
                        result = analyze_file(path)
                        nested = result["watermark"]["nested_results"]
                        hits = [
                            (n["path"], f["location"])
                            for n in nested
                            for f in n["result"]["findings"]
                            if f["detector"] == "document_text_marker"
                        ]
                        self.assertEqual(hits, [(member, "text:1:5")] if marker else [])

    def test_incidental_binary_matches_do_not_raise_severity(self):
        marker = "\u200b".encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "movie.mp4": struct.pack(">I4s", 8 + len(marker), b"mdat") + marker,
                "font.pdf": (
                    b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n"
                    + zlib.compress(marker, level=0)
                    + b"\nendstream\n%%EOF"
                ),
            }
            for name, data in files.items():
                (root / name).write_bytes(data)
            for suffix in ("docx", "odt"):
                path = root / f"styles.{suffix}"
                with zipfile.ZipFile(
                    path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=0
                ) as archive:
                    archive.writestr("styles.xml", marker)
            for path in root.iterdir():
                with self.subTest(path=path):
                    self.assertFalse(result_is_flagged(analyze_file(path)))

    def test_decoded_archive_comment_marker_names_metadata_field(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.comment = "text\u200b".encode()
            result = analyze_file(path)
            self.assertTrue(result_is_flagged(result))
            self.assertIn(
                "archive_comment",
                [
                    f["evidence"].get("field")
                    for f in result["watermark"]["findings"]
                    if f["category"] == "METADATA"
                ],
            )

    def test_cli_reports_agree_for_directory_and_explicit_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            samples = root / "samples"
            samples.mkdir()
            document = samples / "marked.docx"
            with zipfile.ZipFile(document, "w") as archive:
                _write_document_headers(archive, "docx")
                archive.writestr("word/document.xml", "<document><t>word\u200b</t></document>")
            benign = samples / ".ordinary"
            benign.write_text("Καλημέρα κόσμε!", encoding="utf-8")
            json_report = root / "report.json"
            html_report = root / "report.html"
            executable = Path(sys.executable).with_name(
                "stegguard.exe" if os.name == "nt" else "stegguard"
            )
            command = [sys.executable, "-m", "stegguard"]
            if sys.prefix != sys.base_prefix and executable.is_file():
                command = [str(executable)]
            for inputs in [["-r", str(samples)], [str(document), str(benign)]]:
                with self.subTest(inputs=inputs):
                    completed = subprocess.run(
                        [
                            *command,
                            "detect",
                            "--json",
                            str(json_report),
                            "--html",
                            str(html_report),
                            *inputs,
                        ],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 1, completed.stderr)
                    payload = json.loads(json_report.read_text(encoding="utf-8"))
                    self.assertEqual((payload["total_files"], payload["flagged_files"]), (2, 1))
                    files = {Path(r["file"]).name: r for r in payload["results"]}
                    self.assertEqual(files[".ordinary"]["severity"], "clean")
                    self.assertEqual(files["marked.docx"]["severity"], "high")
                    nested = files["marked.docx"]["watermark"]["nested_results"][0]
                    self.assertEqual(nested["path"], "word/document.xml")
                    self.assertEqual(nested["result"]["findings"][0]["location"], "text:1:5")
                    html = html_report.read_text(encoding="utf-8")
                    self.assertIn('class="sn">1</div><div class="sl">Flagged Files</div>', html)
                    self.assertIn("<td>text:1:5</td>", html)

    def test_baseline_reports_final_verdict_errors_by_format_and_family(self):
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [
                sys.executable,
                str(root / "scripts/evaluate_detection.py"),
                str(root / "tests/corpus/manifest-v2.json"),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(root)},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        results = json.loads(completed.stdout)
        self.assertIn("final_verdicts", results)
        self.assertEqual(results["final_verdicts"]["incomplete_files"], 0)
        self.assertEqual(results["final_verdicts"]["overall"]["false_positives"], 0)
        self.assertEqual(results["final_verdicts"]["overall"]["false_negatives"], 0)
        self.assertEqual(results["final_verdicts"]["formats"][".txt"]["false_negatives"], 0)
        self.assertEqual(results["final_verdicts"]["families"]["TEXT"]["false_positives"], 0)

    def test_document_extraction_respects_decompression_and_finding_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.docx"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                _write_document_headers(archive, "docx")
                archive.writestr(
                    "word/document.xml", "<document><t>" + "\u200b" * 30 + "</t></document>"
                )
            limited = analyze_file(path, limits={"max_decompressed_bytes": 64})
            self.assertFalse(limited["watermark"]["nested_results"])
            self.assertTrue(limited["watermark"]["nested_scan_errors"])
            limited = analyze_file(path, limits={"max_findings": 4})
            member = limited["watermark"]["nested_results"][0]["result"]
            self.assertEqual(len(member["findings"]), 4)
            self.assertIn("Finding limit reached.", member["scan_errors"])
