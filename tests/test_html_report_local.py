# SPDX-License-Identifier: Apache-2.0
"""The HTML report must open fully offline and render in light and dark mode."""

import json
import re

from stegguard import detector


def _report(tmp_path, files: dict[str, str]) -> str:
    results = []
    for name, content in files.items():
        source = tmp_path / name
        source.write_text(content, encoding="utf-8")
        results.append(detector.analyze_file(source))
    out = tmp_path / "report.html"
    detector.generate_html_report(results, str(out))
    return out.read_text(encoding="utf-8")


def _css(html: str) -> str:
    return re.search(r"<style>(.*?)</style>", html, re.S).group(1)


def _without_style(html: str) -> str:
    return re.sub(r"<style>.*?</style>", "", html, flags=re.S)


def test_report_loads_no_external_resources(tmp_path):
    html = _report(tmp_path, {"a.py": "x = 1\u200b\n"})

    assert re.findall(r"<(?:link|img|iframe|script)\b[^>]*\b(?:src|href)\s*=", html) == []
    assert "@import" not in html
    assert "url(" not in html
    assert "googleapis" not in html


def test_report_title_and_header_use_the_stegguard_name(tmp_path):
    html = _report(tmp_path, {"a.py": "x = 1\n"})

    assert re.search(r"<title>StegGuard report · \d{4}-\d\d-\d\d \d\d:\d\d:\d\d</title>", html)
    assert "<h1>StegGuard report</h1>" in html
    assert "steg detector" not in html.lower()


def test_report_defines_a_dark_palette_for_every_color_token(tmp_path):
    css = _css(_report(tmp_path, {"a.py": "x = 1\n"}))
    light = re.search(r":root\{(.*?)\}", css, re.S).group(1)
    dark = re.search(r"@media \(prefers-color-scheme: dark\)\{:root\{(.*?)\}\}", css, re.S).group(1)

    def names(block):
        return set(re.findall(r"(--[a-z0-9-]+):\s*#", block))

    assert names(light) == names(dark)
    assert {"--critical", "--high", "--medium", "--low", "--clean"} <= names(light)


def test_every_css_variable_used_in_the_report_is_defined(tmp_path):
    html = _report(
        tmp_path,
        {
            "zw.py": "x\u200b" * 25 + "\n",
            "bidi.py": "a\u202eb\u202c\n",
            "hg.py": "def \u0430uth(): pass\n",
            "tw.py": "line  \t\nnext \n",
            "eol.py": "a\r\nb\n",
            "clean.py": "ok\n",
        },
    )
    css = _css(html)
    defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
    used = set(re.findall(r"var\((--[a-z0-9-]+)", html))

    assert used - defined == set()


def test_report_markup_and_script_carry_no_hardcoded_hex_colors(tmp_path):
    html = _report(
        tmp_path,
        {
            "zw.py": "x\u200b" * 25 + "\n",
            "bidi.py": "a\u202eb\u202c\n",
            "tw.py": "line  \t\n",
            "clean.py": "ok\n",
        },
    )
    body = _without_style(html)

    assert re.findall(r"[:'\"]\s*#[0-9a-fA-F]{6}\b", body) == []


def test_severity_html_returns_theme_tokens_not_fixed_colors():
    assert detector.severity_html(0, [], False) == ("clean", "CLEAN", "var(--clean)")
    assert detector.severity_html(1, [], False) == ("low", "LOW", "var(--low)")
    assert detector.severity_html(2, [], False) == ("medium", "MEDIUM", "var(--medium)")
    assert detector.severity_html(8, [], False) == ("high", "HIGH", "var(--high)")
    assert detector.severity_html(20, [], False) == ("critical", "CRITICAL", "var(--critical)")


def _report_for_path(tmp_path, fake_path: str) -> str:
    source = tmp_path / "a.py"
    source.write_text("x\u200b\n", encoding="utf-8")
    result = detector.analyze_file(source)
    result["file"] = fake_path
    out = tmp_path / "report.html"
    detector.generate_html_report([result], str(out))
    return out.read_text(encoding="utf-8")


def test_file_names_are_escaped_in_cards_and_navigation(tmp_path):
    html = _report_for_path(tmp_path, "src/<i>x.py")

    assert "<i>" not in html
    # card title, card path and sidebar entry
    assert html.count("&lt;i&gt;x.py") == 3


def test_file_names_cannot_close_the_embedded_json_script(tmp_path):
    html = _report_for_path(tmp_path, "src/a</script>.py")
    data = re.search(r'<script id="file-data" type="application/json">(.*?)</script>', html, re.S)

    assert "<" not in data.group(1)
    assert json.loads(data.group(1))[0]["file"] == "src/a</script>.py"


def test_copy_buttons_use_a_text_label_that_every_font_can_render(tmp_path):
    html = _report(tmp_path, {"a.py": "x​\n"})

    assert "&#x2398;" not in html
    assert 'title="Copy path">Copy</button>' in html


def test_report_tables_do_not_inherit_break_anywhere_wrapping(tmp_path):
    css = _css(_report(tmp_path, {"a.py": "x\n"}))

    assert re.search(r"\.tbl\{[^}]*overflow-wrap:normal", css)
    assert re.search(r"\.fsum-table\{[^}]*overflow-wrap:normal", css)


def test_report_tables_size_to_content_and_scroll_on_small_screens(tmp_path):
    css = _css(_report(tmp_path, {"a.py": "x\n"}))
    small = re.search(r"@media \(max-width:600px\)\{(.*?)\}\}", css, re.S).group(1)

    assert ".tbl{width:max-content;min-width:100%" in small
    assert re.search(r"\.fb\{[^}]*overflow-x:auto", css)
