# SPDX-License-Identifier: Apache-2.0
"""Sanitization profiles: keep legitimate text by default, remove on explicit request."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from stegguard.cli import main as cli_main
from stegguard.operations import sanitize_file


FAMILY = "\U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466"
TECHNOLOGIST = "\U0001f469\U0001f3fd\u200d\U0001f4bb"
HEART_ON_FIRE = "\u2764\ufe0f\u200d\U0001f525"


def _sanitize(tmp_path: Path, content: str | bytes, name: str = "input.txt", **options) -> dict:
    source = tmp_path / name
    source.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return sanitize_file(source, tmp_path / f"output-{name}", **options)


def _output(result: dict) -> bytes:
    return Path(result["sanitized_path"]).read_bytes()


def _output_text(result: dict) -> str:
    return _output(result).decode("utf-8")


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("input.txt", "Привет, мир!\n"),
        ("input.txt", f"{FAMILY}\n"),
        ("input.txt", f"{TECHNOLOGIST} and {HEART_ON_FIRE}\n"),
        ("input.txt", "می\u200cخواهم\n"),
        ("input.txt", "क्\u200dष\n"),
        ("input.txt", "สวัสดี\u200bครับ\n"),
        ("input.txt", "שלום\u200f!\n"),
        ("input.txt", "\ufeffbyte order mark\n"),
        ("input.txt", "α + β = γ\n"),
        ("input.md", "first line  \nsecond line\n"),
        ("input.py", 's = "\\u200b"\nname = "Привет"\n'),
        ("input.bat", "echo one\r\necho two\r\n"),
    ],
)
def test_conservative_default_leaves_legitimate_text_byte_identical(tmp_path, name, content):
    result = _sanitize(tmp_path, content, name)

    assert _output(result) == content.encode("utf-8")
    assert result["changed"] is False
    assert result["diff"] == ""
    assert result["sha256_before"] == result["sha256_after"]


@pytest.mark.parametrize(
    ("hidden", "name"),
    [
        ("\u200b", "zero width space"),
        ("\u200c", "zero width non-joiner"),
        ("\u200d", "zero width joiner"),
        ("\u200e", "left-to-right mark"),
        ("\u200f", "right-to-left mark"),
        ("\ufeff", "byte order mark"),
        ("\u2060", "word joiner"),
        ("\u2061", "function application"),
        ("\u2062", "invisible times"),
        ("\u2063", "invisible separator"),
        ("\u2064", "invisible plus"),
        ("\u00ad", "soft hyphen"),
    ],
)
def test_conservative_default_removes_each_hidden_character_from_latin_text(tmp_path, hidden, name):
    result = _sanitize(tmp_path, f"pay{hidden}ment\n")

    assert _output_text(result) == "payment\n", name
    assert result["changes"]["zero_width_removed"] == 1
    assert result["changes"]["zero_width_preserved"] == 0


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (f"\U0001f468\u200d\u200d\U0001f469\n", "\U0001f468\U0001f469\n"),
        ("\U0001f468\u200dA\n", "\U0001f468A\n"),
        ("A\u200d\U0001f468\n", "A\U0001f468\n"),
        ("\U0001f468\u200c\U0001f469\n", "\U0001f468\U0001f469\n"),
        ("می\u200c\u200cخواهم\n", "میخواهم\n"),
        ("می\u200bخواهم\n", "میخواهم\n"),
        ("hello\ufeffworld\n", "helloworld\n"),
        ("סוף\u200b\u200f\n", "סוף\n"),
    ],
)
def test_hidden_characters_outside_their_legitimate_context_are_removed(
    tmp_path, content, expected
):
    assert _output_text(_sanitize(tmp_path, content)) == expected


@pytest.mark.parametrize(
    "control",
    ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"],
)
def test_conservative_default_removes_every_bidirectional_control(tmp_path, control):
    result = _sanitize(tmp_path, f"access{control}level\n")

    assert _output_text(result) == "accesslevel\n"
    assert result["changes"]["bidi_removed"] == 1


def test_conservative_default_repairs_a_lookalike_letter_inside_a_latin_word(tmp_path):
    result = _sanitize(tmp_path, "p\u0430ypal and Привет\n")

    assert _output_text(result) == "paypal and Привет\n"
    assert result["changes"]["homoglyphs_replaced"] == 1
    assert result["changes"]["homoglyphs_preserved"] == 2


def test_conservative_default_leaves_a_standalone_cyrillic_word_with_lookalikes_only(tmp_path):
    result = _sanitize(tmp_path, "\u0441\u0430\u0445\u0430\u0440 sugar\n")

    assert _output_text(result) == "\u0441\u0430\u0445\u0430\u0440 sugar\n"
    assert result["changes"]["homoglyphs_replaced"] == 0
    assert result["changes"]["homoglyphs_preserved"] == 5


def test_conservative_default_removes_trailing_whitespace_from_plain_text(tmp_path):
    result = _sanitize(tmp_path, "one \t \ntwo  \n")

    assert _output_text(result) == "one\ntwo\n"
    assert result["changes"]["trailing_whitespace_removed"] == 5


@pytest.mark.parametrize("suffix", [".md", ".markdown", ".mdown", ".mkd", ".mdx", ".MD"])
def test_two_trailing_spaces_are_kept_as_a_hard_break_in_markdown_files(tmp_path, suffix):
    result = _sanitize(tmp_path, "first  \nsecond\n", f"input{suffix}")

    assert _output_text(result) == "first  \nsecond\n"
    assert result["changes"]["hard_breaks_preserved"] == 1
    assert result["changes"]["trailing_whitespace_removed"] == 0


@pytest.mark.parametrize(
    ("content", "expected", "removed", "preserved"),
    [
        ("first     \nsecond\n", "first  \nsecond\n", 3, 1),
        ("first \nsecond\n", "first\nsecond\n", 1, 0),
        ("first\t\t\nsecond\n", "first\nsecond\n", 2, 0),
        ("first \t \nsecond\n", "first\nsecond\n", 3, 0),
        ("first  \n\nsecond\n", "first\n\nsecond\n", 2, 0),
        ("first  \n", "first\n", 2, 0),
        ("first  ", "first", 2, 0),
        ("   \nsecond\n", "\nsecond\n", 3, 0),
    ],
)
def test_markdown_whitespace_that_is_not_a_hard_break_is_removed(
    tmp_path, content, expected, removed, preserved
):
    result = _sanitize(tmp_path, content, "input.md")

    assert _output_text(result) == expected
    assert result["changes"]["trailing_whitespace_removed"] == removed
    assert result["changes"]["hard_breaks_preserved"] == preserved


def test_hard_break_is_not_kept_in_a_file_that_is_not_markdown(tmp_path):
    assert _output_text(_sanitize(tmp_path, "first  \nsecond\n", "input.py")) == "first\nsecond\n"


@pytest.mark.parametrize(
    ("content", "expected", "normalized"),
    [
        (b"a\r\nb\r\nc\n", b"a\r\nb\r\nc\r\n", 1),
        (b"a\nb\nc\r\n", b"a\nb\nc\n", 1),
        (b"a\r\nb\n", b"a\nb\n", 1),
        (b"a\rb\rc\n", b"a\rb\rc\r", 1),
    ],
)
def test_mixed_line_endings_become_the_most_common_ending(tmp_path, content, expected, normalized):
    result = _sanitize(tmp_path, content)

    assert _output(result) == expected
    assert result["changes"]["line_endings_normalized"] == normalized


def test_uniform_crlf_line_endings_are_unchanged_and_not_counted(tmp_path):
    result = _sanitize(tmp_path, b"a\r\nb\r\n")

    assert _output(result) == b"a\r\nb\r\n"
    assert result["changes"]["line_endings_normalized"] == 0


def test_last_line_without_an_ending_is_not_given_one(tmp_path):
    assert _output(_sanitize(tmp_path, b"a\r\nb\r\nc")) == b"a\r\nb\r\nc"


def test_destructive_profile_replaces_every_lookalike_letter_and_reports_it(tmp_path):
    result = _sanitize(tmp_path, "Привет, мир!\n", profile="destructive")

    assert _output_text(result) == "Пpивeт, миp!\n"
    assert result["changes"]["homoglyphs_replaced"] == 3
    assert result["changes"]["homoglyphs_preserved"] == 0
    assert result["policy"]["profile"] == "destructive"


def test_destructive_profile_removes_emoji_joiners_and_byte_order_marks(tmp_path):
    result = _sanitize(tmp_path, f"\ufeff{FAMILY}\n", profile="destructive")

    assert _output_text(result) == "\U0001f468\U0001f469\U0001f467\U0001f466\n"
    assert result["changes"]["zero_width_removed"] == 4
    assert result["changes"]["zero_width_preserved"] == 0


def test_destructive_profile_removes_markdown_hard_breaks(tmp_path):
    result = _sanitize(tmp_path, "first  \nsecond\n", "input.md", profile="destructive")

    assert _output_text(result) == "first\nsecond\n"
    assert result["changes"]["hard_breaks_preserved"] == 0


def test_destructive_profile_converts_every_line_ending_to_lf(tmp_path):
    result = _sanitize(tmp_path, b"a\r\nb\r\n", profile="destructive")

    assert _output(result) == b"a\nb\n"
    assert result["changes"]["line_endings_normalized"] == 2


def test_selected_channel_runs_alone(tmp_path):
    result = _sanitize(tmp_path, "p\u0430y\u200bment\u202e  \r\nline\n", channels=["bidi"])

    assert _output_text(result) == "p\u0430y\u200bment  \r\nline\n"
    assert result["changes"]["bidi_removed"] == 1
    assert result["changes"]["zero_width_removed"] == 0
    assert result["changes"]["homoglyphs_replaced"] == 0
    assert result["changes"]["trailing_whitespace_removed"] == 0
    assert result["changes"]["line_endings_normalized"] == 0
    assert result["policy"]["channels"] == ["bidi"]


@pytest.mark.parametrize(
    ("channel", "content", "expected", "counter", "count"),
    [
        ("zero_width", "a\u200bb  \n", "ab  \n", "zero_width_removed", 1),
        ("homoglyphs", "p\u0430y  \n", "pay  \n", "homoglyphs_replaced", 1),
        ("trailing_whitespace", "a\u200bb  \n", "a\u200bb\n", "trailing_whitespace_removed", 2),
        ("line_endings", "a\u200bb\r\nc\nd\n", "a\u200bb\nc\nd\n", "line_endings_normalized", 1),
    ],
)
def test_each_channel_can_be_selected_on_its_own(
    tmp_path, channel, content, expected, counter, count
):
    result = _sanitize(tmp_path, content.encode("utf-8"), channels=[channel])

    assert _output_text(result) == expected
    assert result["changes"][counter] == count
    assert result["policy"]["applied"] == [channel]


def test_channel_that_was_not_selected_reports_what_it_left_behind(tmp_path):
    result = _sanitize(tmp_path, "pay\u200bment p\u0430y\n", channels=["bidi"])

    assert result["changes"]["zero_width_preserved"] == 1
    assert result["changes"]["homoglyphs_preserved"] == 1


def test_policy_lists_the_profile_and_channels_in_a_stable_order(tmp_path):
    result = _sanitize(tmp_path, "clean\n", channels=["line_endings", "bidi", "bidi"])

    assert result["policy"] == {
        "profile": "conservative",
        "channels": ["bidi", "line_endings"],
        "applied": [],
    }


def test_default_policy_selects_every_channel(tmp_path):
    assert _sanitize(tmp_path, "clean\n")["policy"] == {
        "profile": "conservative",
        "channels": ["zero_width", "bidi", "homoglyphs", "trailing_whitespace", "line_endings"],
        "applied": [],
    }


def test_policy_lists_only_the_channels_that_changed_the_text(tmp_path):
    result = _sanitize(tmp_path, "a\u200bb\u202ec\n")

    assert result["policy"]["applied"] == ["zero_width", "bidi"]


@pytest.mark.parametrize(
    "options",
    [
        {"profile": "aggressive"},
        {"channels": ["unknown"]},
        {"channels": []},
    ],
)
def test_invalid_policy_is_rejected_before_any_output_is_written(tmp_path, options):
    source = tmp_path / "input.txt"
    source.write_text("a\u200bb\n", encoding="utf-8")
    output = tmp_path / "output.txt"

    with pytest.raises(ValueError):
        sanitize_file(source, output, **options)

    assert not output.exists()


def test_report_warns_when_it_left_characters_that_can_still_carry_data(tmp_path):
    result = _sanitize(tmp_path, f"{FAMILY} Привет\n")

    assert result["warnings"] == [
        "Kept 3 zero-width character(s) in text where they have a legitimate use; "
        "they can still carry data. Use --profile destructive to remove them.",
        "Kept 2 letter(s) that look like Latin letters; they can still carry data. "
        "Use --profile destructive to replace them.",
    ]


def test_report_warns_when_a_markdown_hard_break_was_kept(tmp_path):
    result = _sanitize(tmp_path, "first  \nsecond\n", "input.md")

    assert result["warnings"] == [
        "Kept 1 Markdown hard break(s); they can still carry data. "
        "Use --profile destructive to remove them."
    ]


def test_report_has_no_warnings_for_text_with_nothing_left_behind(tmp_path):
    assert _sanitize(tmp_path, "a\u200bb\n")["warnings"] == []


def test_destructive_report_warns_that_legitimate_text_may_have_changed(tmp_path):
    result = _sanitize(tmp_path, "Привет\n", profile="destructive")

    assert result["warnings"] == [
        "The destructive profile can change legitimate text, including non-Latin words "
        "and emoji. Review the diff."
    ]


def test_destructive_report_gives_no_warning_when_nothing_changed(tmp_path):
    assert _sanitize(tmp_path, "plain\n", profile="destructive")["warnings"] == []


def test_changed_source_file_warns_that_behavior_is_not_guaranteed(tmp_path):
    result = _sanitize(tmp_path, 'text = """line  \n"""\n', "input.py")

    assert result["warnings"] == [
        "Changes to source code can alter its behavior, including string literals. Review the diff."
    ]


def test_unchanged_source_file_gives_no_behavior_warning(tmp_path):
    assert _sanitize(tmp_path, "value = 1\n", "input.py")["warnings"] == []


def test_report_includes_policy_counts_hashes_and_diff(tmp_path):
    original = "pay\u200bment\n"
    result = _sanitize(tmp_path, original)

    assert result["sha256_before"] == hashlib.sha256(original.encode()).hexdigest()
    assert result["sha256_after"] == hashlib.sha256(b"payment\n").hexdigest()
    assert "+payment\n" in result["diff"]
    assert result["changes"] == {
        "zero_width_removed": 1,
        "zero_width_preserved": 0,
        "bidi_removed": 0,
        "homoglyphs_replaced": 0,
        "homoglyphs_preserved": 0,
        "trailing_whitespace_removed": 0,
        "hard_breaks_preserved": 0,
        "line_endings_normalized": 0,
    }


def test_binary_report_lists_the_policy_with_nothing_applied(tmp_path):
    result = _sanitize(tmp_path, b"\x89PNG\r\n\x1a\n", "input.png", profile="destructive")

    assert result["sanitization_status"] == "NO_OP_UNSUPPORTED"
    assert result["policy"]["profile"] == "destructive"
    assert result["policy"]["applied"] == []
    assert result["warnings"] == []
    assert set(result["changes"].values()) == {0}


def test_latin1_file_keeps_its_encoding(tmp_path):
    result = _sanitize(tmp_path, "caf\xe9  \n".encode("latin-1"))

    assert _output(result) == "caf\xe9\n".encode("latin-1")


@pytest.mark.parametrize("profile", ["conservative", "destructive"])
def test_every_profile_refuses_to_overwrite_an_existing_output(tmp_path, profile):
    source = tmp_path / "input.txt"
    source.write_text("a\u200bb\n", encoding="utf-8")
    output = tmp_path / "output.txt"
    output.write_text("keep me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        sanitize_file(source, output, profile=profile)

    assert output.read_text(encoding="utf-8") == "keep me"


@pytest.mark.parametrize("profile", ["conservative", "destructive"])
def test_every_profile_requires_dual_confirmation_to_overwrite(tmp_path, profile):
    source = tmp_path / "input.txt"
    source.write_text("a\u200bb\n", encoding="utf-8")

    with pytest.raises(ValueError):
        sanitize_file(source, in_place=True, profile=profile)

    assert source.read_text(encoding="utf-8") == "a\u200bb\n"


@pytest.mark.parametrize("profile", ["conservative", "destructive"])
def test_every_profile_preserves_the_original_in_copy_mode(tmp_path, profile):
    source = tmp_path / "input.txt"
    source.write_text("a\u200bb\n", encoding="utf-8")

    result = sanitize_file(source, profile=profile)

    assert source.read_text(encoding="utf-8") == "a\u200bb\n"
    assert result["original_preserved"] is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable")
@pytest.mark.parametrize("profile", ["conservative", "destructive"])
def test_every_profile_preserves_permissions_when_overwriting(tmp_path, profile):
    source = tmp_path / "input.txt"
    source.write_text("a\u200bb\n", encoding="utf-8")
    source.chmod(0o640)

    sanitize_file(source, in_place=True, confirm=True, profile=profile)

    assert stat.S_IMODE(source.stat().st_mode) == 0o640
    assert source.read_text(encoding="utf-8") == "ab\n"


def _validator_for(original: bytes):
    def validator(manifest, content, location):
        if content == original:
            return {"status": "VALID", "provider": "Example"}
        return {"status": "TAMPERED", "validation_errors": ["content hash mismatch"]}

    return validator


def test_conservative_profile_preserves_provenance_when_legitimate_text_is_unchanged(tmp_path):
    original = f"<svg><!-- c2pa manifest --><text>{FAMILY}</text></svg>".encode()
    source = tmp_path / "marked.svg"
    source.write_bytes(original)

    result = sanitize_file(source, provenance_validator=_validator_for(original))

    assert result["changed"] is False
    assert result["provenance_impact"] == "preserved"


def test_destructive_profile_reports_provenance_invalidation(tmp_path):
    original = f"<svg><!-- c2pa manifest --><text>{FAMILY}</text></svg>".encode()
    source = tmp_path / "marked.svg"
    source.write_bytes(original)

    result = sanitize_file(
        source, provenance_validator=_validator_for(original), profile="destructive"
    )

    assert result["changed"] is True
    assert result["provenance_after"]["status"] == "TAMPERED"
    assert result["provenance_impact"] == "invalidated"


def test_cli_uses_the_conservative_profile_by_default(tmp_path, capsys):
    source = tmp_path / "input.txt"
    source.write_text("Привет\n", encoding="utf-8")

    assert cli_main(["sanitize", str(source)]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["policy"]["profile"] == "conservative"
    assert Path(report["sanitized_path"]).read_text(encoding="utf-8") == "Привет\n"


def test_cli_applies_the_destructive_profile_on_request(tmp_path, capsys):
    source = tmp_path / "input.txt"
    source.write_text("Привет\n", encoding="utf-8")

    assert cli_main(["sanitize", str(source), "--profile", "destructive"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert Path(report["sanitized_path"]).read_text(encoding="utf-8") == "Пpивeт\n"


def test_cli_applies_only_the_selected_channels(tmp_path, capsys):
    source = tmp_path / "input.txt"
    source.write_text("a\u200bb\u202ec  \n", encoding="utf-8")

    arguments = ["sanitize", str(source), "--channel", "bidi", "--channel", "zero_width"]
    assert cli_main(arguments) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["policy"]["channels"] == ["zero_width", "bidi"]
    assert Path(report["sanitized_path"]).read_text(encoding="utf-8") == "abc  \n"


@pytest.mark.parametrize(
    "arguments",
    [["--profile", "aggressive"], ["--channel", "unknown"]],
)
def test_cli_rejects_an_unknown_policy_with_exit_two(tmp_path, capsys, arguments):
    source = tmp_path / "input.txt"
    source.write_text("text\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exit_info:
        cli_main(["sanitize", str(source), *arguments])

    assert exit_info.value.code == 2
    assert not (tmp_path / "input.sanitized.txt").exists()
    assert "invalid choice" in capsys.readouterr().err


def test_word_with_a_letter_that_has_no_latin_lookalike_is_left_alone(tmp_path):
    word = "Пpивет"

    result = _sanitize(tmp_path, f"{word}\n")

    assert _output_text(result) == f"{word}\n"
    assert result["changes"]["homoglyphs_replaced"] == 0


@pytest.mark.parametrize("document", ["CHANGELOG.md", "docs/compatibility.md"])
def test_default_change_has_a_migration_note_naming_the_destructive_profile(document):
    root = Path(__file__).resolve().parents[1]

    assert "--profile destructive" in (root / document).read_text(encoding="utf-8")
