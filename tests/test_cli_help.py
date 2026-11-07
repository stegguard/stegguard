"""The help screens: banner, styling, hidden limits, and text that matches real behavior."""

import json
import shlex
import sys
import zipfile

import pytest

from stegguard.cli import _validate_batch_arguments, build_parser
from stegguard.cli import main as cli_main
from stegguard.common import color
from stegguard.detector import build_detect_parser

BOLD = "\x1b[1m"
RESET = "\x1b[0m"
BANNER_CYAN = "\x1b[36m"
COMMANDS = ["detect", "decode", "sanitize", "watermark"]
EVERY_HELP = [["--help"], *([command, "--help"] for command in COMMANDS)]
LIMIT_FLAGS = [
    "--max-file-bytes",
    "--max-decompressed-bytes",
    "--max-image-pixels",
    "--max-archive-members",
    "--max-nesting-depth",
    "--max-scan-seconds",
    "--max-findings",
]

EXPECTED_BANNER = (
    r" ____  _____ _____ ____  ____ _   _   _    ____  ____  "
    "\n"
    r"/ ___||_   _| ____/ ___|/ ___| | | | / \  |  _ \|  _ \ "
    "\n"
    r"\___ \  | | |  _|| |  _| |  _| | | |/ _ \ | |_) | | | |"
    "\n"
    r" ___) | | | | |__| |_| | |_| | |_| / ___ \|  _ <| |_| |"
    "\n"
    r"|____/  |_| |_____\____|\____|\___/_/   \_\_| \_\____/ "
)


@pytest.fixture
def plain_terminal(monkeypatch):
    """Fix the width and clear NO_COLOR, whatever the machine running the tests has set."""
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.delenv("NO_COLOR", raising=False)


@pytest.fixture
def tty(plain_terminal, monkeypatch):
    """Return a function that makes stdout report itself as an interactive terminal.

    Tests call it in their body because pytest swaps sys.stdout after fixture setup.
    """

    def enable():
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    return enable


def _run_expecting_exit(arguments, capsys):
    """Run the CLI, which argparse ends with SystemExit, and return (code, out, err)."""
    with pytest.raises(SystemExit) as exit_info:
        cli_main(arguments)
    captured = capsys.readouterr()
    return exit_info.value.code, captured.out, captured.err


def _help_text(arguments, capsys):
    return _run_expecting_exit(arguments, capsys)[1]


# --- Banner ---


def test_top_level_help_starts_with_the_banner_followed_by_usage(plain_terminal, capsys):
    code, out, err = _run_expecting_exit(["--help"], capsys)

    assert code == 0
    assert out.startswith(f"{EXPECTED_BANNER}\n\nusage: stegguard ")
    assert err == ""


def test_top_level_help_prints_the_banner_exactly_once(plain_terminal, capsys):
    assert _help_text(["--help"], capsys).count(EXPECTED_BANNER) == 1


def test_banner_is_plain_ascii_so_it_renders_on_legacy_consoles():
    assert EXPECTED_BANNER.isascii()


@pytest.mark.parametrize("command", COMMANDS)
def test_subcommand_help_starts_with_usage_and_has_no_banner(command, plain_terminal, capsys):
    out = _help_text([command, "--help"], capsys)

    assert out.startswith(f"usage: stegguard {command}")
    assert "____" not in out


def test_version_output_is_only_the_version_line_without_a_banner(capsys):
    code, out, _ = _run_expecting_exit(["--version"], capsys)

    assert code == 0
    assert out.startswith("stegguard ")
    assert out.count("\n") == 1


def test_missing_command_error_shows_usage_on_stderr_without_a_banner(capsys):
    code, out, err = _run_expecting_exit([], capsys)

    assert code == 2
    assert out == ""
    assert err.startswith("usage: stegguard ")
    assert "____" not in err


def test_unknown_option_error_goes_to_stderr_without_a_banner(capsys):
    code, out, err = _run_expecting_exit(["decode", "x.txt", "--no-such-flag"], capsys)

    assert code == 2
    assert out == ""
    assert "unrecognized arguments: --no-such-flag" in err
    assert "____" not in err


# --- Main screen layout ---


def test_main_help_shows_the_three_step_workflow_in_order(plain_terminal, capsys):
    out = _help_text(["--help"], capsys)

    workflow = (
        "typical workflow:\n"
        "  stegguard detect . -r --json findings.json\n"
        "  stegguard decode --from-findings findings.json\n"
        "  stegguard sanitize --from-findings findings.json --output-dir clean/\n"
    )
    assert workflow in out


def test_main_help_describes_all_three_exit_codes(plain_terminal, capsys):
    out = _help_text(["--help"], capsys)

    assert (
        "exit codes:\n"
        "  0  Finished (for detect: nothing found)\n"
        "  1  Hidden content found (detect only)\n"
        "  2  Invalid input, or the run couldn't finish\n"
    ) in out


def test_main_help_lists_each_command_on_one_line_with_its_description(plain_terminal, capsys):
    out = _help_text(["--help"], capsys)

    section = out.split("commands:\n", 1)[1].split("\n\n", 1)[0]
    assert section.splitlines() == [
        "  detect      Scan files and folders for hidden content",
        "  decode      Extract hidden payloads without changing the file",
        "  sanitize    Write cleaned copies and leave the originals alone",
        "  watermark   Check watermark signals and Content Credentials",
    ]


# --- Text accuracy ---


@pytest.mark.parametrize("stale", ["(OSS)", "steg_decoder", "steg_detector", "detection toolkit"])
@pytest.mark.parametrize("arguments", EVERY_HELP)
def test_help_no_longer_mentions_retired_names(arguments, stale, plain_terminal, capsys):
    assert stale not in _help_text(arguments, capsys)


def test_detect_json_help_names_the_commands_that_read_the_report(plain_terminal, capsys):
    out = " ".join(_help_text(["detect", "--help"], capsys).split())

    assert "for the --from-findings option of 'stegguard decode' and 'stegguard sanitize'" in out


def test_detect_decode_flag_points_to_the_decode_command(plain_terminal, capsys):
    out = " ".join(_help_text(["detect", "--help"], capsys).split())

    assert "'stegguard decode' covers every payload type" in out


def test_sanitize_profile_help_states_when_lsbs_are_cleared(plain_terminal, capsys):
    out = " ".join(_help_text(["sanitize", "--help"], capsys).split())

    assert "clears pixel LSBs only when it finds evidence of a payload" in out
    assert "destructive removes all of these, including LSBs" in out


def test_sanitize_channel_help_separates_text_and_binary_channels(plain_terminal, capsys):
    out = " ".join(_help_text(["sanitize", "--help"], capsys).split())

    assert (
        "Text files: zero_width, bidi, homoglyphs, trailing_whitespace, line_endings. "
        "Binary files: metadata, lsb"
    ) in out


@pytest.mark.parametrize("command", ["decode", "sanitize"])
def test_input_help_says_from_findings_is_the_alternative(command, plain_terminal, capsys):
    assert f"File to {command} (or use --from-findings instead)" in _help_text(
        [command, "--help"], capsys
    )


@pytest.mark.parametrize("arguments", EVERY_HELP)
def test_help_fits_an_80_column_terminal(arguments, plain_terminal, capsys):
    out = _help_text(arguments, capsys)

    assert [line for line in out.splitlines() if len(line) > 80] == []


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_help_has_examples_and_exit_codes(command, plain_terminal, capsys):
    out = _help_text([command, "--help"], capsys)

    examples = out.split("examples:\n", 1)[1].split("\n\n", 1)[0].splitlines()
    assert len(examples) == 3
    assert all(line.startswith(f"  stegguard {command} ") for line in examples)
    assert "exit codes:\n  0  " in out
    assert "\n  2  " in out


@pytest.mark.parametrize("command", ["decode", "sanitize", "watermark"])
def test_examples_in_command_help_are_accepted_by_the_parser(command, plain_terminal, capsys):
    out = _help_text([command, "--help"], capsys)
    parser = build_parser()

    for line in out.split("examples:\n", 1)[1].split("\n\n", 1)[0].splitlines():
        args = parser.parse_args(shlex.split(line)[1:])
        assert args.command == command
        if command != "watermark":
            _validate_batch_arguments(parser, args)


def test_examples_in_detect_help_are_accepted_by_the_parser(plain_terminal, capsys):
    out = _help_text(["detect", "--help"], capsys)

    for line in out.split("examples:\n", 1)[1].split("\n\n", 1)[0].splitlines():
        args = build_detect_parser().parse_args(shlex.split(line)[2:])
        assert args.paths


def test_workflow_examples_in_main_help_are_accepted_by_the_parsers(plain_terminal, capsys):
    out = _help_text(["--help"], capsys)
    detect, decode, sanitize = out.split("typical workflow:\n", 1)[1].split("\n\n")[0].splitlines()

    assert build_detect_parser().parse_args(shlex.split(detect)[2:]).json_out == "findings.json"
    assert build_parser().parse_args(shlex.split(decode)[1:]).from_findings == "findings.json"
    assert build_parser().parse_args(shlex.split(sanitize)[1:]).output_dir == "clean/"


# --- The promises the help text makes about behavior ---


def test_sanitize_writes_next_to_the_input_as_documented(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text("clean\n", encoding="utf-8")

    assert cli_main(["sanitize", str(source)]) == 0
    assert (tmp_path / "note.sanitized.txt").read_text(encoding="utf-8") == "clean\n"


def test_sanitize_refuses_to_overwrite_an_existing_copy_as_documented(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text("clean\n", encoding="utf-8")
    existing = tmp_path / "note.sanitized.txt"
    existing.write_text("keep me\n", encoding="utf-8")

    assert cli_main(["sanitize", str(source)]) == 2
    assert existing.read_text(encoding="utf-8") == "keep me\n"


def test_sanitize_exits_zero_with_a_partial_status_as_documented(tmp_path, capsys):
    source = tmp_path / "bundle.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("member.txt", "content")
        archive.comment = b"hidden comment"

    code = cli_main(["sanitize", str(source)])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["sanitization_status"] == "PARTIAL"


def test_decode_exits_zero_for_an_unparseable_binary_as_documented(tmp_path, capsys):
    source = tmp_path / "broken.png"
    source.write_bytes(b"not really a png")

    code = cli_main(["decode", str(source)])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "NOT_SUPPORTED"


def test_decode_exits_two_for_a_missing_file_as_documented(tmp_path, capsys):
    assert cli_main(["decode", str(tmp_path / "missing.txt")]) == 2


# --- Hidden resource limits ---


@pytest.mark.parametrize("command", ["detect", "decode", "sanitize", "watermark"])
def test_normal_help_hides_the_limit_flags_and_points_to_help_all(command, plain_terminal, capsys):
    out = _help_text([command, "--help"], capsys)

    assert "--max-" not in out.replace("(--max-*)", "")
    assert "resource limits" not in out
    assert "--help-all" in out


@pytest.mark.parametrize("command", ["detect", "decode", "sanitize", "watermark"])
def test_help_all_lists_every_limit_flag(command, plain_terminal, capsys):
    code, out, _ = _run_expecting_exit([command, "--help-all"], capsys)

    assert code == 0
    assert "resource limits:" in out
    for flag in LIMIT_FLAGS:
        assert flag in out


def test_help_all_shows_the_default_for_each_limit(plain_terminal, capsys):
    out = " ".join(_help_text(["decode", "--help-all"], capsys).split())

    assert "Maximum bytes read from one top-level file (default: 104857600)" in out
    assert "Maximum archive members inspected (default: 500)" in out
    assert "Maximum elapsed seconds per file (default: 30.0)" in out


def test_hidden_limit_flags_still_take_effect(tmp_path, capsys):
    source = tmp_path / "note.txt"
    source.write_text("0123456789", encoding="utf-8")

    assert cli_main(["decode", str(source)]) == 0
    capsys.readouterr()

    assert cli_main(["decode", str(source), "--max-file-bytes", "5"]) == 2
    assert "stegguard: error:" in capsys.readouterr().err


# --- Color ---


def test_piped_help_has_no_escape_codes(plain_terminal, capsys):
    for arguments in EVERY_HELP:
        assert "\x1b[" not in _help_text(arguments, capsys)


def test_terminal_help_colors_the_banner_cyan(tty, capsys):
    tty()
    out = _help_text(["--help"], capsys)

    assert out.startswith(f"{BANNER_CYAN}{EXPECTED_BANNER}{RESET}\n\n")


@pytest.mark.parametrize(
    "heading", ["usage:", "typical workflow:", "options:", "commands:", "exit codes:"]
)
def test_terminal_help_makes_main_headings_bold(heading, tty, capsys):
    tty()
    assert f"\n{BOLD}{heading}{RESET}" in _help_text(["--help"], capsys)


@pytest.mark.parametrize("heading", ["usage:", "options:", "examples:", "exit codes:"])
@pytest.mark.parametrize("command", COMMANDS)
def test_terminal_help_makes_command_headings_bold(command, heading, tty, capsys):
    tty()
    out = _help_text([command, "--help"], capsys)

    assert f"{BOLD}{heading}{RESET}" in out


def test_terminal_help_leaves_descriptions_and_examples_uncolored(tty, capsys):
    tty()
    out = _help_text(["sanitize", "--help"], capsys)

    assert "\n  stegguard sanitize suspicious.txt\n" in out
    assert "\nWrite a cleaned copy and print a JSON report of every change.\n" in out


def test_colored_help_matches_plain_help_once_codes_are_removed(
    plain_terminal, monkeypatch, capsys
):
    plain = _help_text(["--help"], capsys)

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    colored = _help_text(["--help"], capsys)

    assert "\x1b[" in colored
    stripped = colored.replace(BANNER_CYAN, "").replace(BOLD, "").replace(RESET, "")
    assert stripped == plain


def test_no_color_turns_off_help_colors_in_a_terminal(tty, monkeypatch, capsys):
    tty()
    monkeypatch.setenv("NO_COLOR", "1")

    assert "\x1b[" not in _help_text(["--help"], capsys)


def test_empty_no_color_does_not_turn_off_colors(tty, monkeypatch, capsys):
    tty()
    monkeypatch.setenv("NO_COLOR", "")

    assert color("x", BOLD) == f"{BOLD}x{RESET}"


def test_no_color_also_applies_to_the_shared_color_helper(tty, monkeypatch):
    tty()
    monkeypatch.setenv("NO_COLOR", "1")

    assert color("x", BOLD) == "x"


def test_decode_json_stays_free_of_escape_codes_in_a_terminal(tty, tmp_path, capsys):
    tty()
    source = tmp_path / "note.txt"
    source.write_text("hello\n", encoding="utf-8")

    assert cli_main(["decode", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "DECODED"


def test_sanitize_json_stays_free_of_escape_codes_in_a_terminal(tty, tmp_path, capsys):
    tty()
    source = tmp_path / "note.txt"
    source.write_text("hello\n", encoding="utf-8")

    assert cli_main(["sanitize", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["sanitization_status"]


def test_terminal_help_does_not_bold_text_that_merely_contains_a_colon(tty, capsys):
    tty()
    out = _help_text(["decode", "--help"], capsys)

    assert "\nText files: zero-width characters, trailing whitespace, and line endings.\n" in out
