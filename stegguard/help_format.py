# Copyright 2025 Aditya Arakeri
# SPDX-License-Identifier: Apache-2.0

"""Shared argparse help styling for the StegGuard commands."""

import argparse
import re
from collections.abc import Generator, Iterable
from typing import Any

from stegguard.common import BOLD, color

# "usage:" plus whole lines such as "options:" or "exit codes:". Only column 0 counts,
# so indented examples and option descriptions are never styled.
_HEADING = re.compile(r"^(?:usage:|[A-Za-z][A-Za-z ]*:$)", re.MULTILINE)


class CommandListFormatter(argparse.RawDescriptionHelpFormatter):
    """List subcommands flush with the options, without argparse's "COMMAND" line."""

    def _iter_indented_subactions(
        self, action: argparse.Action
    ) -> Generator[argparse.Action, None, None]:
        # The default indent isn't counted in the column width, so long names wrap.
        yield from getattr(action, "_get_subactions", list)()

    def _format_action(self, action: argparse.Action) -> str:
        text = super()._format_action(action)
        if action.nargs == argparse.PARSER:
            return text.split("\n", 1)[1]
        return text


class StyledParser(argparse.ArgumentParser):
    """Parser whose help keeps hand-written line breaks and has bold headings."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(*args, **kwargs)
        # Python 3.14 argparse adds its own colors; keep every version looking the same.
        self.color = False

    def format_help(self) -> str:
        # Styled after formatting: argparse counts escape codes as width when wrapping.
        return _HEADING.sub(lambda match: color(match.group(), BOLD), super().format_help())


class HelpAllAction(argparse.Action):
    """Reveal the options hidden from normal help, print the help, and exit."""

    def __init__(
        self,
        option_strings: list[str],
        dest: str = argparse.SUPPRESS,
        default: str = argparse.SUPPRESS,
        help: str | None = None,
        hidden: Iterable[tuple[argparse.Action, str]] = (),
    ) -> None:
        super().__init__(option_strings, dest, nargs=0, default=default, help=help)
        self.hidden = tuple(hidden)

    def __call__(self, parser: argparse.ArgumentParser, *_: Any) -> None:
        for action, help_text in self.hidden:
            action.help = help_text
        parser.print_help()
        parser.exit()
