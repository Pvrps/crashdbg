"""Generic detection/parsing helpers for Wine/Proton processes - covers
any Windows game or app running under Wine, not just Unreal Engine
titles. This exists because coredumpctl's own Executable/Command fields
are next to useless for these: every Windows process under Proton shows
up as the same handful of wine-preloader/wineserver/wine64 binaries,
regardless of which actual Windows program was running - a game, or one
of the dozens of internal Windows services Wine emulates (plugplay.exe,
services.exe, explorer.exe, ...).
"""

from __future__ import annotations

import re

# Generic wine loader/server binary names - identical across every
# Wine/Proton build and every game, so the name alone tells you nothing
# useful about which Windows program actually crashed.
_WINE_LOADER_NAMES = {
    "wine-preloader",
    "wine64-preloader",
    "wineserver",
    "wine",
    "wine64",
}


def is_wine_process(exe: str | None) -> bool:
    """Whether `exe` (a full path, as coredumpctl reports it) is one of
    Wine's own generic loader/server binaries rather than a real,
    distinguishable program."""
    if not exe:
        return False
    name = exe.rsplit("/", 1)[-1]
    return name in _WINE_LOADER_NAMES


# coredumpctl (systemd) renders a stored argv array as a sequence of
# bash ANSI-C-quoted tokens - $'arg one' $'arg\\ two' ... - it's not a
# real shell command line, just that quoting convention used to safely
# display arbitrary bytes. This tokenizes it back into a plain argv list.
_TOKEN_RE = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_ESCAPE_RE = re.compile(r"\\(.)")
_ANSI_C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"'}


def _unescape(token: str) -> str:
    return _ESCAPE_RE.sub(lambda m: _ANSI_C_ESCAPES.get(m.group(1), m.group(1)), token)


def parse_command_line(command_line: str | None) -> list[str]:
    """Tokenize a coredumpctl-reported CommandLine string back into argv."""
    if not command_line:
        return []
    return [_unescape(m.group(1)) for m in _TOKEN_RE.finditer(command_line)]


def wine_target(command_line: str | None) -> str | None:
    """The actual Windows-side program Wine was running, if recoverable
    from its argv - e.g. 'Bodycam-Win64-Shipping.exe' or 'plugplay.exe' -
    instead of the generic wine-preloader/wineserver binary name every
    such process otherwise shares.

    Real game processes show their full Windows path directly as the
    last argv entry (e.g. "S:\\...\\Bodycam-Win64-Shipping.exe"); wine's
    own internal helper processes (services.exe, plugplay.exe, ...) show
    up the same way, which is exactly the point - this lets you tell them
    apart."""
    args = parse_command_line(command_line)
    if not args:
        return None
    last = args[-1]
    # Only treat it as a resolved target if it actually looks like a
    # Windows executable path - wine64-preloader's own argv sometimes ends
    # in another Linux-side wine helper instead, which isn't useful here.
    if not re.search(r"\.exe$", last, re.IGNORECASE):
        return None
    name = last.replace("\\", "/").rsplit("/", 1)[-1]
    return name or None
