"""Recovers exact function boundaries from a binary's .eh_frame (the
exception-unwinding metadata GCC/Clang emit for every function in C/C++
code), with no symbol table required at all.

Each function gets exactly one FDE (Frame Description Entry) covering its
address range, because unwinding through arbitrary code at runtime (e.g.
propagating a C++ exception, or a debugger walking the stack) needs to
know exactly where each function starts/ends and how to restore the
previous frame. `strip` removes .symtab freely, but cannot safely remove
.eh_frame without breaking exception handling and stack unwinding for the
whole binary - so this survives stripping just like the PLT does.

This gives us, for free: the exact start/end of "the method that crashed",
without any decompiler, debug symbols, or heuristic prologue scanning.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_FDE_RE = re.compile(r"FDE cie=[0-9a-f]+ pc=(?P<start>[0-9a-f]+)\.\.(?P<end>[0-9a-f]+)")


def available() -> bool:
    return shutil.which("readelf") is not None


def find_function_bounds(
    binary_path: Path, addr: int, timeout: float = 30.0
) -> tuple[int, int] | None:
    """Return (start, end) of the function containing `addr`, or None if
    no FDE covers it (function has no unwind info, e.g. hand-written
    assembly or certain non-C++ code) or the tool/section is unavailable.
    """
    if not available() or not binary_path.exists():
        return None
    proc = subprocess.run(
        ["readelf", "--debug-dump=frames", str(binary_path)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        return None

    for line in proc.stdout.splitlines():
        m = _FDE_RE.search(line)
        if not m:
            continue
        start, end = int(m.group("start"), 16), int(m.group("end"), 16)
        if start <= addr < end:
            return (start, end)
    return None


def synthetic_label(addr: int) -> str:
    """IDA/Ghidra/Binary Ninja-style placeholder name for an address with
    no real symbol - clearly marked as synthetic, never confused with a
    real function name."""
    return f"sub_{addr:x}"
