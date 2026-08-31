"""Shared objdump-based disassembly parsing, used both by the nearest
imported-call scanner (imports.py) and the full crashing-function listing.
Kept in one place so both consumers agree on exactly what counts as a
resolved symbol vs. objdump's "nearest known symbol + huge offset"
fallback noise (see imports.py's docstring for why that distinction
matters)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .models import RawInstr

_LINE_RE = re.compile(r"^\s*(?P<addr>[0-9a-f]+):\t(?P<rest>.*)$")
# Only an exact, zero-offset resolved symbol - objdump omits "+offset"
# solely when the target address matches a symbol precisely.
_EXACT_SYMBOL_RE = re.compile(r"<(?P<sym>[^+>]+)>\s*$")
_TARGET_ADDR_RE = re.compile(r"^([0-9a-f]+)\b")


def available() -> bool:
    return shutil.which("objdump") is not None


def classify_symbol(target: str) -> tuple[str, bool]:
    """Split a resolved objdump target like 'getifaddrs@plt' or
    'memcpy@GLIBC_2.14' into (symbol_name, via_plt)."""
    if target.endswith("@plt"):
        return target[: -len("@plt")], True
    if "@" in target:
        return target.split("@", 1)[0], False
    return target, False


def _parse(stdout: str) -> list[RawInstr]:
    instrs: list[RawInstr] = []
    for line in stdout.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        addr = int(m.group("addr"), 16)
        rest = m.group("rest").strip()
        if not rest or rest.startswith(".byte"):
            # Misaligned tail bytes (can happen right at an arbitrary
            # --start-address before the disassembler resynchronizes).
            instrs.append(RawInstr(addr, "byte", rest or "??", None, None, False))
            continue

        parts = rest.split(None, 1)
        mnemonic = parts[0]
        operand = parts[1] if len(parts) > 1 else ""

        target: int | None = None
        if mnemonic.startswith(("j", "loop", "call")):
            tm = _TARGET_ADDR_RE.match(operand)
            if tm:
                target = int(tm.group(1), 16)

        call_symbol: str | None = None
        via_plt = False
        if mnemonic.startswith("call"):
            sm = _EXACT_SYMBOL_RE.search(operand)
            if sm:
                call_symbol, via_plt = classify_symbol(sm.group("sym"))

        instrs.append(RawInstr(addr, mnemonic, operand, target, call_symbol, via_plt))

    instrs.sort(key=lambda i: i.address)
    return instrs


def disassemble_range(
    binary_path: Path, start: int, stop: int, timeout: float = 30.0
) -> list[RawInstr]:
    """Disassemble [start, stop) - stop is exclusive, matching objdump's
    --stop-address semantics."""
    if not available() or not binary_path.exists() or start >= stop:
        return []
    cmd = [
        "objdump",
        "-d",
        "-M",
        "intel",
        "--no-show-raw-insn",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        str(binary_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        return []
    return _parse(proc.stdout)
