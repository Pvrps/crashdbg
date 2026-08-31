"""Resolves the nearest recognizable *imported library* calls preceding a
crash by disassembling backward from the fault address with objdump.

This works without any debug symbols for the crashing binary: a
dynamically linked ELF must keep its PLT stubs and dynamic symbol table
intact at runtime (otherwise calls into shared libraries like libc could
never be resolved), so `strip` cannot remove them the way it removes
.symtab. objdump uses exactly that table to annotate `call` instructions -
we just read its output.

The one thing to guard against: objdump also annotates calls to *other
stripped internal functions* with the nearest symbol it knows plus a
(often huge) offset, e.g. `call d48bb90 <fmodf@plt+0xd07abf0>` - that is
NOT a call to fmodf, it's objdump's best-effort label for an unnamed
address. We only trust exact, zero-offset matches.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .models import ImportedCall

# Matches "  <hex addr>:\tcall(q)?  <hex target>  <bracketed symbol>"
# where <bracketed symbol> has NO "+offset" suffix - only an exact,
# zero-offset symbol match is emitted by objdump without one.
_CALL_LINE_RE = re.compile(
    r"^\s*(?P<addr>[0-9a-f]+):\s+callq?\s+[0-9a-f]+\s+<(?P<target>[^+>]+)>\s*$"
)


def available() -> bool:
    return shutil.which("objdump") is not None


def _classify(target: str) -> tuple[str, bool]:
    """Split a resolved objdump target like 'getifaddrs@plt' or
    'memcpy@GLIBC_2.14' into (symbol_name, via_plt)."""
    if target.endswith("@plt"):
        return target[: -len("@plt")], True
    if "@" in target:
        return target.split("@", 1)[0], False
    return target, False


def find_recent_calls(
    binary_path: Path,
    fault_vaddr: int,
    window: int = 0x4000,
    max_results: int = 8,
    timeout: float = 20.0,
) -> list[ImportedCall]:
    """Disassemble [fault_vaddr - window, fault_vaddr) and return `call`
    instructions objdump could resolve to an exact symbol, closest to the
    fault first."""
    if not available() or not binary_path.exists():
        return []

    start = max(fault_vaddr - window, 0)
    cmd = [
        "objdump",
        "-d",
        "-M",
        "intel",
        "--no-show-raw-insn",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{fault_vaddr:x}",
        str(binary_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        return []

    results: list[ImportedCall] = []
    for line in proc.stdout.splitlines():
        m = _CALL_LINE_RE.match(line)
        if not m:
            continue
        addr = int(m.group("addr"), 16)
        symbol, via_plt = _classify(m.group("target"))
        results.append(
            ImportedCall(
                address=addr,
                symbol=symbol,
                via_plt=via_plt,
                distance_bytes=fault_vaddr - addr,
            )
        )

    results.sort(key=lambda c: c.distance_bytes)
    return results[:max_results]
