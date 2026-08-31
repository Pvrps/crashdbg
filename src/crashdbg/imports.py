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

Byte-proximity alone is also misleading on its own: compilers routinely
place error-handling blocks for a *failed* call physically between that
call and the code that runs on success, e.g.:

    call getifaddrs
    test eax, eax
    je   success          <- actually taken
    call strerror         <- only reached if getifaddrs FAILED (never ran)
    ...
    success: ... (crashes later)

`strerror` is closer in bytes to the crash than `getifaddrs`, despite
never having executed. To avoid that false signal, we do a lightweight
backward reachability pass over the disassembled window: track every
branch's target, then walk backward from the fault instruction along
actual control-flow edges (fall-through and/or jump target) and only
trust calls that are provably reachable that way. This is *not* full
symbolic execution - conditional branches are resolved optimistically
(either successor counts), and any jump whose target lands outside the
scanned window is treated as unresolvable (conservatively excluded) - but
it correctly discards untaken error-handling blocks like the example
above, which is the dominant source of false positives in practice.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import ImportedCall

_LINE_RE = re.compile(r"^\s*(?P<addr>[0-9a-f]+):\t(?P<rest>.*)$")
# An exact, zero-offset resolved symbol - objdump only omits "+offset" when
# the target address matches a symbol precisely.
_EXACT_SYMBOL_RE = re.compile(r"<(?P<sym>[^+>]+)>\s*$")
_TARGET_ADDR_RE = re.compile(r"^([0-9a-f]+)\b")

_UNCONDITIONAL_JUMP = {"jmp", "jmpq"}
_RETURN = {"ret", "retq", "retn", "retf"}


def _is_branch(mnemonic: str) -> bool:
    return mnemonic.startswith(("j", "loop"))


@dataclass
class _Instr:
    addr: int
    mnemonic: str
    target: int | None
    call_symbol: str | None
    via_plt: bool


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


def _parse_instructions(objdump_stdout: str) -> list[_Instr]:
    instrs: list[_Instr] = []
    for line in objdump_stdout.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        addr = int(m.group("addr"), 16)
        rest = m.group("rest").strip()
        if not rest or rest.startswith(".byte"):
            # Misaligned tail bytes (can happen right at an arbitrary
            # --start-address before the disassembler resynchronizes) -
            # treat as an opaque 1-byte non-branching instruction.
            instrs.append(_Instr(addr, "byte", None, None, False))
            continue

        parts = rest.split(None, 1)
        mnemonic = parts[0]
        operand = parts[1] if len(parts) > 1 else ""

        target: int | None = None
        if mnemonic in _UNCONDITIONAL_JUMP or _is_branch(mnemonic) or mnemonic.startswith("call"):
            tm = _TARGET_ADDR_RE.match(operand)
            if tm:
                target = int(tm.group(1), 16)

        call_symbol: str | None = None
        via_plt = False
        if mnemonic.startswith("call"):
            sm = _EXACT_SYMBOL_RE.search(operand)
            if sm:
                call_symbol, via_plt = _classify(sm.group("sym"))

        instrs.append(_Instr(addr, mnemonic, target, call_symbol, via_plt))

    instrs.sort(key=lambda i: i.addr)
    return instrs


def _compute_reachability(instrs: list[_Instr]) -> list[bool]:
    """Backward DP: on_path[i] is True if control flow starting at
    instrs[i] can plausibly reach the end of the window (the instruction
    immediately preceding the fault) via fall-through and/or explicit
    branch targets that stay within the window."""
    n = len(instrs)
    on_path = [False] * n
    if n == 0:
        return on_path
    on_path[-1] = True  # anchor: instruction immediately before the fault

    addr_index = {ins.addr: i for i, ins in enumerate(instrs)}

    for i in range(n - 2, -1, -1):
        cur = instrs[i]
        if cur.mnemonic in _RETURN:
            on_path[i] = False
            continue

        target_idx = addr_index.get(cur.target) if cur.target is not None else None
        # A target index >= i means it's later in program order (forward
        # jump, already computed this pass) or, for targets equal to an
        # earlier index than i (backward jump), on_path there is still its
        # unresolved default of False - which correctly avoids trusting
        # loop-carried edges we haven't analyzed.
        via_target = bool(target_idx is not None and on_path[target_idx])

        if cur.mnemonic in _UNCONDITIONAL_JUMP:
            on_path[i] = via_target
        elif _is_branch(cur.mnemonic):
            on_path[i] = on_path[i + 1] or via_target
        else:
            # Normal instruction, including `call` (falls through after
            # the callee returns) - flows to the next instruction.
            on_path[i] = on_path[i + 1]

    return on_path


def find_recent_calls(
    binary_path: Path,
    fault_vaddr: int,
    window: int = 0x4000,
    max_results: int = 8,
    timeout: float = 20.0,
) -> list[ImportedCall]:
    """Disassemble [fault_vaddr - window, fault_vaddr), resolve exact
    imported-symbol calls, and mark each as reachable/unreachable via a
    backward control-flow pass. Reachable calls are returned first
    (closest to the fault first), followed by unreachable ones."""
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

    instrs = _parse_instructions(proc.stdout)
    reachable = _compute_reachability(instrs)

    results: list[ImportedCall] = []
    for instr, is_reachable in zip(instrs, reachable, strict=True):
        if instr.call_symbol is None:
            continue
        results.append(
            ImportedCall(
                address=instr.addr,
                symbol=instr.call_symbol,
                via_plt=instr.via_plt,
                distance_bytes=fault_vaddr - instr.addr,
                reachable=is_reachable,
            )
        )

    results.sort(key=lambda c: (not c.reachable, c.distance_bytes))
    return results[:max_results]
