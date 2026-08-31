"""Resolves the nearest recognizable *imported library* calls preceding a
crash by disassembling backward from the fault address.

This works without any debug symbols for the crashing binary: a
dynamically linked ELF must keep its PLT stubs and dynamic symbol table
intact at runtime (otherwise calls into shared libraries like libc could
never be resolved), so `strip` cannot remove them the way it removes
.symtab. objdump uses exactly that table to annotate `call` instructions -
we just read its output (see objdump_disasm.py).

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

from pathlib import Path

from . import objdump_disasm
from .models import ImportedCall, RawInstr

_UNCONDITIONAL_JUMP = {"jmp", "jmpq"}
_RETURN = {"ret", "retq", "retn", "retf"}


def _is_branch(mnemonic: str) -> bool:
    return mnemonic.startswith(("j", "loop"))


def available() -> bool:
    return objdump_disasm.available()


def _compute_reachability(instrs: list[RawInstr]) -> list[bool]:
    """Backward DP: on_path[i] is True if control flow starting at
    instrs[i] can plausibly reach the end of the window (the instruction
    immediately preceding the fault) via fall-through and/or explicit
    branch targets that stay within the window."""
    n = len(instrs)
    on_path = [False] * n
    if n == 0:
        return on_path
    on_path[-1] = True  # anchor: instruction immediately before the fault

    addr_index = {ins.address: i for i, ins in enumerate(instrs)}

    for i in range(n - 2, -1, -1):
        cur = instrs[i]
        if cur.mnemonic in _RETURN:
            on_path[i] = False
            continue

        target_idx = addr_index.get(cur.target) if cur.target is not None else None
        # A backward jump target (index < i, not yet computed in this
        # reverse pass) naturally defaults to False here, which correctly
        # avoids trusting loop-carried edges we haven't analyzed.
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
) -> list[ImportedCall]:
    """Disassemble [fault_vaddr - window, fault_vaddr), resolve exact
    imported-symbol calls, and mark each as reachable/unreachable via a
    backward control-flow pass. Reachable calls are returned first
    (closest to the fault first), followed by unreachable ones."""
    start = max(fault_vaddr - window, 0)
    instrs = objdump_disasm.disassemble_range(binary_path, start, fault_vaddr)
    reachable = _compute_reachability(instrs)

    results: list[ImportedCall] = []
    for instr, is_reachable in zip(instrs, reachable, strict=True):
        if instr.call_symbol is None:
            continue
        results.append(
            ImportedCall(
                address=instr.address,
                symbol=instr.call_symbol,
                via_plt=instr.via_plt,
                distance_bytes=fault_vaddr - instr.address,
                reachable=is_reachable,
            )
        )

    results.sort(key=lambda c: (not c.reachable, c.distance_bytes))
    return results[:max_results]
