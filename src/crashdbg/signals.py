"""Generic, POSIX-level knowledge about signals and x86 page-fault error
codes. Nothing here is specific to any particular application or bug -
it's just the standard meaning of signal numbers and the CPU/kernel page
fault error-code bitmask, applicable to any native crash on Linux/x86_64.
"""

from __future__ import annotations

from dataclasses import dataclass

# Standard POSIX/Linux signal numbers -> (name, generic one-line meaning).
# Only the subset that actually correspond to crashes/aborts is included.
SIGNAL_INFO: dict[int, tuple[str, str]] = {
    4: (
        "SIGILL",
        "Illegal instruction - corrupted code, CPU/ISA mismatch, or a jump into non-code memory.",
    ),
    5: (
        "SIGTRAP",
        "Trace/breakpoint trap - often an unhandled debug breakpoint or assertion trap.",
    ),
    6: (
        "SIGABRT",
        "Abort - raised by abort()/assert() failures, or glibc detecting heap corruption.",
    ),
    7: (
        "SIGBUS",
        "Bus error - misaligned memory access, or access past the end of an mmap'd file.",
    ),
    8: (
        "SIGFPE",
        "Floating point exception - typically integer division by zero or overflow, not just floats.",
    ),
    11: (
        "SIGSEGV",
        "Segmentation fault - invalid memory access (NULL/dangling pointer, out-of-bounds, stack overflow).",
    ),
    31: (
        "SIGSYS",
        "Bad system call - usually a seccomp filter rejecting a syscall the process attempted.",
    ),
}


def describe_signal(sig: int) -> tuple[str, str]:
    """Return (name, description) for a signal number, generic fallback if unknown."""
    if sig in SIGNAL_INFO:
        return SIGNAL_INFO[sig]
    return (f"SIG{sig}", "Unrecognized/uncommon signal number.")


@dataclass(frozen=True)
class PageFaultError:
    """Decoded x86 page-fault error code (see Linux arch/x86/mm/fault.c)."""

    present: bool
    write: bool
    user: bool
    reserved_write: bool
    instruction_fetch: bool
    raw: int

    @property
    def summary(self) -> str:
        access = "write" if self.write else "read"
        mode = "user-mode" if self.user else "kernel-mode"
        cause = (
            "protection violation (page was mapped, but access not permitted)"
            if self.present
            else "unmapped page (no mapping exists at this address)"
        )
        extra = []
        if self.reserved_write:
            extra.append("reserved bit set in page table entry (possible corruption)")
        if self.instruction_fetch:
            extra.append(
                "fault occurred fetching an instruction (NX violation or jump to bad address)"
            )
        suffix = f" [{'; '.join(extra)}]" if extra else ""
        return f"{mode} {access}, {cause}{suffix}"


def decode_page_fault_error(code: int) -> PageFaultError:
    """Decode the 'error N' value from a kernel 'segfault at ...' message.

    Bit layout (x86_64, see arch/x86/include/asm/trap_pf.h):
      bit 0 (P): 0 = no page found, 1 = protection fault
      bit 1 (W): 0 = read, 1 = write
      bit 2 (U): 0 = kernel mode, 1 = user mode
      bit 3 (R): reserved bit violation
      bit 4 (I): instruction fetch
    """
    return PageFaultError(
        present=bool(code & 0x1),
        write=bool(code & 0x2),
        user=bool(code & 0x4),
        reserved_write=bool(code & 0x8),
        instruction_fetch=bool(code & 0x10),
        raw=code,
    )
