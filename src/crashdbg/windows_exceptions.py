"""Generic, engine-agnostic knowledge about Windows/SEH exception codes, as
they appear in the "Unhandled Exception: ..." style ErrorMessage strings
written by Windows-native crash reporters (Unreal Engine's included).
Nothing here is specific to any particular application or engine - this is
the Windows-exception equivalent of signals.py's POSIX signal knowledge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Exception/NTSTATUS name -> generic one-line meaning. Only the subset that
# actually shows up in crash reports is included.
EXCEPTION_INFO: dict[str, str] = {
    "EXCEPTION_ACCESS_VIOLATION": (
        "Invalid memory access (NULL/dangling pointer, out-of-bounds, or "
        "use-after-free) - the Windows/SEH equivalent of a Linux SIGSEGV."
    ),
    "EXCEPTION_STACK_OVERFLOW": (
        "Stack overflow - usually unbounded/infinite recursion, or a very large stack allocation."
    ),
    "EXCEPTION_ILLEGAL_INSTRUCTION": (
        "Illegal instruction - corrupted code or a CPU/ISA mismatch."
    ),
    "EXCEPTION_INT_DIVIDE_BY_ZERO": "Integer division by zero.",
    "EXCEPTION_FLT_DIVIDE_BY_ZERO": "Floating point division by zero.",
    "EXCEPTION_ARRAY_BOUNDS_EXCEEDED": "Array index out of bounds (hardware bound-check fault).",
    "EXCEPTION_DATATYPE_MISALIGNMENT": "Misaligned memory access.",
    "EXCEPTION_PRIV_INSTRUCTION": "Attempted to execute a privileged CPU instruction.",
    "EXCEPTION_IN_PAGE_ERROR": (
        "Failed to page in memory from disk (e.g. a bad mmap'd/network file, or failing storage)."
    ),
    "EXCEPTION_BREAKPOINT": (
        "Breakpoint/debug trap - often an unhandled assertion trap (e.g. __debugbreak())."
    ),
    "EXCEPTION_HEAP_CORRUPTION": "Heap corruption detected by the CRT/OS heap manager.",
    "EXCEPTION_STACK_BUFFER_OVERRUN": "Stack buffer overrun detected (/GS check failure).",
    "STATUS_STACK_BUFFER_OVERRUN": "Stack buffer overrun detected (/GS check failure).",
    "EXCEPTION_FLT_INVALID_OPERATION": "Invalid floating point operation.",
    "EXCEPTION_FLT_OVERFLOW": "Floating point overflow.",
    "EXCEPTION_FLT_UNDERFLOW": "Floating point underflow.",
    "EXCEPTION_FLT_STACK_CHECK": "Floating point stack overflow/underflow.",
    "EXCEPTION_NONCONTINUABLE_EXCEPTION": (
        "A non-continuable exception was raised again after being marked non-continuable."
    ),
}

_EXC_NAME_RE = re.compile(r"\b(EXCEPTION_[A-Z_]+|STATUS_[A-Z_]+)\b")
_ADDR_RE = re.compile(r"\b(reading|writing) address (0x[0-9a-fA-F]+)")


@dataclass(frozen=True)
class WindowsExceptionInfo:
    name: str | None
    description: str
    access_type: str | None  # "read" | "write" | None
    fault_address: int | None
    raw: str

    @property
    def is_null_deref(self) -> bool:
        # Small offsets from NULL are almost always a null (or near-null,
        # e.g. `nullptr->member`) pointer dereference rather than a real
        # invalid heap/stack address - the same "NULL page" convention
        # Windows (like most OSes) reserves as permanently unmapped.
        return self.fault_address is not None and self.fault_address < 0x10000


def parse_error_message(message: str | None) -> WindowsExceptionInfo | None:
    """Parse a UE-style 'Unhandled Exception: EXCEPTION_... reading/writing
    address 0x...' ErrorMessage string into a structured exception, if
    recognizable. Returns None for messages that don't look like a hardware
    exception at all (e.g. an engine-level fatal-error/ensure/check string
    with no EXCEPTION_*/STATUS_* code in it)."""
    if not message:
        return None
    name_match = _EXC_NAME_RE.search(message)
    addr_match = _ADDR_RE.search(message)
    if name_match is None and addr_match is None:
        return None

    name = name_match.group(1) if name_match else None
    if name is not None:
        description = EXCEPTION_INFO.get(name, "Unrecognized/uncommon exception code.")
    else:
        description = (
            "No recognized Windows exception code - likely an engine-level fatal "
            "error/ensure/check failure rather than a hardware exception."
        )

    access_type = None
    fault_address = None
    if addr_match:
        access_type = "write" if addr_match.group(1) == "writing" else "read"
        fault_address = int(addr_match.group(2), 16)

    return WindowsExceptionInfo(
        name=name,
        description=description,
        access_type=access_type,
        fault_address=fault_address,
        raw=message,
    )
