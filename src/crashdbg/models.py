"""Plain data models shared across crashdbg. Everything here is generic -
no field or type is specific to any particular application/binary/bug."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class CoredumpEntry:
    """One row from `coredumpctl list --json=short`."""

    pid: int
    uid: int
    gid: int
    signal: int
    exe: str | None
    timestamp: datetime | None
    corefile: str  # "present" | "missing" | "none" | "truncated" | "unreadable"
    size: int | None


@dataclass
class CoredumpInfo:
    """Full detail from `coredumpctl info --json=short <match>`."""

    pid: int
    tid: int | None
    uid: int
    gid: int
    signal: int
    signal_name: str | None
    timestamp: datetime
    executable: str | None
    command: str | None
    command_line: str | None
    hostname: str | None
    unit: str | None
    filename: Path | None
    disk_size: int | None
    storage: str | None
    message: str


@dataclass
class KernelFault:
    """Parsed 'segfault at ...' line from the kernel (dmesg/journalctl -k)."""

    comm: str
    pid: int
    fault_addr: int
    ip: int
    sp: int
    error: int
    module: str | None
    module_ip_offset: int | None
    module_base: int | None
    module_size: int | None
    cpu: int | None
    raw_line: str


@dataclass
class DisasmInstr:
    address: int
    size: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes
    is_fault_instr: bool = False


@dataclass
class ImportedCall:
    """A `call` instruction, found while scanning backward from the fault
    address, that objdump could resolve to an exact (zero-offset) symbol
    via the binary's PLT/dynamic symbol table - the only kind of symbol
    that survives `strip` on a dynamically linked binary."""

    address: int
    symbol: str
    via_plt: bool
    distance_bytes: int


@dataclass
class BacktraceFrame:
    index: int
    address: int | None
    function: str
    args: str | None
    location: str | None  # "file.c:42" if debug info present
    module: str | None  # "from /path/to/lib.so" if shown
    raw_line: str


@dataclass
class AnalysisReport:
    coredump: CoredumpInfo
    kernel_fault: KernelFault | None = None
    disasm: list[DisasmInstr] = field(default_factory=list)
    recent_calls: list[ImportedCall] = field(default_factory=list)
    backtrace: list[BacktraceFrame] = field(default_factory=list)
    backtrace_source: str = "none"  # "gdb" | "coredump-message" | "none"
    journal_context: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands_used: list[str] = field(default_factory=list)
    kept_core_path: Path | None = None
