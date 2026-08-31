"""Correlates a coredump with the surrounding systemd journal - in
particular the kernel's 'segfault at ...' line (or other fault-type lines),
plus generic contextual log lines around the crash. Nothing here assumes
which process/app produced the crash.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timedelta

from .models import KernelFault

# Kernel page-fault message format, see arch/x86/mm/fault.c show_signal_msg():
#   "<comm>[<pid>]: segfault at <addr> ip <ip> sp <sp> error <code>"
#   optionally followed by " in <module>[<ip_off>,<base>+<size>]"
#   optionally followed by " likely on CPU <n> (core <n>, socket <n>)"
_SEGFAULT_RE = re.compile(
    r"^(?P<comm>\S+)\[(?P<pid>\d+)]: segfault at (?P<addr>[0-9a-fA-F]+) "
    r"ip (?P<ip>[0-9a-fA-F]+) sp (?P<sp>[0-9a-fA-F]+) error (?P<error>\d+)"
    r"(?: in (?P<module>[^\[]+)\[(?P<ip_off>[0-9a-fA-F]+),(?P<base>[0-9a-fA-F]+)\+(?P<size>[0-9a-fA-F]+)])?"
    r"(?: likely on CPU (?P<cpu>\d+))?"
)

_CODE_LINE_RE = re.compile(r"^Code:\s+(?P<bytes>.+)$")


def available() -> bool:
    return shutil.which("journalctl") is not None


def _iter_json_entries(since: datetime, until: datetime, kernel_only: bool) -> list[dict]:
    args = [
        "journalctl",
        "-o",
        "json",
        "--since",
        since.strftime("%Y-%m-%d %H:%M:%S"),
        "--until",
        until.strftime("%Y-%m-%d %H:%M:%S"),
    ]
    if kernel_only:
        args.append("-k")
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return []
    entries = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def find_kernel_fault(
    pid: int, crash_time: datetime, window_seconds: float = 5.0
) -> tuple[KernelFault | None, str | None]:
    """Search kernel log lines around crash_time for a 'segfault at ...'
    line matching this pid, plus the following 'Code:' disassembly hint
    line if present. Returns (fault, code_line_raw)."""
    since = crash_time - timedelta(seconds=window_seconds)
    until = crash_time + timedelta(seconds=window_seconds)
    entries = _iter_json_entries(since, until, kernel_only=True)

    fault: KernelFault | None = None
    code_line: str | None = None

    for entry in entries:
        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            continue
        m = _SEGFAULT_RE.match(message)
        if m and int(m.group("pid")) == pid:
            fault = KernelFault(
                comm=m.group("comm"),
                pid=int(m.group("pid")),
                fault_addr=int(m.group("addr"), 16),
                ip=int(m.group("ip"), 16),
                sp=int(m.group("sp"), 16),
                error=int(m.group("error")),
                module=m.group("module"),
                module_ip_offset=int(m.group("ip_off"), 16) if m.group("ip_off") else None,
                module_base=int(m.group("base"), 16) if m.group("base") else None,
                module_size=int(m.group("size"), 16) if m.group("size") else None,
                cpu=int(m.group("cpu")) if m.group("cpu") else None,
                raw_line=message,
            )
            continue

        # The 'Code:' line is emitted as the very next kernel message after
        # the segfault line for the same event.
        if fault is not None and code_line is None and _CODE_LINE_RE.match(message):
            code_line = message

    return fault, code_line


def context_around(
    crash_time: datetime,
    pid: int | None = None,
    unit: str | None = None,
    before_seconds: float = 15.0,
    after_seconds: float = 2.0,
    limit: int = 40,
) -> list[str]:
    """Generic journal context (not kernel-only) around the crash - useful
    for spotting whatever preceded it (missing symbols, warnings, etc.)
    without assuming what to look for."""
    since = crash_time - timedelta(seconds=before_seconds)
    until = crash_time + timedelta(seconds=after_seconds)
    entries = _iter_json_entries(since, until, kernel_only=False)

    lines: list[str] = []
    for entry in entries:
        entry_pid = entry.get("_PID")
        try:
            entry_pid_int = int(entry_pid) if entry_pid is not None else None
        except ValueError:
            entry_pid_int = None

        matches_pid = pid is not None and entry_pid_int == pid
        matches_unit = unit is not None and entry.get("_SYSTEMD_UNIT") == unit
        if pid is None and unit is None:
            matches = True
        else:
            matches = matches_pid or matches_unit

        if not matches:
            continue

        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            continue
        ident = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "?"
        lines.append(f"{ident}: {message}")

    return lines[-limit:]
