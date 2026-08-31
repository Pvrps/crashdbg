"""Renders an AnalysisReport with rich. Purely presentational - all the
generic decoding/interpretation lives in signals.py/journal.py/disasm.py."""

from __future__ import annotations

import json
from dataclasses import asdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import AnalysisReport
from .signals import decode_page_fault_error, describe_signal


def _header_panel(report: AnalysisReport) -> Panel:
    cd = report.coredump
    name, desc = describe_signal(cd.signal)
    body = Text()
    body.append("Executable  ", style="bold")
    body.append(f"{cd.executable or cd.command or '?'}\n")
    body.append("PID         ", style="bold")
    body.append(f"{cd.pid}\n")
    body.append("Timestamp   ", style="bold")
    body.append(f"{cd.timestamp}\n")
    body.append("Hostname    ", style="bold")
    body.append(f"{cd.hostname or '?'}\n")
    body.append("Signal      ", style="bold")
    body.append(f"{cd.signal} ({cd.signal_name or name})\n", style="red bold")
    body.append("            ")
    body.append(desc, style="italic")
    return Panel(body, title="Crash", border_style="red")


def _fault_panel(report: AnalysisReport) -> Panel | None:
    kf = report.kernel_fault
    if kf is None:
        return Panel(
            Text(
                "No matching kernel 'segfault at ...' line was found in the "
                "journal near this crash time.\n"
                "This is normal for non-SIGSEGV crashes (SIGABRT, SIGSYS, "
                "etc.) or if kernel logs were rotated/unavailable.",
                style="yellow",
            ),
            title="Kernel Fault",
            border_style="yellow",
        )

    err = decode_page_fault_error(kf.error)
    body = Text()
    body.append("Fault address  ", style="bold")
    body.append(f"0x{kf.fault_addr:x}", style="red bold" if kf.fault_addr == 0 else "")
    if kf.fault_addr == 0:
        body.append("  (NULL pointer)", style="red")
    body.append("\n")
    body.append("Instruction ptr", style="bold")
    body.append(f" 0x{kf.ip:x}\n")
    body.append("Stack ptr      ", style="bold")
    body.append(f" 0x{kf.sp:x}\n")
    if kf.module:
        body.append("Module         ", style="bold")
        body.append(
            f" {kf.module} (fault at offset 0x{kf.module_ip_offset:x} within "
            f"module base 0x{kf.module_base:x}, size 0x{kf.module_size:x})\n"
        )
    body.append("Error code     ", style="bold")
    body.append(f" 0x{kf.error:x} ({kf.error})\n")
    body.append("  -> ", style="bold")
    body.append(err.summary, style="cyan")
    return Panel(body, title="Kernel Fault", border_style="cyan")


def _disasm_table(report: AnalysisReport) -> Table | None:
    if not report.disasm:
        return None
    table = Table(title="Faulting Instruction (decoded from kernel Code: bytes)")
    table.add_column("Addr (rel. to fault)", justify="right")
    table.add_column("Bytes", style="dim")
    table.add_column("Instruction")
    for instr in report.disasm:
        style = "bold red" if instr.is_fault_instr else None
        marker = "-> " if instr.is_fault_instr else "   "
        table.add_row(
            f"{marker}0x{instr.address:x}",
            instr.raw_bytes.hex(" "),
            f"{instr.mnemonic} {instr.op_str}",
            style=style,
        )
    return table


def _recent_calls_panel(report: AnalysisReport) -> Panel | None:
    if not report.recent_calls:
        return None
    body = Text()
    body.append(
        "Resolved via the binary's PLT/dynamic symbol table (survives stripping), "
        "scanning backward from the fault:\n\n",
        style="dim italic",
    )
    for i, c in enumerate(report.recent_calls):
        marker = "-> " if i == 0 else "   "
        kind = "plt" if c.via_plt else "direct"
        body.append(f"{marker}0x{c.address:x}  ", style="bold" if i == 0 else "")
        body.append(f"call {c.symbol}", style="green bold" if i == 0 else "green")
        body.append(f"  ({kind}, {c.distance_bytes} bytes before fault)\n", style="dim")
    return Panel(
        body, title="Nearest Recognizable Library Call(s) Before Fault", border_style="green"
    )


def _backtrace_table(report: AnalysisReport) -> Table:
    table = Table(title=f"Backtrace (source: {report.backtrace_source})")
    table.add_column("#", justify="right")
    table.add_column("Address", justify="right")
    table.add_column("Function")
    table.add_column("Location / Module")
    for f in report.backtrace:
        loc = f.location or f.module or ""
        addr = f"0x{f.address:x}" if f.address is not None else ""
        table.add_row(str(f.index), addr, f.function, loc)
    return table


def _notes_panel(report: AnalysisReport) -> Panel | None:
    if not report.notes:
        return None
    body = Text("\n".join(f"- {n}" for n in report.notes))
    return Panel(body, title="Notes", border_style="magenta")


def _commands_panel(report: AnalysisReport) -> Panel | None:
    if not report.commands_used:
        return None
    body = Text("\n".join(report.commands_used), style="dim")
    return Panel(body, title="Commands used (rerun manually if needed)", border_style="grey50")


def render(report: AnalysisReport, console: Console) -> None:
    console.print(_header_panel(report))

    fault_panel = _fault_panel(report)
    if fault_panel:
        console.print(fault_panel)

    disasm_table = _disasm_table(report)
    if disasm_table:
        console.print(disasm_table)

    calls_panel = _recent_calls_panel(report)
    if calls_panel:
        console.print(calls_panel)

    if report.backtrace:
        console.print(_backtrace_table(report))
    else:
        console.print(Panel(Text("No backtrace available.", style="yellow")))

    if report.journal_context:
        ctx = Text("\n".join(report.journal_context[-20:]))
        console.print(Panel(ctx, title="Journal context (before crash)", border_style="grey50"))

    notes_panel = _notes_panel(report)
    if notes_panel:
        console.print(notes_panel)

    cmds_panel = _commands_panel(report)
    if cmds_panel:
        console.print(cmds_panel)

    if report.kept_core_path:
        console.print(f"[green]Decompressed core kept at:[/] {report.kept_core_path}")


def to_json(report: AnalysisReport) -> str:
    def default(obj):
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        if hasattr(obj, "__fspath__"):
            return str(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        raise TypeError(f"not serializable: {type(obj)}")

    data = asdict(report)
    return json.dumps(data, default=default, indent=2)
