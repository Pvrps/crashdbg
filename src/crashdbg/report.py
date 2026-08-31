"""Builds Rich renderables from an AnalysisReport, and renders them as a
static one-shot report. Purely presentational - all the generic
decoding/interpretation lives in signals.py/journal.py/disasm.py.

The individual `*_panel`/`*_table` builders below are public (not
underscore-prefixed) because tui.py reuses them directly to populate its
tabs - the static report and the interactive TUI are just two different
arrangements of the exact same Rich renderables.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import AnalysisReport
from .signals import decode_page_fault_error, describe_signal


def header_panel(report: AnalysisReport) -> Panel:
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


def fault_panel(report: AnalysisReport) -> Panel | None:
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


def disasm_table(report: AnalysisReport) -> Table | None:
    if not report.disasm:
        return None
    table = Table(title="Faulting Instruction (decoded from kernel Code: bytes)")
    table.add_column("Addr (rel. to fault)", justify="right")
    table.add_column("Bytes", style="dim")
    table.add_column("Instruction")
    for instr in report.disasm:
        style = "bold red" if instr.is_fault_instr else None
        marker = "-> " if instr.is_fault_instr else "   "
        # Instruction text (e.g. "movzx eax, word ptr [rax]") is plain text,
        # never markup - Table.add_row() would otherwise interpret literal
        # '[' / ']' in memory operands as (invalid) rich style tags and
        # silently drop them, so wrap in Text() rather than passing a str.
        table.add_row(
            Text(f"{marker}0x{instr.address:x}"),
            Text(instr.raw_bytes.hex(" ")),
            Text(f"{instr.mnemonic} {instr.op_str}"),
            style=style,
        )
    return table


def recent_calls_panel(report: AnalysisReport) -> Panel | None:
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
        style = "dim" if not c.reachable else ("green bold" if i == 0 else "green")
        body.append(f"{marker}0x{c.address:x}  ", style="bold" if i == 0 and c.reachable else "")
        body.append(f"call {c.symbol}", style=style)
        suffix = f"  ({kind}, {c.distance_bytes} bytes before fault)"
        if not c.reachable:
            suffix += "  [unreachable branch]"
        body.append(f"{suffix}\n", style="dim")
    return Panel(
        body, title="Nearest Recognizable Library Call(s) Before Fault", border_style="green"
    )


def crash_function_table(report: AnalysisReport) -> Table | None:
    cf = report.crash_function
    if cf is None:
        return None
    size = cf.end - cf.start
    subtitle = (
        f"{cf.label} (synthetic name - no real symbol available)  "
        f"0x{cf.start:x}..0x{cf.end:x}  ({size} bytes)  "
        f"fault at {cf.label}+0x{cf.fault_offset:x}"
    )
    if cf.truncated:
        subtitle += "  [showing a window around the fault; --function-context to widen]"
    table = Table(title="Crashing Function (recovered from .eh_frame, no symbols needed)")
    table.caption = subtitle
    table.add_column("Offset", justify="right")
    table.add_column("Address", justify="right")
    table.add_column("Instruction")
    fault_addr = cf.start + cf.fault_offset
    for instr in cf.instructions:
        is_fault = instr.address == fault_addr
        marker = "-> " if is_fault else "   "
        style = "bold red" if is_fault else ("green" if instr.call_symbol else None)
        text = f"{instr.mnemonic} {instr.operand}".strip()
        if instr.call_symbol:
            kind = "plt" if instr.via_plt else "direct"
            text = f"{instr.mnemonic} {instr.call_symbol}  ({kind})"
        # See disasm_table: instruction text is plain, not markup - memory
        # operands like "[rsp+0x10]" would otherwise be silently eaten.
        table.add_row(
            Text(f"{marker}+0x{instr.address - cf.start:x}"),
            Text(f"0x{instr.address:x}"),
            Text(text),
            style=style,
        )
    return table


def network_table(report: AnalysisReport) -> Table | None:
    if not report.network_interfaces:
        return None
    table = Table(
        title=f"Live Network Interfaces (captured: crash involved {report.network_capture_reason}())"
    )
    table.add_column("Interface")
    table.add_column("Flags")
    table.add_column("Addresses")
    for iface in report.network_interfaces:
        style = "yellow bold" if iface.is_point_to_point else None
        name = iface.name + ("  [POINTOPOINT]" if iface.is_point_to_point else "")
        table.add_row(
            Text(name, style=style),
            Text(",".join(iface.flags), style=style),
            Text("\n".join(iface.addresses), style=style),
        )
    return table


def backtrace_table(report: AnalysisReport) -> Table:
    table = Table(title=f"Backtrace (source: {report.backtrace_source})")
    table.add_column("#", justify="right")
    table.add_column("Address", justify="right")
    table.add_column("Function")
    table.add_column("Location / Module")
    for f in report.backtrace:
        loc = f.location or f.module or ""
        addr = f"0x{f.address:x}" if f.address is not None else ""
        # Function names (esp. demangled C++, e.g. "vector<int>::operator[]")
        # and paths are plain text, not markup - see disasm_table.
        table.add_row(Text(str(f.index)), Text(addr), Text(f.function), Text(loc))
    return table


def notes_panel(report: AnalysisReport) -> Panel | None:
    if not report.notes:
        return None
    body = Text("\n".join(f"- {n}" for n in report.notes))
    return Panel(body, title="Notes", border_style="magenta")


def commands_panel(report: AnalysisReport) -> Panel | None:
    if not report.commands_used:
        return None
    body = Text("\n".join(report.commands_used), style="dim")
    return Panel(body, title="Commands used (rerun manually if needed)", border_style="grey50")


def journal_context_panel(report: AnalysisReport, limit: int = 20) -> Panel | None:
    if not report.journal_context:
        return None
    ctx = Text("\n".join(report.journal_context[-limit:]))
    return Panel(ctx, title="Journal context (before crash)", border_style="grey50")


def render(report: AnalysisReport, console: Console) -> None:
    console.print(header_panel(report))

    fp = fault_panel(report)
    if fp:
        console.print(fp)

    dt = disasm_table(report)
    if dt:
        console.print(dt)

    cft = crash_function_table(report)
    if cft:
        console.print(cft)

    cp = recent_calls_panel(report)
    if cp:
        console.print(cp)

    nt = network_table(report)
    if nt:
        console.print(nt)

    if report.backtrace:
        console.print(backtrace_table(report))
    else:
        console.print(Panel(Text("No backtrace available.", style="yellow")))

    jcp = journal_context_panel(report)
    if jcp:
        console.print(jcp)

    np = notes_panel(report)
    if np:
        console.print(np)

    cmp_ = commands_panel(report)
    if cmp_:
        console.print(cmp_)

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
