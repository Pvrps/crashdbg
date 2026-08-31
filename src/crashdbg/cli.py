"""crashdbg CLI - generic native-crash triage.

Pipeline (mirrors manual coredumpctl + journalctl + gdb triage):
  1. locate a coredump via coredumpctl (any match expression: PID, comm, exe path...)
  2. pull full metadata via `coredumpctl info`
  3. correlate the kernel's 'segfault at ...' line via journalctl, decode the
     page-fault error code generically
  4. disassemble the faulting instruction from the kernel's Code: hint
  5. scan backward from the fault for the nearest *imported* library call
     objdump can resolve via the binary's PLT/dynamic symbol table - this
     survives stripping, unlike .symtab, so it works with no debug info
  6. get a symbolized backtrace via gdb (falling back to coredumpctl's own
     embedded address-only backtrace if gdb/zstd are unavailable)
  7. render a report

No step assumes anything about which application crashed or why.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from . import backtrace, coredump, elf, imports, journal, report
from .disasm import disassemble_fault, parse_code_line
from .models import AnalysisReport

app = typer.Typer(
    name="crashdbg",
    help="Generic native crash triage: coredumpctl + journalctl + gdb, correlated automatically.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


@app.command("list")
def list_cmd(
    match: Annotated[
        list[str] | None,
        typer.Argument(help="Optional coredumpctl match expression(s) (PID, COMM, EXE path, ...)."),
    ] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", help="Max entries to show.")] = 20,
) -> None:
    """List recent coredumps (thin wrapper over `coredumpctl list`)."""
    if not coredump.available():
        err_console.print("[red]coredumpctl not found on PATH.[/]")
        raise typer.Exit(1)

    entries = coredump.list_coredumps(match, limit=limit)
    if not entries:
        console.print("[yellow]No matching coredumps found.[/]")
        raise typer.Exit(0)

    from rich.table import Table

    table = Table(title="Coredumps")
    table.add_column("PID", justify="right")
    table.add_column("Time")
    table.add_column("Signal", justify="right")
    table.add_column("Executable")
    table.add_column("Core")
    table.add_column("Size", justify="right")
    for e in entries:
        size = f"{e.size / 1e6:.1f} MB" if e.size else "-"
        table.add_row(
            str(e.pid),
            str(e.timestamp) if e.timestamp else "-",
            str(e.signal),
            e.exe or "-",
            e.corefile,
            size,
        )
    console.print(table)


@app.command("analyze")
def analyze_cmd(
    match: Annotated[
        list[str] | None,
        typer.Argument(
            help="coredumpctl match expression(s) identifying the crash "
            "(PID, COMM, EXE path, ...). Omit to analyze the most recent "
            "coredump on the system."
        ),
    ] = None,
    fault_window: Annotated[
        float,
        typer.Option(
            "--fault-window", help="Seconds around crash time to search for the kernel fault line."
        ),
    ] = 5.0,
    context_before: Annotated[
        float,
        typer.Option(
            "--context-before", help="Seconds of journal context to show before the crash."
        ),
    ] = 15.0,
    backtrace_enabled: Annotated[
        bool, typer.Option("--backtrace/--no-backtrace", help="Attempt a symbolized gdb backtrace.")
    ] = True,
    keep_core: Annotated[
        bool,
        typer.Option("--keep-core", help="Keep the decompressed core file instead of deleting it."),
    ] = False,
    call_scan_window: Annotated[
        int,
        typer.Option(
            "--call-scan-window",
            help="Bytes to disassemble backward from the fault when looking for the "
            "nearest resolvable imported library call.",
        ),
    ] = 0x4000,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the report as JSON instead of rich text.")
    ] = False,
) -> None:
    """Analyze a single crash end-to-end and print a triage report."""
    if not coredump.available():
        err_console.print("[red]coredumpctl not found on PATH.[/]")
        raise typer.Exit(1)

    commands_used: list[str] = []

    with console.status("Locating coredump...", spinner="dots"):
        entry = coredump.pick_latest(match)
    if entry is None:
        err_console.print("[red]No matching coredump found.[/]")
        raise typer.Exit(1)
    commands_used.append(f"coredumpctl list --json=short {' '.join(match or [])}".strip())

    with console.status("Reading coredump metadata...", spinner="dots"):
        info = coredump.get_info(str(entry.pid))
    commands_used.append(f"coredumpctl info --json=short {entry.pid}")

    rpt = AnalysisReport(coredump=info, commands_used=commands_used)
    exe_path = Path(info.executable) if info.executable else None

    # --- kernel fault correlation -----------------------------------
    if journal.available():
        with console.status("Correlating kernel journal...", spinner="dots"):
            fault, code_line = journal.find_kernel_fault(info.pid, info.timestamp, fault_window)
        rpt.kernel_fault = fault
        rpt.commands_used.append(
            f"journalctl -k -o json --since '{info.timestamp}' (±{fault_window}s)"
        )
        if fault is None:
            rpt.notes.append(
                f"No kernel fault line found for PID {info.pid} within ±{fault_window}s "
                "of the crash timestamp. Try a larger --fault-window, or this may not "
                "have been a page-fault-triggering signal."
            )
        elif code_line:
            code_bytes, fault_idx = parse_code_line(code_line)
            rpt.disasm = disassemble_fault(code_bytes, fault_idx)
            if not rpt.disasm:
                rpt.notes.append(
                    "Found kernel Code: bytes but capstone is unavailable to disassemble them."
                )
    else:
        rpt.notes.append("journalctl not found on PATH; skipped kernel fault correlation.")

    # --- nearest resolvable library call before the fault ----------------
    if rpt.kernel_fault is not None:
        kf = rpt.kernel_fault
        if exe_path is not None and imports.available():
            file_vaddr = elf.fault_file_vaddr(exe_path, kf.ip, kf.module_ip_offset)
            if file_vaddr is None:
                rpt.notes.append(
                    "Could not determine the binary's ELF type (EXEC vs. PIE); skipped "
                    "nearest-import-call scan since the file-relative fault address is unknown."
                )
            else:
                with console.status(
                    "Scanning for nearest imported library call...", spinner="dots"
                ):
                    rpt.recent_calls = imports.find_recent_calls(
                        exe_path, file_vaddr, window=call_scan_window
                    )
                rpt.commands_used.append(
                    f"objdump -d -M intel --start-address=0x{max(file_vaddr - call_scan_window, 0):x} "
                    f"--stop-address=0x{file_vaddr:x} {exe_path}"
                )
                if not rpt.recent_calls:
                    rpt.notes.append(
                        f"No exactly-resolvable imported call found within "
                        f"{call_scan_window} bytes before the fault; try a larger --call-scan-window."
                    )
        elif not imports.available():
            rpt.notes.append("objdump not found on PATH; skipped nearest-import-call scan.")

    # --- journal context ----------------------------------------------
    if journal.available():
        with console.status("Gathering journal context...", spinner="dots"):
            rpt.journal_context = journal.context_around(
                info.timestamp, pid=info.pid, unit=info.unit, before_seconds=context_before
            )

    # --- backtrace -------------------------------------------------------
    if backtrace_enabled and info.filename is not None:
        exe_path = Path(info.executable) if info.executable else None
        try:
            with console.status(
                "Decompressing core and running gdb (this can take a while)...", spinner="dots"
            ):
                frames, source, kept, regs = backtrace.get_backtrace(
                    exe_path, info.filename, keep_core=keep_core
                )
            rpt.backtrace = frames
            rpt.backtrace_source = source
            rpt.kept_core_path = kept
            rpt.commands_used.append(f"zstd -d {info.filename}")
            rpt.commands_used.append(f"gdb -batch -ex bt -ex 'info registers' {exe_path} <core>")
            if regs and rpt.kernel_fault and regs.get("rip") not in (None, rpt.kernel_fault.ip):
                rpt.notes.append(
                    "Note: gdb's post-mortem $rip differs from the kernel's reported "
                    "fault ip; this can happen with signal-handler re-entry."
                )
            if not frames:
                rpt.notes.append(
                    "gdb ran but produced no parsable stack frames (binary may be fully stripped)."
                )
            elif sum(1 for f in frames if f.function == "??") > len(frames) / 2:
                rpt.notes.append(
                    "Binary appears to be stripped (no symbol table): function names "
                    "are unavailable and gdb's unwinder has no frame-pointer/CFI info to "
                    "work with, so frames near the end of the trace may be spurious. "
                    "Addresses are still valid offsets into the executable/module."
                )
        except backtrace.BacktraceError as e:
            rpt.notes.append(
                f"Symbolized backtrace unavailable ({e}); falling back to embedded address-only trace."
            )
            rpt.backtrace = backtrace.frames_from_coredump_message(info.message)
            rpt.backtrace_source = "coredump-message" if rpt.backtrace else "none"
    elif not backtrace_enabled:
        rpt.backtrace = backtrace.frames_from_coredump_message(info.message)
        rpt.backtrace_source = "coredump-message" if rpt.backtrace else "none"
    else:
        rpt.notes.append("No core file available on disk; skipped backtrace.")

    if json_output:
        # Bypass rich entirely for machine-readable output: rich's console
        # would interpret literal '[' / ']' in the JSON as markup tags and
        # soft-wrap long lines, corrupting the output.
        typer.echo(report.to_json(rpt))
    else:
        report.render(rpt, console)


def main() -> None:
    app()
