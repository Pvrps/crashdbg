"""crashdbg CLI - generic native-crash triage.

See pipeline.py for the actual analysis pipeline - this module is just
argument parsing plus picking a renderer (Rich report / JSON / TUI).
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from . import coredump, report
from .pipeline import AnalysisOptions, NoCoredumpFound, run_analysis

app = typer.Typer(
    name="crashdbg",
    help="Generic native crash triage: coredumpctl + journalctl + gdb, correlated automatically.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

# Shared option definitions so --help stays identical across `analyze` and `tui`.
_MATCH_ARG = typer.Argument(
    help="coredumpctl match expression(s) identifying the crash "
    "(PID, COMM, EXE path, ...). Omit to analyze the most recent "
    "coredump on the system."
)
_FAULT_WINDOW_OPT = typer.Option(
    "--fault-window", help="Seconds around crash time to search for the kernel fault line."
)
_CONTEXT_BEFORE_OPT = typer.Option(
    "--context-before", help="Seconds of journal context to show before the crash."
)
_BACKTRACE_OPT = typer.Option(
    "--backtrace/--no-backtrace", help="Attempt a symbolized gdb backtrace."
)
_KEEP_CORE_OPT = typer.Option(
    "--keep-core", help="Keep the decompressed core file instead of deleting it."
)
_CALL_SCAN_WINDOW_OPT = typer.Option(
    "--call-scan-window",
    help="Bytes to disassemble backward from the fault when looking for the "
    "nearest resolvable imported library call.",
)
_SHOW_UNREACHABLE_OPT = typer.Option(
    "--show-unreachable-calls",
    help="Also show nearby imported calls that a backward control-flow check "
    "found on a branch that doesn't actually reach the fault (e.g. an untaken "
    "error-handling path) - hidden by default since they're usually noise.",
)
_FUNCTION_CONTEXT_OPT = typer.Option(
    "--function-context",
    help="Max instructions to show from the crashing function's disassembly, "
    "centered on the fault, if it's larger than this.",
)


def _no_match_message(match: list[str] | None) -> str:
    if not match:
        return "[red]No coredumps found on this system.[/] Crash a program first, or check `coredumpctl list`."
    searched = " ".join(match)
    return (
        f"[red]No coredump matches:[/] {searched!r}\n"
        "This is treated as a coredumpctl match expression (PID, COMM, or EXE path "
        "substring) - not a subcommand. Run [bold]`crashdbg list`[/] (or `just list`) "
        "to see what's available."
    )


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
    match: Annotated[list[str] | None, _MATCH_ARG] = None,
    fault_window: Annotated[float, _FAULT_WINDOW_OPT] = 5.0,
    context_before: Annotated[float, _CONTEXT_BEFORE_OPT] = 15.0,
    backtrace_enabled: Annotated[bool, _BACKTRACE_OPT] = True,
    keep_core: Annotated[bool, _KEEP_CORE_OPT] = False,
    call_scan_window: Annotated[int, _CALL_SCAN_WINDOW_OPT] = 0x4000,
    show_unreachable_calls: Annotated[bool, _SHOW_UNREACHABLE_OPT] = False,
    function_context: Annotated[int, _FUNCTION_CONTEXT_OPT] = 60,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the report as JSON instead of rich text.")
    ] = False,
) -> None:
    """Analyze a single crash end-to-end and print a triage report."""
    if not coredump.available():
        err_console.print("[red]coredumpctl not found on PATH.[/]")
        raise typer.Exit(1)

    options = AnalysisOptions(
        fault_window=fault_window,
        context_before=context_before,
        backtrace_enabled=backtrace_enabled,
        keep_core=keep_core,
        call_scan_window=call_scan_window,
        show_unreachable_calls=show_unreachable_calls,
        function_context=function_context,
    )
    try:
        rpt = run_analysis(match, options, console)
    except NoCoredumpFound:
        err_console.print(_no_match_message(match))
        raise typer.Exit(1) from None

    if json_output:
        # Bypass rich entirely for machine-readable output: rich's console
        # would interpret literal '[' / ']' in the JSON as markup tags and
        # soft-wrap long lines, corrupting the output.
        typer.echo(report.to_json(rpt))
    else:
        report.render(rpt, console)


@app.command("tui")
def tui_cmd(
    match: Annotated[list[str] | None, _MATCH_ARG] = None,
    fault_window: Annotated[float, _FAULT_WINDOW_OPT] = 5.0,
    context_before: Annotated[float, _CONTEXT_BEFORE_OPT] = 15.0,
    backtrace_enabled: Annotated[bool, _BACKTRACE_OPT] = True,
    keep_core: Annotated[bool, _KEEP_CORE_OPT] = False,
    call_scan_window: Annotated[int, _CALL_SCAN_WINDOW_OPT] = 0x4000,
    show_unreachable_calls: Annotated[bool, _SHOW_UNREACHABLE_OPT] = False,
    function_context: Annotated[int, _FUNCTION_CONTEXT_OPT] = 60,
) -> None:
    """Analyze a crash and explore it in an interactive full-screen TUI."""
    if not coredump.available():
        err_console.print("[red]coredumpctl not found on PATH.[/]")
        raise typer.Exit(1)

    options = AnalysisOptions(
        fault_window=fault_window,
        context_before=context_before,
        backtrace_enabled=backtrace_enabled,
        keep_core=keep_core,
        call_scan_window=call_scan_window,
        show_unreachable_calls=show_unreachable_calls,
        function_context=function_context,
    )
    try:
        rpt = run_analysis(match, options, console)
    except NoCoredumpFound:
        err_console.print(_no_match_message(match))
        raise typer.Exit(1) from None

    from .tui import CrashDbgApp

    CrashDbgApp(rpt).run()


def main() -> None:
    app()
