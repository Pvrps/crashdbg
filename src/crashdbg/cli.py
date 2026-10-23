"""crashdbg CLI - generic native-crash triage.

See pipeline.py for the actual analysis pipeline - this module is just
argument parsing plus picking a renderer (Rich report / JSON / TUI).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from . import coredump, report, ue_crash, wine
from .models import UnrealCrashReport
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
_UE_CRASH_OPT = typer.Option(
    "--ue-crash/--no-ue-crash",
    help="Look for a correlated Unreal Engine crash report (Steam compatdata "
    "Saved/Crashes/UECC-*) - covers Windows/Proton games whose crashes never "
    "produce a Linux coredump at all.",
)
_UE_CRASH_WINDOW_OPT = typer.Option(
    "--ue-crash-window",
    help="Seconds around the coredump's timestamp to search for a correlated "
    "Unreal Engine crash report.",
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


_IDENTIFY_OPT = typer.Option(
    "--identify/--no-identify",
    help="For Wine/Proton processes (wine-preloader, wineserver, ...) - which "
    "otherwise all look identical in this list regardless of which game they "
    "belong to - resolve the actual Windows-side program from its argv (one "
    "extra `coredumpctl info` lookup per Wine entry), and cross-reference "
    "Unreal Engine crash reports to show which game was affected.",
)
_IDENTIFY_WINDOW_OPT = typer.Option(
    "--identify-window",
    help="Seconds around each Wine entry's timestamp to search for a "
    "correlated Unreal Engine crash report, for --identify.",
)
_LIST_UE_CRASH_OPT = typer.Option(
    "--ue-crash/--no-ue-crash",
    help="Also list standalone Unreal Engine crash reports (Steam compatdata "
    "Saved/Crashes/UECC-*) that have no Linux coredump of their own - the "
    "common case for Windows/Proton games, whose crashes are native Windows "
    "SEH exceptions handled entirely inside Wine and never reach coredumpctl.",
)


def _ue_report_matches_tokens(rpt: UnrealCrashReport, tokens: list[str]) -> bool:
    """Simple case-insensitive substring filter for UE crash reports against
    `match` tokens - these are coredumpctl match expressions for the
    Coredumps table, but there's no coredumpctl entry to match here, so this
    just checks the report's game/executable name instead."""
    haystack = f"{rpt.game_name or ''} {rpt.executable_name or ''}".lower()
    return any(token.lower() in haystack for token in tokens)


@app.command("list")
def list_cmd(
    match: Annotated[
        list[str] | None,
        typer.Argument(help="Optional coredumpctl match expression(s) (PID, COMM, EXE path, ...)."),
    ] = None,
    limit: Annotated[int, typer.Option("-n", "--limit", help="Max entries to show.")] = 20,
    identify: Annotated[bool, _IDENTIFY_OPT] = True,
    identify_window: Annotated[float, _IDENTIFY_WINDOW_OPT] = 1800.0,
    ue_crash_enabled: Annotated[bool, _LIST_UE_CRASH_OPT] = True,
) -> None:
    """List recent coredumps (thin wrapper over `coredumpctl list`), plus
    any standalone Unreal Engine crash reports that never produced one."""
    have_coredumpctl = coredump.available()
    if not have_coredumpctl:
        err_console.print(
            "[yellow]coredumpctl not found on PATH; skipping coredump listing.[/]"
        )

    entries = coredump.list_coredumps(match, limit=limit) if have_coredumpctl else []

    # Parsed once up front (not per row) - see ue_crash.load_reports().
    need_ue_reports = (identify or ue_crash_enabled) and ue_crash.available()
    ue_reports = ue_crash.load_reports() if need_ue_reports else []
    # UE reports already shown as the "Game" column of a Coredumps row below
    # - tracked by identity so the standalone table further down doesn't
    # show the exact same crash a second time.
    matched_ue_ids: set[int] = set()

    from rich.table import Table

    if entries:
        table = Table(title="Coredumps")
        table.add_column("PID", justify="right")
        table.add_column("Time")
        table.add_column("Signal", justify="right")
        table.add_column("Process")
        table.add_column("Game")
        table.add_column("Core")
        table.add_column("Size", justify="right")
        for e in entries:
            process_label = e.exe or "-"
            game_label = "-"
            if identify and e.exe and wine.is_wine_process(e.exe):
                process_label = Path(e.exe).name
                info = None
                try:
                    info = coredump.get_info(str(e.pid))
                except coredump.CoredumpctlError:
                    pass
                target = wine.wine_target(info.command_line) if info else None
                if target:
                    process_label = f"{process_label} \u2192 {target}"
                if e.timestamp is not None and ue_reports:
                    nearest = ue_crash.nearest_report(
                        ue_reports, e.timestamp, window_seconds=identify_window
                    )
                    if nearest:
                        game_label = nearest.game_name or nearest.executable_name or "-"
                        matched_ue_ids.add(id(nearest))
            size = f"{e.size / 1e6:.1f} MB" if e.size else "-"
            table.add_row(
                str(e.pid),
                str(e.timestamp) if e.timestamp else "-",
                str(e.signal),
                process_label,
                game_label,
                e.corefile,
                size,
            )
        console.print(table)
    elif have_coredumpctl:
        console.print("[yellow]No matching coredumps found.[/]")

    standalone_ue: list[UnrealCrashReport] = []
    if ue_crash_enabled:
        if not ue_crash.available():
            if not entries:
                err_console.print(
                    "[yellow]No Steam installation found; skipped Unreal Engine crash reports.[/]"
                )
        else:
            standalone_ue = [r for r in ue_reports if id(r) not in matched_ue_ids]
            if match:
                standalone_ue = [r for r in standalone_ue if _ue_report_matches_tokens(r, match)]
            # datetime.min used purely as a naive sort-order sentinel for
            # reports with no recoverable time, never compared against an
            # aware datetime - consistent with this codebase's convention of
            # naive local datetimes throughout (see coredump._parse_timestamp).
            standalone_ue.sort(
                key=lambda r: ue_crash.report_time(r) or datetime.min,  # noqa: DTZ901
                reverse=True,
            )
            standalone_ue = standalone_ue[:limit]
            if standalone_ue:
                ue_table = Table(
                    title="Unreal Engine Crash Reports (no Linux coredump - common for "
                    "Windows/Proton games)"
                )
                ue_table.add_column("Time")
                ue_table.add_column("Game")
                ue_table.add_column("Executable")
                ue_table.add_column("Type")
                ue_table.add_column("Error")
                ue_table.add_column("Wine")
                for r in standalone_ue:
                    when = ue_crash.report_time(r)
                    kind, _kind_desc = ue_crash.describe_crash_type(r)
                    kind_style = "red bold" if kind == "Crash" else "yellow"
                    wine_label = (
                        "yes" if r.running_under_wine else ("no" if r.running_under_wine is False else "-")
                    )
                    ue_table.add_row(
                        str(when) if when else "-",
                        r.game_name or "-",
                        r.executable_name or "-",
                        Text(kind, style=kind_style),
                        r.error_message or "-",
                        wine_label,
                    )
                console.print(ue_table)
            elif not entries:
                console.print("[yellow]No standalone Unreal Engine crash reports found.[/]")

    if not entries and not standalone_ue:
        raise typer.Exit(0 if (have_coredumpctl or ue_crash.available()) else 1)


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
    ue_crash_enabled: Annotated[bool, _UE_CRASH_OPT] = True,
    ue_crash_window: Annotated[float, _UE_CRASH_WINDOW_OPT] = 1800.0,
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
        ue_crash_enabled=ue_crash_enabled,
        ue_crash_window=ue_crash_window,
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
    ue_crash_enabled: Annotated[bool, _UE_CRASH_OPT] = True,
    ue_crash_window: Annotated[float, _UE_CRASH_WINDOW_OPT] = 1800.0,
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
        ue_crash_enabled=ue_crash_enabled,
        ue_crash_window=ue_crash_window,
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
