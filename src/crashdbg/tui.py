"""Interactive Textual TUI for exploring an AnalysisReport.

This is purely a presentation layer: it reuses the exact same Rich
renderables as the static report (report.py), just arranged into
scrollable tabs instead of one long vertical stack. Nothing here re-runs
or duplicates the analysis pipeline (see pipeline.py).
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import VerticalScroll
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from . import report
from .models import AnalysisReport
from .signals import decode_page_fault_error, describe_signal


def _bottom_line(rpt: AnalysisReport) -> str:
    """Synthesize a one-paragraph plain-English summary from everything
    the pipeline found, so the conclusion is the first thing shown instead
    of being buried after several tables."""
    cd = rpt.coredump
    name, desc = describe_signal(cd.signal)
    lines = [
        (
            f"{cd.executable or cd.command or '?'} (PID {cd.pid}) crashed with "
            f"{cd.signal_name or name} (signal {cd.signal}): {desc}"
        )
    ]

    if rpt.kernel_fault:
        kf = rpt.kernel_fault
        err = decode_page_fault_error(kf.error)
        addr_desc = "a NULL pointer" if kf.fault_addr == 0 else f"address 0x{kf.fault_addr:x}"
        lines.append(f"Fault: {err.summary} at {addr_desc}.")

    if rpt.crash_function:
        cf = rpt.crash_function
        lines.append(
            f"This happened in {cf.label}, a {cf.end - cf.start}-byte function recovered "
            f"from .eh_frame with no symbols needed, at offset +0x{cf.fault_offset:x}."
        )

    reachable = [c for c in rpt.recent_calls if c.reachable]
    if reachable:
        nearest = reachable[0]
        lines.append(
            f"{nearest.distance_bytes} bytes earlier on the executed path, the code called "
            f"{nearest.symbol}()."
        )

    if rpt.network_capture_reason and any(i.is_point_to_point for i in rpt.network_interfaces):
        pp = [i.name for i in rpt.network_interfaces if i.is_point_to_point]
        lines.append(
            f"A POINTOPOINT interface is currently up ({', '.join(pp)}) - the kernel "
            "legitimately returns a NULL ifa_addr for such interfaces, a well-known source "
            f"of NULL-deref crashes in callers of {rpt.network_capture_reason}() that don't "
            "check for it."
        )

    if not rpt.kernel_fault and not rpt.crash_function:
        lines.append(
            "Limited detail available for this crash - see the Raw tab for notes on what "
            "could and couldn't be determined."
        )

    return "\n\n".join(lines)


class CrashDbgApp(App[None]):
    """Full-screen tabbed crash triage explorer."""

    TITLE = "crashdbg"
    CSS = """
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        padding: 0;
    }
    VerticalScroll {
        height: 1fr;
        padding: 1 1;
    }
    #overview-text {
        padding: 1 2;
        border: round $primary;
        margin-bottom: 1;
    }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("1", "show_tab('overview')", "Overview"),
        Binding("2", "show_tab('crash-site')", "Crash Site"),
        Binding("3", "show_tab('backtrace')", "Backtrace"),
        Binding("4", "show_tab('environment')", "Environment"),
        Binding("5", "show_tab('raw')", "Raw"),
        Binding("q", "quit", "Quit"),
        Binding("s", "save_screenshot", "Screenshot"),
    ]

    def __init__(self, rpt: AnalysisReport) -> None:
        super().__init__()
        self.rpt = rpt
        cd = rpt.coredump
        self.sub_title = f"{cd.executable or cd.command or '?'} (PID {cd.pid})"

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"), VerticalScroll():
                yield Static(_bottom_line(self.rpt), id="overview-text")
                yield Static(report.header_panel(self.rpt))
                fp = report.fault_panel(self.rpt)
                if fp:
                    yield Static(fp)

            with TabPane("Crash Site", id="crash-site"), VerticalScroll():
                dt = report.disasm_table(self.rpt)
                if dt:
                    yield Static(dt)
                cft = report.crash_function_table(self.rpt)
                if cft:
                    yield Static(cft)
                cp = report.recent_calls_panel(self.rpt)
                if cp:
                    yield Static(cp)
                if not (dt or cft or cp):
                    yield Static("No crash-site detail available - see the Raw tab for notes.")

            with TabPane("Backtrace", id="backtrace"), VerticalScroll():
                if self.rpt.backtrace:
                    yield Static(report.backtrace_table(self.rpt))
                else:
                    yield Static("No backtrace available.")

            with TabPane("Environment", id="environment"), VerticalScroll():
                nt = report.network_table(self.rpt)
                if nt:
                    yield Static(nt)
                jcp = report.journal_context_panel(self.rpt, limit=100)
                if jcp:
                    yield Static(jcp)
                if not (nt or jcp):
                    yield Static("No environment context available.")

            with TabPane("Raw", id="raw"), VerticalScroll():
                np = report.notes_panel(self.rpt)
                if np:
                    yield Static(np)
                cmdp = report.commands_panel(self.rpt)
                if cmdp:
                    yield Static(cmdp)
                if self.rpt.kept_core_path:
                    yield Static(f"Decompressed core kept at: {self.rpt.kept_core_path}")
        yield Footer()

    def action_show_tab(self, tab: str) -> None:
        self.get_child_by_type(TabbedContent).active = tab

    def action_save_screenshot(self) -> None:
        path = self.save_screenshot()
        self.notify(f"Saved screenshot: {path}")
