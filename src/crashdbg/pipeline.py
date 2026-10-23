"""The core crash-analysis pipeline, shared by every presentation layer
(the Rich report, --json, and the interactive TUI). Each of those is just
a different renderer over the same AnalysisReport produced here - none of
this module knows or cares how its result will be displayed.

Pipeline (mirrors manual coredumpctl + journalctl + gdb triage):
  1. locate a coredump via coredumpctl (any match expression: PID, comm, exe path...)
  2. pull full metadata via `coredumpctl info`
  3. correlate the kernel's 'segfault at ...' line via journalctl, decode the
     page-fault error code generically
  4. disassemble the faulting instruction from the kernel's Code: hint
  5. recover the crashing function's exact boundaries from .eh_frame (C++
     exception-unwinding metadata every GCC/Clang binary emits - survives
     stripping just like the PLT does) and disassemble the whole thing
  6. scan backward from the fault for the nearest *imported* library call
     objdump can resolve via the binary's PLT/dynamic symbol table - this
     survives stripping, unlike .symtab, so it works with no debug info
  7. if the nearest resolved call is a network-interface-enumeration
     function (getifaddrs & family), snapshot live interface state and
     flag anything with the POINTOPOINT flag - the documented condition
     under which the kernel returns a NULL ifa_addr, a common crash cause
  8. get a symbolized backtrace via gdb (falling back to coredumpctl's own
     embedded address-only backtrace if gdb/zstd are unavailable)

No step assumes anything about which application crashed or why.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from . import (
    backtrace,
    coredump,
    elf,
    functions,
    imports,
    journal,
    netstate,
    objdump_disasm,
    ue_crash,
    wine,
)
from .disasm import disassemble_fault, parse_code_line
from .models import AnalysisReport, CrashFunction


class NoCoredumpFound(RuntimeError):
    """No coredump matched the given match expression(s), and no fallback
    Unreal Engine crash report was found either."""


@dataclass
class AnalysisOptions:
    fault_window: float = 5.0
    context_before: float = 15.0
    backtrace_enabled: bool = True
    keep_core: bool = False
    call_scan_window: int = 0x4000
    show_unreachable_calls: bool = False
    function_context: int = 60
    ue_crash_enabled: bool = True
    ue_crash_window: float = 1800.0


def run_analysis(
    match: list[str] | None, options: AnalysisOptions, console: Console
) -> AnalysisReport:
    """Run the full pipeline and return the resulting report. Progress
    spinners are printed to `console` while the pipeline runs. Raises
    NoCoredumpFound if no matching coredump exists."""
    commands_used: list[str] = []

    with console.status("Locating coredump...", spinner="dots"):
        entry = coredump.pick_latest(match)

    # Windows/Proton games' crashes are frequently native Windows SEH
    # exceptions, handled entirely inside Wine, and never produce a Linux
    # signal/coredump at all - Unreal Engine's own crash reporter may still
    # have caught it though. Only relevant when no specific match was
    # requested (a match expression is inherently coredumpctl-specific, so
    # there's nothing sensible to fall back to if the user asked for one
    # and it didn't exist).
    #
    # Crucially, this has to compare *timestamps*, not just "does any
    # coredump exist at all": on any system that's been used for a while,
    # some old, unrelated coredump (from a completely different program)
    # will almost always still be sitting around, and would otherwise
    # permanently shadow a brand new UE-only crash that has no coredump of
    # its own - defeating this fallback in exactly the case it exists for.
    if not match and options.ue_crash_enabled:
        with console.status(
            "Checking for a more recent Unreal Engine crash report...", spinner="dots"
        ):
            ue = ue_crash.find_most_recent_report() if ue_crash.available() else None
        ue_time = ue_crash.report_time(ue) if ue is not None else None
        ue_is_newer = ue_time is not None and (
            entry is None or entry.timestamp is None or ue_time > entry.timestamp
        )
        if ue_is_newer:
            note = (
                "No Linux coredump was found on this system, but an Unreal Engine "
                "crash report was."
                if entry is None
                else (
                    "The most recent Unreal Engine crash report is newer than the "
                    "most recent Linux coredump on this system, so it's shown here "
                    "instead - the coredump is almost certainly from an unrelated "
                    "crash."
                )
            ) + (
                " This is typical for Windows/Proton games: their crashes are "
                "native Windows SEH exceptions, handled entirely inside Wine, and "
                "never produce a Linux coredump for coredumpctl to see."
            )
            return AnalysisReport(
                coredump=None,
                unreal_crash=ue,
                unreal_crash_correlated=False,
                notes=[note],
                commands_used=[
                    "(scanned Steam compatdata for Saved/Crashes/UECC-*; no coredumpctl match)"
                ],
            )

    if entry is None:
        raise NoCoredumpFound
    commands_used.append(f"coredumpctl list --json=short {' '.join(match or [])}".strip())

    with console.status("Reading coredump metadata...", spinner="dots"):
        info = coredump.get_info(str(entry.pid))
    commands_used.append(f"coredumpctl info --json=short {entry.pid}")

    rpt = AnalysisReport(coredump=info, commands_used=commands_used)
    exe_path = Path(info.executable) if info.executable else None

    # --- correlated Unreal Engine crash report ----------------------------
    # Only attempted for coredumps that are actually Wine/Proton processes
    # (wine-preloader, wineserver, ...) - a Windows/Proton game's *actual*
    # crash frequently leaves no trace in this coredump at all (see above),
    # so even a harmless, early SIGSYS from a wine-preloader helper during
    # Proton bootstrap is worth correlating against. But a coredump from an
    # unrelated native Linux process (a browser, OBS, ...) has no possible
    # connection to any Windows game's crash report no matter how close in
    # time the two happen to be - attempting correlation there produces
    # confident-looking but meaningless matches.
    is_wine_coredump = exe_path is not None and wine.is_wine_process(str(exe_path))
    if options.ue_crash_enabled and is_wine_coredump:
        if ue_crash.available():
            with console.status("Checking for Unreal Engine crash reports...", spinner="dots"):
                ue = ue_crash.find_correlated_report(info.timestamp, options.ue_crash_window)
                correlated = ue is not None
                if ue is None:
                    ue = ue_crash.find_most_recent_report()
            rpt.unreal_crash = ue
            rpt.unreal_crash_correlated = correlated
            if ue is not None:
                rpt.commands_used.append(
                    "(scanned Steam compatdata for Saved/Crashes/UECC-* "
                    f"within \u00b1{options.ue_crash_window:.0f}s of {info.timestamp})"
                )
                if correlated and ue.crash_time is not None:
                    delta = (ue.crash_time - info.timestamp).total_seconds()
                    rpt.notes.append(
                        f"Correlated Unreal Engine crash report found ~{abs(delta):.0f}s "
                        f"{'after' if delta >= 0 else 'before'} this coredump's timestamp "
                        "(nearest-in-time heuristic - verify it's from the same play "
                        "session if in doubt)."
                    )
                elif not correlated:
                    rpt.notes.append(
                        "No Unreal Engine crash report found within "
                        f"\u00b1{options.ue_crash_window:.0f}s of this coredump; showing "
                        "the most recent one found system-wide instead, which may be "
                        "unrelated to this particular coredump."
                    )
        else:
            rpt.notes.append(
                "No Steam installation found; skipped Unreal Engine crash-report correlation."
            )

    # --- kernel fault correlation -----------------------------------
    if journal.available():
        with console.status("Correlating kernel journal...", spinner="dots"):
            fault, code_line = journal.find_kernel_fault(
                info.pid, info.timestamp, options.fault_window
            )
        rpt.kernel_fault = fault
        rpt.commands_used.append(
            f"journalctl -k -o json --since '{info.timestamp}' (±{options.fault_window}s)"
        )
        if fault is None:
            rpt.notes.append(
                f"No kernel fault line found for PID {info.pid} within "
                f"±{options.fault_window}s of the crash timestamp. Try a larger "
                "--fault-window, or this may not have been a page-fault-triggering signal."
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

    # --- file-relative fault address (needed by both steps below) --------
    file_vaddr: int | None = None
    if rpt.kernel_fault is not None and exe_path is not None:
        kf = rpt.kernel_fault
        file_vaddr = elf.fault_file_vaddr(exe_path, kf.ip, kf.module_ip_offset)
        if file_vaddr is None:
            rpt.notes.append(
                "Could not determine the binary's ELF type (EXEC vs. PIE); skipped "
                "function-boundary recovery and nearest-import-call scan since the "
                "file-relative fault address is unknown."
            )

    # --- crashing function recovery via .eh_frame (no symbols needed) ----
    if file_vaddr is not None and exe_path is not None:
        if functions.available():
            with console.status(
                "Recovering crashing function bounds (.eh_frame)...", spinner="dots"
            ):
                bounds = functions.find_function_bounds(exe_path, file_vaddr)
            rpt.commands_used.append(f"readelf --debug-dump=frames {exe_path}")
            if bounds is None:
                rpt.notes.append(
                    "No .eh_frame entry covers the fault address (function may lack "
                    "unwind info); the nearest-import-call scan will use a fixed-size "
                    "window instead of the exact function bounds."
                )
            else:
                start, end = bounds
                with console.status("Disassembling crashing function...", spinner="dots"):
                    instrs = objdump_disasm.disassemble_range(exe_path, start, end)
                rpt.commands_used.append(
                    f"objdump -d -M intel --start-address=0x{start:x} "
                    f"--stop-address=0x{end:x} {exe_path}"
                )
                truncated = False
                if len(instrs) > options.function_context:
                    fault_idx = next(
                        (i for i, ins in enumerate(instrs) if ins.address == file_vaddr), None
                    )
                    if fault_idx is not None:
                        before = options.function_context * 2 // 3
                        after = options.function_context - before
                        lo = max(fault_idx - before, 0)
                        hi = min(fault_idx + after + 1, len(instrs))
                        instrs = instrs[lo:hi]
                        truncated = True
                rpt.crash_function = CrashFunction(
                    start=start,
                    end=end,
                    label=functions.synthetic_label(start),
                    fault_offset=file_vaddr - start,
                    instructions=instrs,
                    truncated=truncated,
                )
        else:
            rpt.notes.append("readelf not found on PATH; skipped function-boundary recovery.")

    # --- nearest resolvable library call before the fault ----------------
    if file_vaddr is not None and exe_path is not None:
        if imports.available():
            effective_window = options.call_scan_window
            if rpt.crash_function is not None:
                effective_window = file_vaddr - rpt.crash_function.start
            with console.status("Scanning for nearest imported library call...", spinner="dots"):
                all_calls = imports.find_recent_calls(exe_path, file_vaddr, window=effective_window)
            rpt.commands_used.append(
                f"objdump -d -M intel --start-address=0x{max(file_vaddr - effective_window, 0):x} "
                f"--stop-address=0x{file_vaddr:x} {exe_path}"
            )
            if options.show_unreachable_calls:
                rpt.recent_calls = all_calls
            else:
                rpt.recent_calls = [c for c in all_calls if c.reachable]
                hidden = len(all_calls) - len(rpt.recent_calls)
                if hidden:
                    rpt.notes.append(
                        f"{hidden} nearby imported call(s) hidden: a backward control-flow "
                        "check found them on a branch that doesn't reach the fault (e.g. an "
                        "untaken error-handling path). Use --show-unreachable-calls to see them."
                    )
            if not all_calls:
                rpt.notes.append(
                    f"No exactly-resolvable imported call found within "
                    f"{effective_window} bytes before the fault; try a larger --call-scan-window."
                )
        else:
            rpt.notes.append("objdump not found on PATH; skipped nearest-import-call scan.")

    # --- network-interface state, only if the crash involved that API ----
    matched_fn = next(
        (c.symbol for c in rpt.recent_calls if c.symbol in netstate.INTERFACE_ENUM_FUNCTIONS),
        None,
    )
    if matched_fn is not None:
        if netstate.available():
            with console.status("Capturing live network interface state...", spinner="dots"):
                rpt.network_interfaces = netstate.capture_interfaces()
            rpt.network_capture_reason = matched_fn
            rpt.commands_used.append("ip -j addr show")
            if any(i.is_point_to_point for i in rpt.network_interfaces):
                rpt.notes.append(
                    f"The crash involved {matched_fn}(), and a POINTOPOINT interface is "
                    "currently up (see 'Live Network Interfaces' below). The kernel legitimately "
                    "returns a NULL ifa_addr for such interfaces' AF_PACKET entry, which is a "
                    "well-known source of NULL-deref crashes in callers that don't check for it."
                )
        else:
            rpt.notes.append(
                f"The crash involved {matched_fn}(), but 'ip' is not on PATH; "
                "skipped live network-interface capture."
            )

    # --- journal context ----------------------------------------------
    if journal.available():
        with console.status("Gathering journal context...", spinner="dots"):
            rpt.journal_context = journal.context_around(
                info.timestamp, pid=info.pid, unit=info.unit, before_seconds=options.context_before
            )

    # --- backtrace -------------------------------------------------------
    if options.backtrace_enabled and info.filename is not None:
        try:
            with console.status(
                "Decompressing core and running gdb (this can take a while)...", spinner="dots"
            ):
                frames, source, kept, regs = backtrace.get_backtrace(
                    exe_path, info.filename, keep_core=options.keep_core
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
    elif not options.backtrace_enabled:
        rpt.backtrace = backtrace.frames_from_coredump_message(info.message)
        rpt.backtrace_source = "coredump-message" if rpt.backtrace else "none"
    else:
        rpt.notes.append("No core file available on disk; skipped backtrace.")

    return rpt
