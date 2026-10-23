"""Discovers and parses Unreal Engine's own crash reporter output
(Saved/Crashes/UECC-*/CrashContext.runtime-xml), found inside Steam Proton
compatdata prefixes (Windows builds) or directly under steamapps/common
(native Linux builds).

This exists because a huge fraction of "the game just crashed" reports
involve a Windows game running under Wine/Proton whose crash is a native
Windows SEH exception, caught and handled entirely inside Wine itself - it
never becomes a Linux signal, so it never produces a coredump for
coredumpctl to see. Unreal Engine's own crash reporter (CrashReportClient)
does catch it though, and writes a full report to disk independently of
whatever (if anything) coredumpctl found.

Nothing here is specific to any particular game - only to the on-disk
layout Unreal Engine itself uses for every UE3/4/5 title, and to Steam's
own directory conventions for Proton compatdata / library folders.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import UnrealCallFrame, UnrealCrashReport, UnrealThread

# UE's FDateTime (used for <TimeOfCrash>) counts 100ns ticks since
# 0001-01-01 - the same epoch and resolution as .NET's DateTime.Ticks, *not*
# the Win32 FILETIME epoch (1601) despite both being Windows-flavoured.
_UE_TICKS_EPOCH = datetime(1, 1, 1, tzinfo=UTC)

# "<ModuleName> 0x<base> + <offset>" - the module-relative address format
# Unreal's crash reporter always uses for callstacks in Shipping builds,
# which are stripped and have no symbol server involved.
_CALLSTACK_LINE_RE = re.compile(
    r"^(?P<module>\S+)\s+0x[0-9a-fA-F]+\s*\+\s*(?P<offset>[0-9a-fA-F]+)$"
)

_VDF_PATH_RE = re.compile(r'"path"\s+"(?P<path>[^"]+)"')

_DEFAULT_STEAM_ROOTS = [
    Path.home() / ".local/share/Steam",
    Path.home() / ".steam/steam",
    Path.home() / ".steam/root",
    Path.home() / ".var/app/com.valvesoftware.Steam/data/Steam",  # Flatpak
]


def available() -> bool:
    """Whether any Steam installation (hence a potential compatdata tree)
    could be found at all."""
    return bool(_steam_roots())


def _steam_roots() -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()
    for base in _DEFAULT_STEAM_ROOTS:
        if not base.is_dir():
            continue
        resolved = base.resolve()
        if resolved not in seen:
            seen.add(resolved)
            roots.append(base)
    # Additional Steam library folders (SD cards, second drives, ...),
    # recorded in libraryfolders.vdf next to each main install found above.
    for root in list(roots):
        for path in _parse_library_folders(root / "steamapps" / "libraryfolders.vdf"):
            if not path.is_dir():
                continue
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                roots.append(path)
    return roots


def _parse_library_folders(vdf_path: Path) -> list[Path]:
    try:
        text = vdf_path.read_text(errors="replace")
    except OSError:
        return []
    return [Path(m.group("path")) for m in _VDF_PATH_RE.finditer(text)]


def find_report_dirs(roots: list[Path] | None = None) -> list[Path]:
    """Every UECC-* crash report directory found across all known Steam
    libraries - both inside Proton compatdata prefixes (Windows builds)
    and directly under steamapps/common (native Linux builds)."""
    search_roots = roots if roots is not None else _steam_roots()
    found: list[Path] = []
    for root in search_roots:
        steamapps = root / "steamapps"
        found.extend(
            (steamapps / "compatdata").glob(
                "*/pfx/drive_c/users/*/AppData/Local/*/Saved/Crashes/UECC-*"
            )
        )
        found.extend((steamapps / "common").glob("*/**/Saved/Crashes/UECC-*"))
    return [d for d in found if (d / "CrashContext.runtime-xml").is_file()]


def _text(el: ET.Element | None, tag: str) -> str | None:
    if el is None:
        return None
    child = el.find(tag)
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def _bool(el: ET.Element | None, tag: str) -> bool:
    return (_text(el, tag) or "").lower() in ("true", "1")


def _bool_or_none(el: ET.Element | None, tag: str) -> bool | None:
    text = _text(el, tag)
    return text.lower() in ("true", "1") if text is not None else None


def _int(el: ET.Element | None, tag: str) -> int | None:
    text = _text(el, tag)
    try:
        return int(text) if text is not None else None
    except ValueError:
        return None


def _parse_callstack(raw: str | None) -> list[UnrealCallFrame]:
    if not raw:
        return []
    frames = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _CALLSTACK_LINE_RE.match(line)
        if m:
            frames.append(
                UnrealCallFrame(
                    module=m.group("module"), offset=int(m.group("offset"), 16), raw=line
                )
            )
        else:
            frames.append(UnrealCallFrame(module="?", offset=0, raw=line))
    return frames


def _parse_time_of_crash(rp: ET.Element) -> datetime | None:
    ticks = _int(rp, "TimeOfCrash")
    if ticks is None:
        return None
    try:
        utc = _UE_TICKS_EPOCH + timedelta(microseconds=ticks / 10)
        local = utc.astimezone()
    except (OverflowError, OSError, ValueError):
        return None
    # Naive local time, to match every other timestamp crashdbg deals with
    # (coredumpctl/journalctl timestamps are all naive local wall-clock
    # datetimes - see coredump.py's _parse_timestamp).
    return local.replace(tzinfo=None)


def _parse_threads(rp: ET.Element) -> list[UnrealThread]:
    threads_el = rp.find("Threads")
    if threads_el is None:
        return []
    threads = []
    for t in threads_el.findall("Thread"):
        threads.append(
            UnrealThread(
                thread_id=_int(t, "ThreadID") or 0,
                name=_text(t, "ThreadName") or "?",
                is_crashed=_bool(t, "IsCrashed"),
                callstack=[f.raw for f in _parse_callstack(_text(t, "CallStack"))],
            )
        )
    return threads


def parse_report(report_dir: Path) -> UnrealCrashReport | None:
    """Parse a single UECC-* directory's CrashContext.runtime-xml. Returns
    None if the file is missing/malformed rather than raising - a crash
    report we can't parse should never prevent crashdbg's normal coredump
    analysis from being shown."""
    xml_path = report_dir / "CrashContext.runtime-xml"
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return None

    rp = root.find("RuntimeProperties")
    if rp is None:
        return None
    ed = root.find("EngineData")
    pp = root.find("PlatformProperties")

    seconds_raw = _text(rp, "SecondsSinceStart")
    minidump = report_dir / "UEMinidump.dmp"

    return UnrealCrashReport(
        report_dir=report_dir,
        crash_guid=_text(rp, "CrashGUID"),
        crash_type=_text(rp, "CrashType"),
        is_ensure=_bool(rp, "IsEnsure"),
        is_assert=_bool(rp, "IsAssert"),
        is_stall=_bool(rp, "IsStall"),
        error_message=_text(rp, "ErrorMessage") or "",
        game_name=_text(rp, "GameName"),
        executable_name=_text(rp, "ExecutableName"),
        build_configuration=_text(rp, "BuildConfiguration"),
        engine_version=_text(rp, "EngineVersion"),
        platform_full_name=_text(rp, "PlatformFullName"),
        running_under_wine=_bool_or_none(pp, "PlatformIsRunningWine"),
        process_id=_int(rp, "ProcessId"),
        seconds_since_start=float(seconds_raw) if seconds_raw is not None else None,
        crash_time=_parse_time_of_crash(rp),
        cpu_brand=_text(rp, "Misc.CPUBrand") or _text(rp, "CPUBrand"),
        num_cores=_int(rp, "Misc.NumberOfCores"),
        total_physical_gb=_int(rp, "MemoryStats.TotalPhysicalGB"),
        is_oom=_bool(rp, "MemoryStats.bIsOOM"),
        gpu_adapter_name=_text(ed, "RHI.AdapterName") or _text(rp, "Misc.PrimaryGPUBrand"),
        gpu_vendor=_text(ed, "RHI.GPUVendor"),
        gpu_driver_version=_text(ed, "RHI.UserDriverVersion"),
        gpu_driver_date=_text(ed, "RHI.DriverDate"),
        rhi_name=_text(ed, "RHI.RHIName"),
        rhi_feature_level=_text(ed, "RHI.FeatureLevel"),
        is_with_debug_info=_bool_or_none(rp, "IsWithDebugInfo"),
        callstack=_parse_callstack(_text(rp, "PCallStack")),
        threads=_parse_threads(rp),
        minidump_path=minidump if minidump.is_file() else None,
    )


def report_time(rpt: UnrealCrashReport) -> datetime | None:
    """The effective timestamp of a UE crash report: its recorded
    <TimeOfCrash> if present, else the report file's mtime as a fallback
    for engine versions that don't record it. Public so callers outside
    this module (pipeline.py) can compare a report's recency against
    other crash sources (e.g. coredumpctl timestamps) without duplicating
    this fallback logic."""
    if rpt.crash_time is not None:
        return rpt.crash_time
    try:
        return datetime.fromtimestamp((rpt.report_dir / "CrashContext.runtime-xml").stat().st_mtime)  # noqa: DTZ006
    except OSError:
        return None




def load_reports(roots: list[Path] | None = None) -> list[UnrealCrashReport]:
    """Parse every discoverable UE crash report once. Callers doing more
    than one time-based lookup (e.g. `crashdbg list`, matching a whole
    page of coredumps against the same report set) should call this once
    and reuse the result via nearest_report() rather than re-scanning the
    filesystem and re-parsing XML for every row."""
    reports = []
    for report_dir in find_report_dirs(roots):
        rpt = parse_report(report_dir)
        if rpt is not None:
            reports.append(rpt)
    return reports


def nearest_report(
    reports: list[UnrealCrashReport], when: datetime, window_seconds: float | None = None
) -> UnrealCrashReport | None:
    """The report in `reports` whose recorded crash time is closest to
    `when`, optionally bounded to within `window_seconds` in either
    direction."""
    best: tuple[float, UnrealCrashReport] | None = None
    for rpt in reports:
        report_when = report_time(rpt)
        if report_when is None:
            continue
        delta = abs((report_when - when).total_seconds())
        if window_seconds is not None and delta > window_seconds:
            continue
        if best is None or delta < best[0]:
            best = (delta, rpt)
    return best[1] if best else None


def find_correlated_report(
    crash_time: datetime, window_seconds: float, roots: list[Path] | None = None
) -> UnrealCrashReport | None:
    """The UE crash report whose recorded crash time is closest to
    `crash_time` (typically a coredumpctl timestamp), if within
    `window_seconds` in either direction. Falls back to each report
    directory's mtime for engine versions that don't record <TimeOfCrash>."""
    return nearest_report(load_reports(roots), crash_time, window_seconds)


def find_most_recent_report(roots: list[Path] | None = None) -> UnrealCrashReport | None:
    """The single most recent UE crash report system-wide, regardless of
    any coredump - used as a last-resort fallback when no coredump exists
    at all (routine for Windows/Proton games) or when nothing correlates
    within the requested time window."""
    best: tuple[datetime, UnrealCrashReport] | None = None
    for rpt in load_reports(roots):
        when = report_time(rpt)
        if when is None:
            continue
        if best is None or when > best[0]:
            best = (when, rpt)
    return best[1] if best else None


def describe_crash_type(rpt: UnrealCrashReport) -> tuple[str, str]:
    """Classify Unreal Engine's crash-report categories - only 'Crash' is
    guaranteed to have actually terminated the process."""
    if rpt.is_assert:
        return (
            "Assert",
            (
                "A check()/checkf() programmer assertion failed - an engine/game "
                "invariant was violated. Always fatal."
            ),
        )
    if rpt.is_ensure:
        return (
            "Ensure",
            (
                "An ensure()/ensureMsgf() failed - logged as an error but the game "
                "keeps running (non-fatal). This is *not* why the game closed unless "
                "a separate crash followed it."
            ),
        )
    if rpt.is_stall:
        return (
            "Stall",
            (
                "The engine's hang detector fired - a thread (often the game or "
                "render thread) didn't respond for too long. The game may have "
                "appeared frozen rather than crashed outright."
            ),
        )
    return (rpt.crash_type or "Crash", "An unhandled exception terminated the process.")
