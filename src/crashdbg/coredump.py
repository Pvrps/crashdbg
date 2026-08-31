"""Thin wrapper around `coredumpctl`. All matching/filtering logic is
delegated to coredumpctl itself (PID, COMM, EXE path, etc.) - this module
never hardcodes what a "match" looks like, it just passes tokens through.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from .models import CoredumpEntry, CoredumpInfo


class CoredumpctlError(RuntimeError):
    pass


def available() -> bool:
    return shutil.which("coredumpctl") is not None


def _run_json(args: list[str]) -> str:
    proc = subprocess.run(
        ["coredumpctl", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise CoredumpctlError(
            f"coredumpctl {' '.join(args)} failed (exit {proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout


def _parse_timestamp(value: int | None) -> datetime | None:
    if value is None:
        return None
    # systemd JSON timestamps are microseconds since the Unix epoch. Kept as
    # a naive local-time datetime intentionally: it's fed straight back into
    # `journalctl --since/--until`, which expects local wall-clock strings.
    return datetime.fromtimestamp(value / 1_000_000)  # noqa: DTZ006


def list_coredumps(
    matches: list[str] | None = None, limit: int | None = None
) -> list[CoredumpEntry]:
    """Return coredumps matching `matches` (any coredumpctl match expression),
    oldest first - same ordering coredumpctl itself uses."""
    args = ["list", "--json=short", "--no-legend"]
    if matches:
        args.extend(matches)
    raw = _run_json(args).strip()
    if not raw:
        return []
    rows = json.loads(raw)
    entries = [
        CoredumpEntry(
            pid=row["pid"],
            uid=row["uid"],
            gid=row["gid"],
            signal=row["sig"],
            exe=row.get("exe"),
            timestamp=_parse_timestamp(row.get("time")),
            corefile=row.get("corefile", "unknown"),
            size=row.get("size"),
        )
        for row in rows
    ]
    if limit is not None:
        entries = entries[-limit:]
    return entries


def get_info(match: str) -> CoredumpInfo:
    """Full detail for a single coredump. `match` should uniquely identify
    one coredump (e.g. a PID) - callers are responsible for disambiguating
    first via list_coredumps()."""
    raw = _run_json(["info", "--json=short", match]).strip()
    if not raw:
        raise CoredumpctlError(f"no coredump info returned for match: {match}")
    # coredumpctl may print multiple JSON objects (one per matching entry)
    # if the match is ambiguous; take the last (most recent).
    obj = None
    decoder = json.JSONDecoder()
    idx = 0
    raw_stripped = raw
    objs = []
    while idx < len(raw_stripped):
        raw_stripped_sub = raw_stripped[idx:].lstrip()
        if not raw_stripped_sub:
            break
        skipped = len(raw_stripped[idx:]) - len(raw_stripped_sub)
        obj, end = decoder.raw_decode(raw_stripped_sub)
        objs.append(obj)
        idx += skipped + end
    obj = objs[-1]

    filename = obj.get("Filename")
    return CoredumpInfo(
        pid=obj["PID"],
        tid=obj.get("TID"),
        uid=obj["UID"],
        gid=obj["GID"],
        signal=obj["Signal"],
        signal_name=obj.get("SignalName"),
        timestamp=_parse_timestamp(obj["Timestamp"]),
        executable=obj.get("Executable"),
        command=obj.get("Command"),
        command_line=obj.get("CommandLine"),
        hostname=obj.get("Hostname"),
        unit=obj.get("Unit") or obj.get("UserUnit"),
        filename=Path(filename) if filename else None,
        disk_size=obj.get("DiskSize"),
        storage=obj.get("Storage"),
        message=obj.get("Message", ""),
    )


def pick_latest(matches: list[str] | None = None) -> CoredumpEntry | None:
    entries = list_coredumps(matches)
    return entries[-1] if entries else None
