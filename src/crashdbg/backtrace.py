"""Produces a symbolized backtrace for a coredump.

Primary path: decompress the .zst core and run gdb directly against the
executable + core (bypassing `coredumpctl gdb`/`debug`, whose internal
decompress-into-debugger pipe has been observed to fail with spurious I/O
errors on large cores in this environment).

Fallback path: if gdb or zstd aren't available, parse the raw address-only
"Stack trace of thread" block systemd-coredump already embeds in the
coredump's Message field.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import BacktraceFrame


# Decompressed cores can be multi-gigabyte; the system default tempdir
# (/tmp) is often a small tmpfs (RAM-backed) and can't hold them. Use the
# standard per-user XDG cache dir instead, which is expected to live on
# real disk.
def _scratch_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    root = Path(base) / "crashdbg"
    root.mkdir(parents=True, exist_ok=True)
    return root


_GDB_FRAME_RE = re.compile(
    r"^#(?P<idx>\d+)\s+"
    r"(?:0x(?P<addr>[0-9a-fA-F]+)\s+in\s+)?"
    r"(?P<func>[^\s(]+)\s*"
    r"\((?P<args>.*)\)"
    r"(?:\s+at\s+(?P<loc>\S+))?"
    r"(?:\s+from\s+(?P<from>\S+))?"
    r"\s*$"
)

_MESSAGE_FRAME_RE = re.compile(
    r"^#(?P<idx>\d+)\s+0x(?P<addr>[0-9a-fA-F]+)\s+(?P<func>\S+)\s+"
    r"\((?P<module>[^+]+?)\s*\+\s*0x(?P<offset>[0-9a-fA-F]+)\)\s*$"
)


class BacktraceError(RuntimeError):
    pass


def has_gdb() -> bool:
    return shutil.which("gdb") is not None


def has_zstd() -> bool:
    return shutil.which("zstd") is not None


def decompress_core(src: Path, dest: Path) -> None:
    proc = subprocess.run(
        ["zstd", "-d", "-f", "-q", str(src), "-o", str(dest)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise BacktraceError(f"zstd decompression failed: {proc.stderr.strip()}")


def run_gdb(exe: Path, core: Path, timeout: float = 60.0) -> str:
    cmd = [
        "gdb",
        "-q",
        "-nx",
        "-batch",
        "-ex",
        "bt",
        "-ex",
        "info registers rip rax rbx rcx rdx rsi rdi rbp rsp",
        str(exe),
        str(core),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.stdout + "\n" + proc.stderr


def parse_gdb_backtrace(raw: str) -> list[BacktraceFrame]:
    frames: list[BacktraceFrame] = []
    seen_indices: set[int] = set()
    for line in raw.splitlines():
        m = _GDB_FRAME_RE.match(line.strip())
        if not m:
            continue
        idx = int(m.group("idx"))
        # gdb prints the crash frame once on its own when the core loads,
        # then again as part of `bt`'s own output - drop the duplicate.
        if idx in seen_indices:
            continue
        seen_indices.add(idx)
        addr = int(m.group("addr"), 16) if m.group("addr") else None
        module = m.group("from")
        loc = m.group("loc")
        frames.append(
            BacktraceFrame(
                index=idx,
                address=addr,
                function=m.group("func"),
                args=m.group("args") or None,
                location=loc,
                module=module,
                raw_line=line.strip(),
            )
        )
    return frames


def extract_registers(raw: str) -> dict[str, int]:
    regs: dict[str, int] = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in {
            "rip",
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
        }:
            try:
                regs[parts[0]] = int(parts[1], 16)
            except ValueError:
                continue
    return regs


def frames_from_coredump_message(message: str) -> list[BacktraceFrame]:
    """Fallback: parse systemd-coredump's own address-only backtrace out of
    the coredump Message field (always present, no gdb/zstd required)."""
    frames = []
    in_block = False
    for line in message.splitlines():
        if line.strip().startswith("Stack trace of thread"):
            in_block = True
            continue
        if not in_block:
            continue
        m = _MESSAGE_FRAME_RE.match(line.strip())
        if not m:
            if line.strip() and not line.strip().startswith("#"):
                break
            continue
        frames.append(
            BacktraceFrame(
                index=int(m.group("idx")),
                address=int(m.group("addr"), 16),
                function=m.group("func"),
                args=None,
                location=None,
                module=f"{m.group('module')} + 0x{m.group('offset')}",
                raw_line=line.strip(),
            )
        )
    return frames


def get_backtrace(
    exe: Path | None, core_compressed: Path | None, keep_core: bool = False
) -> tuple[list[BacktraceFrame], str, Path | None, dict[str, int]]:
    """Returns (frames, source, kept_core_path_or_none, registers).
    source is one of: "gdb", "unavailable".
    Raises BacktraceError with a human-readable reason on failure - caller
    decides whether to fall back to frames_from_coredump_message().
    """
    if exe is None or core_compressed is None:
        raise BacktraceError("missing executable or core file path")
    if not has_gdb():
        raise BacktraceError("gdb not found on PATH")
    if not has_zstd():
        raise BacktraceError("zstd not found on PATH")
    if not exe.exists():
        raise BacktraceError(f"executable no longer exists on disk: {exe}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="crashdbg-", dir=str(_scratch_root())))
    core_path = tmp_dir / "core"
    try:
        decompress_core(core_compressed, core_path)
        raw = run_gdb(exe, core_path)
        frames = parse_gdb_backtrace(raw)
        regs = extract_registers(raw)
        kept = None
        if keep_core:
            kept = core_path
        else:
            core_path.unlink(missing_ok=True)
            tmp_dir.rmdir()
        return frames, "gdb", kept, regs
    except Exception:
        if core_path.exists():
            core_path.unlink(missing_ok=True)
        if tmp_dir.exists():
            try:
                tmp_dir.rmdir()
            except OSError:
                pass
        raise
