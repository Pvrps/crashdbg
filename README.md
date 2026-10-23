# crashdbg

Crash triage for native programs on Linux. Point it at a crash and it pulls
together everything you'd normally dig up by hand with `coredumpctl`,
`journalctl`, `gdb` and `objdump`, then shows it as one report or an
interactive TUI. It works even when the crashing binary is stripped and has no
debug symbols, which is the usual case for games and other closed-source apps.

## What it does

Given a crash (by PID, process name or executable path), crashdbg:

- **Finds the coredump** via systemd's `coredumpctl` and reads its metadata.
- **Explains the fault**: finds the kernel's `segfault at ...` line in the
  journal and decodes the signal and page-fault error code into plain English
  (e.g. "user-mode read of an unmapped page", which usually means a NULL pointer).
- **Disassembles the faulting instruction** from the kernel's `Code:` bytes.
- **Recovers the crashing function** using the binary's unwind metadata
  (`.eh_frame`), which survives stripping, and disassembles the whole thing.
- **Finds the nearest library call before the crash** (e.g. `getifaddrs`,
  `strlen`) using the binary's import table, skipping calls that couldn't
  have actually run.
- **Adds relevant live context** where it helps. For example, if the crash
  follows a `getifaddrs` call, it snapshots your network interfaces and flags
  VPN/tunnel devices, a well-known cause of NULL-pointer crashes.
- **Produces a backtrace** with gdb, falling back to the address-only
  backtrace systemd already recorded if gdb isn't available.
- **Shows surrounding journal logs** from just before the crash.

It also covers **Windows games under Wine/Proton**, which often crash without
producing a Linux coredump at all. It finds Unreal Engine's own crash reports
inside Steam's Proton prefixes and game folders, decodes the Windows exception
codes, and works out which Windows program was actually running behind the
generic `wine64`/`wine-preloader` process names.

None of this is hardcoded to any specific app. It relies only on standard
Linux, ELF, Windows and Unreal Engine conventions.

## Requirements

- Linux on x86-64 with systemd-coredump (for `coredumpctl` and `journalctl`)
- [devenv](https://devenv.sh) and [just](https://just.systems), which provide
  Python 3.13, [uv](https://docs.astral.sh/uv/), gdb, zstd, binutils and iproute2

Outside devenv, gdb + zstd (backtraces), `objdump` (function and import-call
disassembly) and `ip` (network context) are optional. crashdbg skips whatever
it can't find.

## Usage

```sh
just install        # set up the environment and dependencies
just list           # list recent coredumps and Unreal Engine crash reports
just list Hero_Siege
just run            # open the TUI on the most recent crash
just run 85253      # open the TUI on a specific PID (or process name / exe path)
```

Or call the CLI directly:

```sh
crashdbg list [MATCH...]
crashdbg analyze [MATCH...]          # one-shot report in the terminal
crashdbg analyze [MATCH...] --json   # machine-readable report
crashdbg tui [MATCH...]              # interactive TUI
```

Run `crashdbg <command> --help` to see all options.
