"""Live network-interface state, captured as context whenever the crash
involved calling a POSIX network-interface-enumeration function.

This encodes one specific, well-documented gotcha: getifaddrs() legitimately
returns a NULL ifa_addr for the AF_PACKET entry of a POINTOPOINT interface
(tun-type devices - WireGuard, Tailscale, PPP, etc. all create these) that
has no link-layer address. Many callers don't null-check ifa_addr before
reading it, which is exactly the NULL-pointer-read crash pattern crashdbg
already detects independently (see disasm.py). When the nearest resolved
call near a crash is one of this specific function family, the live
interface state *is* the relevant "input data" that call would have
returned - so we snapshot it and flag anything with the POINTOPOINT flag,
the same check a human would do by hand with `ip addr`.

This is intentionally narrow and named for what it is: a check for one
specific, well-known API family, not a general "explain any crash"
heuristic. It hardcodes no application, VPN, or tool name - only the
POSIX function signatures and the kernel behavior they're documented to
have.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from .models import NetworkInterface

# The interface-enumeration function family this check is specifically
# about. See module docstring for why these functions in particular.
INTERFACE_ENUM_FUNCTIONS = {
    "getifaddrs",
    "if_nameindex",
    "if_nametoindex",
    "if_indextoname",
}


def available() -> bool:
    return shutil.which("ip") is not None


def capture_interfaces(timeout: float = 10.0) -> list[NetworkInterface]:
    if not available():
        return []
    proc = subprocess.run(
        ["ip", "-j", "addr", "show"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        return []
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    interfaces: list[NetworkInterface] = []
    for entry in raw:
        addrs = [
            f"{a.get('family')} {a.get('local')}/{a.get('prefixlen')}"
            for a in entry.get("addr_info", [])
            if a.get("local")
        ]
        interfaces.append(
            NetworkInterface(
                name=entry.get("ifname", "?"),
                flags=entry.get("flags", []),
                addresses=addrs,
            )
        )
    return interfaces
