"""Minimal, dependency-free ELF header introspection - just enough to know
whether a binary is position-independent (ET_DYN/PIE) or has a fixed load
address (ET_EXEC), which changes how a kernel-reported fault address maps
back to the file-relative virtual address tools like objdump/readelf use.
"""

from __future__ import annotations

import struct
from pathlib import Path

ET_EXEC = 2
ET_DYN = 3


def read_e_type(binary_path: Path) -> int | None:
    try:
        with open(binary_path, "rb") as f:
            header = f.read(18)
    except OSError:
        return None
    if len(header) < 18 or header[:4] != b"\x7fELF":
        return None
    is_little_endian = header[5] == 1
    fmt = "<H" if is_little_endian else ">H"
    return struct.unpack(fmt, header[16:18])[0]


def fault_file_vaddr(binary_path: Path, absolute_ip: int, ip_offset: int | None) -> int | None:
    """Translate a kernel-reported fault $ip into the file-relative virtual
    address objdump/readelf would show, based on the binary's ELF type.

    - ET_EXEC (fixed load address, no ASLR): the kernel's absolute $ip
      already matches the file's own vaddr numbering directly - subtracting
      the reported module base would actually be *wrong* here, since that
      base is already baked into the file's link-time vaddrs.
    - ET_DYN (PIE): the kernel's reported ip-offset (ip minus the randomized
      runtime load base) already equals the file's own vaddr, since PIE
      binaries are linked with a base of 0.
    """
    e_type = read_e_type(binary_path)
    if e_type == ET_EXEC:
        return absolute_ip
    if e_type == ET_DYN:
        return ip_offset
    return None
