"""Decodes the kernel's 'Code: aa bb <cc> dd ...' hint line into real x86-64
instructions via capstone. This is completely generic machine-code
disassembly - it works for any crash, on any binary, and makes no
assumptions about what the faulting instruction *should* be."""

from __future__ import annotations

import re

from .models import DisasmInstr

_BYTE_RE = re.compile(r"^<?([0-9a-fA-F]{2})>?$")


def parse_code_line(code_line: str) -> tuple[bytes, int]:
    """Parse a kernel 'Code: ...' line into (raw_bytes, fault_byte_index).

    The kernel wraps the byte at the faulting $ip in angle brackets, e.g.:
      'Code: 48 8b 45 18 <0f> b7 00 83 f8 0a ...'
    """
    body = code_line.split(":", 1)[1].strip() if ":" in code_line else code_line.strip()
    tokens = body.split()

    raw = bytearray()
    fault_index = -1
    for i, tok in enumerate(tokens):
        m = _BYTE_RE.match(tok)
        if not m:
            continue
        raw.append(int(m.group(1), 16))
        if tok.startswith("<"):
            fault_index = i

    if fault_index == -1:
        fault_index = 0
    return bytes(raw), fault_index


def disassemble_fault(
    code_bytes: bytes, fault_index: int, max_instructions: int = 6
) -> list[DisasmInstr]:
    """Disassemble starting exactly at the faulting byte (a valid
    instruction boundary, per the kernel), returning the faulting
    instruction plus a few that follow for context."""
    try:
        import capstone
    except ImportError:
        return []

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    tail = bytes(code_bytes[fault_index:])
    instrs: list[DisasmInstr] = []
    for i, insn in enumerate(md.disasm(tail, 0x0)):
        instrs.append(
            DisasmInstr(
                address=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                raw_bytes=bytes(insn.bytes),
                is_fault_instr=(i == 0),
            )
        )
        if len(instrs) >= max_instructions:
            break
    return instrs
