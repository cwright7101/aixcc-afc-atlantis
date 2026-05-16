from __future__ import annotations

import platform
import struct
from pathlib import Path
from typing import Optional


_ELF_MACHINE = {
    0x3E: "x86_64",
    0x03: "i386",
    0xB7: "aarch64",
    0x28: "arm",
    0xF3: "riscv64",
}


def detect_arch(binary: Path) -> Optional[str]:
    """Return the architecture string for an ELF, or None if not ELF."""
    try:
        with open(binary, "rb") as f:
            head = f.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    (machine,) = struct.unpack_from("<H", head, 18)
    return _ELF_MACHINE.get(machine)


def host_arch() -> str:
    return platform.machine() or "x86_64"


def pick_mode(target_arch: str, requested: str) -> str:
    """Pick afl-fuzz instrumentation mode.

    QEMU mode supports cross-arch emulation but is slower; Frida mode is
    same-arch only but faster and works where QEMU lacks coverage of newer
    instructions. 'auto' prefers Frida when target_arch == host_arch.
    """
    if requested in ("qemu", "frida"):
        return requested
    return "frida" if target_arch == host_arch() else "qemu"
