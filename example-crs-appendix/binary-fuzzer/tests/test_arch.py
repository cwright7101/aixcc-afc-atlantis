from pathlib import Path

from binary_fuzzer.arch import detect_arch, pick_mode


def _write_elf(path: Path, machine: int) -> None:
    # Minimal 64-bit little-endian ELF header up to e_machine.
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2  # EI_CLASS = ELFCLASS64
    head[5] = 1  # EI_DATA = little-endian
    head[6] = 1  # EI_VERSION = 1
    head[16:18] = (2).to_bytes(2, "little")  # e_type = ET_EXEC
    head[18:20] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(head))


def test_detect_x86_64(tmp_path: Path):
    f = tmp_path / "elf"
    _write_elf(f, 0x3E)
    assert detect_arch(f) == "x86_64"


def test_detect_aarch64(tmp_path: Path):
    f = tmp_path / "elf"
    _write_elf(f, 0xB7)
    assert detect_arch(f) == "aarch64"


def test_detect_non_elf(tmp_path: Path):
    f = tmp_path / "notelf"
    f.write_bytes(b"#!/bin/sh\necho hi\n")
    assert detect_arch(f) is None


def test_pick_mode_explicit():
    assert pick_mode("x86_64", "qemu") == "qemu"
    assert pick_mode("x86_64", "frida") == "frida"


def test_pick_mode_auto_cross_arch(monkeypatch):
    import binary_fuzzer.arch as arch_mod

    monkeypatch.setattr(arch_mod, "host_arch", lambda: "x86_64")
    assert pick_mode("aarch64", "auto") == "qemu"
    assert pick_mode("x86_64", "auto") == "frida"
