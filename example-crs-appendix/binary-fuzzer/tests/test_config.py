from pathlib import Path

import pytest
import yaml

from binary_fuzzer.config import BinaryTask, load_task


def test_defaults(tmp_path: Path):
    task = BinaryTask(binary_path=tmp_path / "fake")
    assert task.entry == "stdin"
    assert task.timeout_ms == 1000
    assert task.mode == "auto"


def test_network_requires_port(tmp_path: Path):
    with pytest.raises(ValueError):
        BinaryTask(binary_path=tmp_path / "fake", entry="network")


def test_file_entry_requires_at_at(tmp_path: Path):
    with pytest.raises(ValueError):
        BinaryTask(
            binary_path=tmp_path / "fake",
            entry="file",
            argv_template="{binary} input.txt",
        )


def test_file_entry_accepts_at_at(tmp_path: Path):
    BinaryTask(
        binary_path=tmp_path / "fake",
        entry="file",
        argv_template="{binary} @@",
    )


def test_load_task(tmp_path: Path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text(yaml.safe_dump({"binary_path": str(tmp_path / "b"), "arch": "aarch64"}))
    task = load_task(cfg)
    assert task.arch == "aarch64"
