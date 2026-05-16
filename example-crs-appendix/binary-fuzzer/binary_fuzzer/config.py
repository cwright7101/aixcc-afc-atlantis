from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, model_validator


class BinaryTask(BaseModel):
    """Standalone config for a binary fuzzing task.

    Mirrors the BinaryDetail schema added to the CRS API (types.py) so the
    same YAML can describe a task in both the CRS and the standalone tool.
    """

    binary_path: Path = Field(..., description="Path to the target ELF on disk.")
    arch: str = Field("x86_64", description="Target arch, e.g. x86_64 or aarch64.")
    entry: Literal["stdin", "argv", "file", "network"] = "stdin"
    network_port: Optional[int] = None
    argv_template: Optional[str] = None
    seed_corpus_dir: Optional[Path] = None
    dictionary_path: Optional[Path] = None
    timeout_ms: int = 1000
    persistent: bool = False
    mode: Literal["qemu", "frida", "auto"] = "auto"

    @model_validator(mode="after")
    def _check_entry(self) -> "BinaryTask":
        if self.entry == "network" and self.network_port is None:
            raise ValueError("network_port is required when entry == 'network'")
        if self.entry == "file" and self.argv_template and "@@" not in self.argv_template:
            raise ValueError("argv_template must contain '@@' when entry == 'file'")
        return self


def load_task(path: Path) -> BinaryTask:
    data = yaml.safe_load(Path(path).read_text())
    return BinaryTask.model_validate(data)
