from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


@dataclass
class SinkConfig:
    """Where crashes go. Local always; CAPI is opt-in via env flag.

    BINARY_FUZZER_SUBMIT_CAPI=1 enables upstream submission. When enabled,
    callers must provide submit_fn that knows how to talk to the
    competition API (see cp_manager.api_util.capi_submit_pov).
    """

    local_dir: Path
    submit_to_capi: bool = False
    submit_fn: Optional[Callable[[bytes, str, str], None]] = None
    harness_name: str = "binary_main"
    sanitizer: str = "address"

    @classmethod
    def from_env(cls, local_dir: Path) -> "SinkConfig":
        return cls(
            local_dir=local_dir,
            submit_to_capi=os.environ.get("BINARY_FUZZER_SUBMIT_CAPI", "0") == "1",
            harness_name=os.environ.get("BINARY_FUZZER_HARNESS_NAME", "binary_main"),
            sanitizer=os.environ.get("BINARY_FUZZER_SANITIZER", "address"),
        )


class CrashSink:
    """Records crashes locally and (optionally) forwards to the CRS API.

    A crash record consists of the raw input bytes and an arbitrary
    metadata dict (return code, stderr tail, AFL filename, etc.). Local
    layout under local_dir:

        crashes/<id>.bin     # raw input
        crashes/<id>.json    # metadata
    """

    def __init__(self, config: SinkConfig):
        self.config = config
        self.crashes_dir = config.local_dir / "crashes"
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    def record(self, blob: bytes, metadata: dict) -> Path:
        self._counter += 1
        crash_id = f"{int(time.time())}_{self._counter:04d}"
        bin_path = self.crashes_dir / f"{crash_id}.bin"
        meta_path = self.crashes_dir / f"{crash_id}.json"
        bin_path.write_bytes(blob)
        meta_path.write_text(json.dumps({"id": crash_id, **metadata}, indent=2))

        if self.config.submit_to_capi:
            self._submit_capi(blob, metadata, crash_id)

        return bin_path

    def import_afl_crashes(self, afl_out_dir: Path) -> int:
        """Scan AFL++ output dir for new crashes and record each one.

        Returns the count of newly recorded crashes.
        """
        count = 0
        for crash_dir in afl_out_dir.glob("*/crashes"):
            for crash_file in crash_dir.iterdir():
                if not crash_file.is_file() or crash_file.name.startswith("README"):
                    continue
                marker = self.crashes_dir / f".imported_{crash_file.name}"
                if marker.exists():
                    continue
                marker.touch()
                self.record(
                    crash_file.read_bytes(),
                    {"source": "afl", "afl_name": crash_file.name},
                )
                count += 1
        return count

    def _submit_capi(self, blob: bytes, metadata: dict, crash_id: str) -> None:
        fn = self.config.submit_fn
        if fn is None:
            return
        try:
            fn(blob, self.config.harness_name, self.config.sanitizer)
        except Exception as e:
            err_path = self.crashes_dir / f"{crash_id}.capi_error.txt"
            err_path.write_text(f"{type(e).__name__}: {e}")
