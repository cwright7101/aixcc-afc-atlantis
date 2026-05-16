from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from .arch import detect_arch, pick_mode
from .config import BinaryTask
from .crash_sink import CrashSink


class BinaryFuzzer:
    """Drives AFL++ in QEMU or Frida mode against a pre-built binary."""

    def __init__(
        self,
        task: BinaryTask,
        out_dir: Path,
        sink: CrashSink,
        afl_fuzz_bin: str = "afl-fuzz",
    ):
        self.task = task
        self.out_dir = out_dir
        self.sink = sink
        self.afl_fuzz_bin = afl_fuzz_bin
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _seeds_dir(self) -> Path:
        seeds = self.out_dir / "seeds"
        seeds.mkdir(parents=True, exist_ok=True)
        if self.task.seed_corpus_dir and self.task.seed_corpus_dir.exists():
            for f in self.task.seed_corpus_dir.iterdir():
                if f.is_file():
                    shutil.copy2(f, seeds / f.name)
        if not any(seeds.iterdir()):
            (seeds / "seed_default").write_bytes(b"A\n")
        return seeds

    def _build_argv(self, mode: str) -> List[str]:
        cmd: List[str] = [self.afl_fuzz_bin]
        cmd += ["-i", str(self._seeds_dir())]
        cmd += ["-o", str(self.out_dir / "afl")]
        cmd += ["-t", str(self.task.timeout_ms)]
        cmd += ["-m", "none"]
        if self.task.dictionary_path and self.task.dictionary_path.exists():
            cmd += ["-x", str(self.task.dictionary_path)]
        if mode == "qemu":
            cmd += ["-Q"]
        elif mode == "frida":
            cmd += ["-O"]
        cmd += ["--"]

        binary = str(self.task.binary_path)
        if self.task.entry == "file":
            tmpl = self.task.argv_template or "{binary} @@"
            cmd += shlex.split(tmpl.format(binary=binary))
        elif self.task.entry == "argv":
            tmpl = self.task.argv_template or "{binary} @@"
            cmd += shlex.split(tmpl.format(binary=binary))
        else:
            cmd += [binary]
        return cmd

    def _env(self, mode: str) -> dict:
        env = os.environ.copy()
        env.setdefault("AFL_SKIP_CPUFREQ", "1")
        env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        env.setdefault("AFL_NO_AFFINITY", "1")
        if mode == "qemu":
            env.setdefault("AFL_USE_QASAN", "1")
        return env

    def resolve_mode(self) -> str:
        target_arch = self.task.arch or detect_arch(self.task.binary_path) or "x86_64"
        return pick_mode(target_arch, self.task.mode)

    def run(self, duration_s: Optional[int] = None) -> int:
        """Run afl-fuzz. If duration_s is set, kill after that many seconds.

        Returns the count of crashes ingested into the sink.
        """
        if not self.task.binary_path.exists():
            raise FileNotFoundError(self.task.binary_path)
        os.chmod(self.task.binary_path, 0o755)

        mode = self.resolve_mode()
        argv = self._build_argv(mode)
        env = self._env(mode)

        log = (self.out_dir / "afl.log").open("wb")
        proc = subprocess.Popen(
            argv, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            self._loop(proc, duration_s)
        finally:
            self._terminate(proc)
            log.close()
        return self.sink.import_afl_crashes(self.out_dir / "afl")

    def _loop(self, proc: subprocess.Popen, duration_s: Optional[int]) -> None:
        start = time.monotonic()
        while proc.poll() is None:
            self.sink.import_afl_crashes(self.out_dir / "afl")
            if duration_s is not None and (time.monotonic() - start) >= duration_s:
                return
            time.sleep(2)

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
