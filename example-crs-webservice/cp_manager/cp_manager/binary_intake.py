"""Binary-only task intake.

Dispatched from CPManager.launch() when task_detail.is_binary_only. Shells
out to the standalone `binary-fuzz` CLI (see example-crs-appendix/binary-fuzzer)
for each binary source, polls the crash output dir, and (optionally) forwards
crashes to the competition API.

The OSS-Fuzz build pipeline, crs-multilang, crs-sarif, crs-patch, and crs-java
are all skipped for binary tasks — none of them are applicable without source.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from loguru import logger

from crs_webserver.my_crs.task_server.models.types import SourceDetail, TaskDetail

from .api_util import capi_submit_pov


BINARY_FUZZ_BIN = os.environ.get("BINARY_FUZZER_BIN", "binary-fuzz")
SHARED_BINARY_ROOT = Path("/tarball-fs")


def _info(task_id: str, msg: str) -> None:
    logger.info(f"[binary_intake][{task_id}] {msg}")


def _err(task_id: str, msg: str) -> None:
    logger.error(f"[binary_intake][{task_id}] {msg}")


def _download(url: str, dst: Path) -> bool:
    dst.parent.mkdir(parents=True, exist_ok=True)
    ret = subprocess.run(
        ["wget", "-q", url, "-O", str(dst)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if ret.returncode != 0:
        return False
    return dst.exists() and dst.stat().st_size > 0


def _bin_name(src: SourceDetail) -> str:
    return f"binary_{abs(hash(src.url)) & 0xFFFF:04x}"


def _build_cli_args(bin_path: Path, src: SourceDetail, out_dir: Path,
                    seeds: Optional[Path], dictionary: Optional[Path],
                    duration_s: int) -> list:
    detail = src.binary
    cmd = [
        BINARY_FUZZ_BIN,
        "--binary", str(bin_path),
        "--arch", detail.arch,
        "--entry", detail.entry,
        "--timeout-ms", str(detail.timeout_ms),
        "--out", str(out_dir),
        "--duration", str(duration_s),
    ]
    if detail.argv_template:
        cmd += ["--argv-template", detail.argv_template]
    if detail.network_port is not None:
        cmd += ["--port", str(detail.network_port)]
    if seeds and seeds.exists():
        cmd += ["--seeds", str(seeds)]
    if dictionary and dictionary.exists():
        cmd += ["--dict", str(dictionary)]
    if detail.persistent:
        cmd += ["--persistent"]
    return cmd


def _harvest_loop(
    task_id: str,
    crashes_dir: Path,
    submit_capi: bool,
    harness_name: str,
    sanitizer: str,
    stop: threading.Event,
) -> None:
    seen: set = set()
    while not stop.is_set():
        if crashes_dir.exists():
            for crash in crashes_dir.glob("*.bin"):
                if crash.name in seen:
                    continue
                seen.add(crash.name)
                blob = crash.read_bytes()
                digest = hashlib.sha256(blob).hexdigest()[:12]
                _info(task_id, f"crash {crash.name} sha256={digest} size={len(blob)}")
                if submit_capi:
                    try:
                        capi_submit_pov(
                            harness_name, sanitizer, base64.b64encode(blob).decode()
                        )
                    except Exception as e:
                        _err(task_id, f"capi submit failed for {crash.name}: {e}")
        time.sleep(5)


def _run_one_binary(
    task_id: str,
    src: SourceDetail,
    out_root: Path,
    duration_s: int,
    submit_capi: bool,
) -> None:
    if src.binary is None:
        _err(task_id, f"binary source {src.url} has no BinaryDetail; skipping")
        return

    name = _bin_name(src)
    work = out_root / name
    work.mkdir(parents=True, exist_ok=True)
    bin_path = work / "target"

    _info(task_id, f"downloading binary {src.url} -> {bin_path}")
    if not _download(src.url, bin_path):
        _err(task_id, f"download failed: {src.url}")
        return
    os.chmod(bin_path, 0o755)

    seeds_dir: Optional[Path] = None
    if src.binary.seed_corpus_url:
        seeds_tar = work / "seeds.tar.gz"
        if _download(src.binary.seed_corpus_url, seeds_tar):
            seeds_dir = work / "seeds"
            seeds_dir.mkdir(exist_ok=True)
            subprocess.run(
                ["tar", "-xzf", str(seeds_tar), "-C", str(seeds_dir)], check=False
            )

    dict_path: Optional[Path] = None
    if src.binary.dictionary_url:
        dp = work / "dict.afl"
        if _download(src.binary.dictionary_url, dp):
            dict_path = dp

    out_dir = work / "out"
    cmd = _build_cli_args(bin_path, src, out_dir, seeds_dir, dict_path, duration_s)
    _info(task_id, "launching: " + " ".join(cmd))

    stop = threading.Event()
    harvester = threading.Thread(
        target=_harvest_loop,
        args=(task_id, out_dir / "crashes", submit_capi, name, "address", stop),
        daemon=True,
    )
    harvester.start()
    try:
        ret = subprocess.run(cmd)
        _info(task_id, f"{name} binary-fuzz exited rc={ret.returncode}")
    finally:
        stop.set()
        harvester.join(timeout=10)


def run_binary_intake(task_detail: TaskDetail, task_id: str) -> None:
    submit_capi = os.environ.get("BINARY_FUZZER_SUBMIT_CAPI", "0") == "1"
    deadline_s = int(task_detail.deadline / 1000)
    duration_s = max(60, deadline_s - int(time.time()) - 120)
    out_root = SHARED_BINARY_ROOT / task_id / "binary-intake"
    out_root.mkdir(parents=True, exist_ok=True)

    bins = task_detail.binary_sources
    _info(
        task_id,
        f"binary intake start: sources={len(bins)} submit_capi={submit_capi} "
        f"duration={duration_s}s out={out_root}",
    )

    threads = []
    for src in bins:
        t = threading.Thread(
            target=_run_one_binary,
            args=(task_id, src, out_root, duration_s, submit_capi),
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    _info(task_id, "binary intake complete")
