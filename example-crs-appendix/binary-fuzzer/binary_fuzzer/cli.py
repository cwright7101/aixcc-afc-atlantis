from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import BinaryTask, load_task
from .crash_sink import CrashSink, SinkConfig
from .fuzzer import BinaryFuzzer


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="binary-fuzz",
        description="Black-box fuzz a pre-built binary using AFL++ QEMU/Frida mode.",
    )
    p.add_argument("--task", type=Path, help="Path to a YAML task config.")
    p.add_argument("--binary", type=Path, help="Path to target binary (overrides task).")
    p.add_argument("--seeds", type=Path, help="Seed corpus directory.")
    p.add_argument("--dict", dest="dictionary", type=Path, help="AFL dictionary file.")
    p.add_argument("--entry", choices=["stdin", "argv", "file", "network"])
    p.add_argument("--argv-template", help="argv string template, e.g. '{binary} @@'.")
    p.add_argument("--port", type=int, help="Port for entry=network.")
    p.add_argument("--mode", choices=["qemu", "frida", "auto"], default="auto")
    p.add_argument("--arch", default=None)
    p.add_argument("--timeout-ms", type=int, default=1000)
    p.add_argument("--persistent", action="store_true")
    p.add_argument("--out", type=Path, default=Path("./out"), help="Output directory.")
    p.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Stop after this many seconds (default: run until killed).",
    )
    return p


def _task_from_args(args: argparse.Namespace) -> BinaryTask:
    if args.task:
        task = load_task(args.task)
    elif args.binary:
        task = BinaryTask(binary_path=args.binary, arch=args.arch or "x86_64")
    else:
        raise SystemExit("Either --task or --binary is required.")

    overrides = {}
    if args.binary:
        overrides["binary_path"] = args.binary
    if args.seeds:
        overrides["seed_corpus_dir"] = args.seeds
    if args.dictionary:
        overrides["dictionary_path"] = args.dictionary
    if args.entry:
        overrides["entry"] = args.entry
    if args.argv_template:
        overrides["argv_template"] = args.argv_template
    if args.port is not None:
        overrides["network_port"] = args.port
    if args.mode:
        overrides["mode"] = args.mode
    if args.arch:
        overrides["arch"] = args.arch
    if args.timeout_ms:
        overrides["timeout_ms"] = args.timeout_ms
    if args.persistent:
        overrides["persistent"] = True

    if overrides:
        task = task.model_copy(update=overrides)
    return task


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    task = _task_from_args(args)
    args.out.mkdir(parents=True, exist_ok=True)
    sink = CrashSink(SinkConfig.from_env(args.out))
    fuzzer = BinaryFuzzer(task, args.out, sink)
    print(f"[binary-fuzz] mode={fuzzer.resolve_mode()} out={args.out}", file=sys.stderr)
    found = fuzzer.run(duration_s=args.duration)
    print(f"[binary-fuzz] crashes recorded: {found}", file=sys.stderr)
    return 0 if found == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
