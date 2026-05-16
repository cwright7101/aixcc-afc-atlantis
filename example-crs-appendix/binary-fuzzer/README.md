# binary-fuzzer

Pure-binary intake for the Atlantis CRS. Takes a pre-built ELF (no source,
no Dockerfile, no `oss-fuzz` project) and black-box fuzzes it with AFL++
in **QEMU** mode (cross-arch, slower) or **Frida** mode (same-arch,
faster). Crashes are recorded locally and optionally forwarded to the
CRS submission API.

Atlantis's normal pipeline assumes the OSS-Fuzz contract (source +
`fuzz-tooling` tarball + `build.sh`). This tool fills the gap for the
case where you only have the binary.

## When to use this

- You only have an ELF (red-team drop, firmware extract, vendored blob).
- You want a fast crash-finding loop without standing up an OSS-Fuzz
  project.
- You want to feed crashes back into the CRS for downstream triage
  (manual review; *not* `crs-patch` — that needs source).

## Quick start

```bash
# Build the container (AFL++ + QEMU + Frida + this CLI).
docker build -t binary-fuzzer .

# Mount your binary, seeds, and an output dir.
docker run --rm -it \
    -v "$PWD/target:/work/target:ro" \
    -v "$PWD/seeds:/work/seeds:ro" \
    -v "$PWD/out:/work/out" \
    binary-fuzzer \
    --binary /work/target/vuln \
    --seeds /work/seeds \
    --out /work/out \
    --duration 300
```

Crashes land in `out/crashes/<id>.bin` (raw input) and
`out/crashes/<id>.json` (metadata).

## YAML config form

```yaml
binary_path: /work/target/vuln
arch: x86_64
entry: stdin            # stdin | argv | file | network
timeout_ms: 1000
mode: auto              # auto | qemu | frida
seed_corpus_dir: /work/seeds
dictionary_path: /work/dict.afl
```

```bash
binary-fuzz --task task.yaml --out /work/out
```

This is intentionally a superset of `BinaryDetail` in
`crs_webserver/my_crs/task_server/models/types.py` so a CRS task can be
spilled to YAML and replayed standalone.

## Crash sink

Local sink is always on. CAPI forwarding is opt-in via env var:

| Var                              | Effect                                          |
| -------------------------------- | ----------------------------------------------- |
| `BINARY_FUZZER_SUBMIT_CAPI=1`    | Submit each crash via the configured submit_fn. |
| `BINARY_FUZZER_HARNESS_NAME=...` | Reported harness name (default: `binary_main`). |
| `BINARY_FUZZER_SANITIZER=...`    | Reported sanitizer label (default: `address`).  |

When invoked standalone, no `submit_fn` is wired, so even with the env
var on you'll just get local crashes. When the CRS launches this tool
(see `cp_manager` integration below), it passes
`cp_manager.api_util.capi_submit_pov` as the submit_fn.

## QEMU vs Frida mode

- **QEMU** (`-Q`): emulates the target's instruction set under host;
  works cross-arch (run an aarch64 binary on an x86_64 host). Slower.
  We also enable `AFL_USE_QASAN=1` to surface heap corruption that the
  uninstrumented binary would otherwise swallow.
- **Frida** (`-O`): same-arch dynamic instrumentation. Faster, supports
  persistent mode for huge throughput gains on cooperative binaries.

`mode: auto` picks Frida when target arch == host arch, else QEMU.

## CRS integration

The CRS dispatches to this tool when a task's `source` list contains
only `SourceType.SourceTypeBinary` entries. See
`example-crs-webservice/cp_manager/cp_manager/cp_manager.py` for the
short-circuit point. The path is:

1. CRS receives `TaskDetail` with `source[*].type == "binary"`.
2. `CPManager.__download` fetches each binary URL into the task's
   tarball dir (no untar).
3. `CPManager.__launch_nodes` detects `task.is_binary_only` and skips
   `crs-multilang`, `crs-patch`, `crs-sarif`, `crs-java`, and the
   standard `crs-userspace` build. It runs `binary-fuzz` directly with
   the staged binary.
4. Crashes flow back through `CrashSink`; with
   `BINARY_FUZZER_SUBMIT_CAPI=1` they go to the competition API too.

## What this does NOT do

- **Patching**: source-less binary patching is out of scope for this
  slice. `crs-patch` is skipped for binary tasks.
- **SARIF / static analysis**: `crs-sarif` requires source.
- **Coverage-guided seed generation via SymCC**: SymCC needs source
  instrumentation; for binary inputs you'll get AFL++'s built-in
  coverage feedback from QEMU/Frida.
- **Decompilation**: we don't lift to pseudo-C. If you want that path,
  drop the decompiled output in as a synthetic `repo` source.

## Testing

```bash
pip install -e .
pytest tests/
```

The fuzzer integration itself isn't exercised in unit tests (it shells
out to `afl-fuzz`). To smoke-test end-to-end:

```bash
# In the container:
cc tests/fixtures/vuln.c -o /tmp/vuln
binary-fuzz --binary /tmp/vuln --out /tmp/out --duration 60
# Inputs starting with "CRASH" should produce crashes under /tmp/out/crashes/.
```
