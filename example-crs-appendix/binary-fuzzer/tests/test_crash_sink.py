import json
from pathlib import Path

from binary_fuzzer.crash_sink import CrashSink, SinkConfig


def test_record_writes_blob_and_metadata(tmp_path: Path):
    sink = CrashSink(SinkConfig(local_dir=tmp_path))
    sink.record(b"abc", {"ret": -11})
    bins = list((tmp_path / "crashes").glob("*.bin"))
    metas = list((tmp_path / "crashes").glob("*.json"))
    assert len(bins) == 1 and len(metas) == 1
    assert bins[0].read_bytes() == b"abc"
    meta = json.loads(metas[0].read_text())
    assert meta["ret"] == -11


def test_capi_disabled_by_default(tmp_path: Path):
    calls = []
    sink = CrashSink(
        SinkConfig(
            local_dir=tmp_path,
            submit_fn=lambda blob, h, s: calls.append(blob),
        )
    )
    sink.record(b"x", {})
    assert calls == []


def test_capi_called_when_enabled(tmp_path: Path):
    calls = []
    sink = CrashSink(
        SinkConfig(
            local_dir=tmp_path,
            submit_to_capi=True,
            submit_fn=lambda blob, h, s: calls.append((blob, h, s)),
            harness_name="hx",
            sanitizer="address",
        )
    )
    sink.record(b"y", {})
    assert calls == [(b"y", "hx", "address")]


def test_capi_error_does_not_raise(tmp_path: Path):
    def boom(*_):
        raise RuntimeError("nope")

    sink = CrashSink(
        SinkConfig(local_dir=tmp_path, submit_to_capi=True, submit_fn=boom)
    )
    sink.record(b"z", {})
    errs = list((tmp_path / "crashes").glob("*.capi_error.txt"))
    assert len(errs) == 1
    assert "nope" in errs[0].read_text()


def test_import_afl_crashes(tmp_path: Path):
    afl_out = tmp_path / "afl"
    crashes = afl_out / "default" / "crashes"
    crashes.mkdir(parents=True)
    (crashes / "id:000000,sig:06,src:000000").write_bytes(b"CRASHpayload")
    (crashes / "README.txt").write_text("ignore me")

    sink = CrashSink(SinkConfig(local_dir=tmp_path / "sink"))
    n = sink.import_afl_crashes(afl_out)
    assert n == 1

    # Re-importing the same dir doesn't double-count.
    n2 = sink.import_afl_crashes(afl_out)
    assert n2 == 0
