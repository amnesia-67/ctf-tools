"""pwnscan against targets whose stack layout we know exactly."""

from __future__ import annotations

import pytest

from ctftools.core import disasm
from ctftools.core.binary import load_binary
from ctftools.tools import pwnscan
from tests.conftest import EXPECTED


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_checksec_matches_build_flags(target, name):
    info = load_binary(target(name))
    expected = EXPECTED[name]
    assert info.arch == "amd64"
    assert info.canary is expected["canary"]
    assert info.pie is expected["pie"]
    assert info.nx is expected["nx"]
    assert {m.name for m in info.mitigations()} >= {"RELRO", "Stack canary", "NX", "PIE"}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_static_offset_matches_ground_truth(target, name):
    info = load_binary(target(name))
    result = disasm.analyse(info)
    assert result.available
    best = result.best()
    assert best is not None, "no stack buffer found"
    assert best.predicted_offset == EXPECTED[name]["offset"]


def test_bounded_read_is_recognised_as_safe(target):
    info = load_binary(target("bounded_read"))
    best = disasm.analyse(info).best()
    assert best.size_argument == 32
    assert best.confidence == "bounded"


@pytest.mark.parametrize("name", ["stack_basic", "ret2win", "nx_rop"])
def test_dynamic_offset_is_confirmed(target, have_gdb, name):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = pwnscan.scan(target(name), verify=False, timeout=10.0)
    offset = report.data["offset"]
    assert offset["offset"] == EXPECTED[name]["offset"]
    assert offset["status"] == "confirmed"
    assert offset["agreement"] == "static analysis agrees"


def test_canary_blocks_the_overflow(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = pwnscan.scan(target("canary_guard"), verify=False, timeout=10.0)
    offset = report.data["offset"]
    assert offset["status"] == "canary-blocked"
    assert offset["canary_offset"] == 56
    assert offset["offset"] == 72


def test_safe_binary_reports_no_crash(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = pwnscan.scan(target("bounded_read"), verify=False, timeout=10.0, max_length=500)
    assert report.data["offset"]["offset"] is None
    assert report.data["offset"]["status"] == "unknown"


def test_ret2win_path_is_proven_by_running_it(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = pwnscan.scan(target("ret2win"), verify=True, timeout=10.0)
    paths = {p["name"]: p for p in report.data["exploit_paths"]}
    win = next(p for name, p in paths.items() if name.startswith("ret2win"))
    assert win["verified"] is True
    assert win["verdict"] == "proven"


def test_pie_binary_asks_for_a_leak(target):
    report = pwnscan.scan(target("pie_win"), run=False)
    names = [p["name"] for p in report.data["exploit_paths"]]
    assert "Leak the image base" in names


def test_prefix_reaches_a_guarded_overflow(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = pwnscan.scan(target("menu_prefix"), prefix=b"1\n", verify=False, timeout=10.0)
    assert report.data["offset"]["offset"] == EXPECTED["menu_prefix"]["offset"]


def test_json_output_is_serialisable(target):
    import json

    report = pwnscan.scan(target("stack_basic"), run=False)
    payload = json.loads(json.dumps(report.as_dict(), default=str))
    assert payload["tool"] == "pwnscan"
    assert payload["binary"]["mitigations"]["nx"] is True
