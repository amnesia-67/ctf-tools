"""fuzzlite separates an overflow, a canary abort, a format string and a safe binary."""

from __future__ import annotations

import pytest

from ctftools.tools import fuzzlite


def _classes(report):
    return {f["classification"] for f in report.data["findings"]}


def test_overflow_shows_up_as_a_segfault(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = fuzzlite.fuzz(target("stack_basic"), cases=40, timeout=3.0)
    assert "segfault" in _classes(report)
    assert report.data["unique_crashes"] >= 1


def test_canary_is_classified_separately(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = fuzzlite.fuzz(target("canary_guard"), cases=40, timeout=3.0)
    assert "canary-abort" in _classes(report)
    assert any("stack smashing" in (f["hint"] or "") for f in report.data["findings"])


def test_format_string_leak_is_spotted(target):
    report = fuzzlite.fuzz(target("fmt_string"), cases=60, timeout=3.0, triage=False)
    leaks = report.data["format_string_leaks"]
    assert leaks, "no leak detected from %p"
    assert any("0x" in leak["output"] for leak in leaks)


def test_safe_binary_produces_no_crashes(target):
    report = fuzzlite.fuzz(target("bounded_read"), cases=60, timeout=3.0, triage=False)
    assert report.data["unique_crashes"] == 0


def test_crashes_are_deduplicated(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = fuzzlite.fuzz(target("stack_basic"), cases=60, timeout=3.0)
    assert report.data["crashes"] > report.data["unique_crashes"]


def test_crashing_inputs_are_saved(target, tmp_path, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    out = tmp_path / "crashes"
    report = fuzzlite.fuzz(target("stack_basic"), cases=30, timeout=3.0, save_dir=str(out))
    files = list(out.iterdir())
    assert len(files) == report.data["unique_crashes"]
    assert all(f.read_bytes() for f in files)
