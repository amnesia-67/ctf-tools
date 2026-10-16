"""heapscope reads a heap whose allocations we chose."""

from __future__ import annotations

import pytest

from ctftools.tools import heapscope


@pytest.fixture(scope="module")
def clean(target_module):
    return heapscope.inspect(target_module("heap_play"), breakpoint_at="getchar")


@pytest.fixture(scope="module")
def poisoned(target_module):
    return heapscope.inspect(target_module("heap_play"), breakpoint_at="getchar", args=["p"])


def test_chunks_match_the_allocations(clean):
    sizes = [c["size"] for c in clean.data["chunks"]]
    # malloc(0x18) -> 0x20, malloc(0x28) -> 0x30, malloc(0x88) -> 0x90, malloc(0x108) -> 0x110
    for wanted in (0x20, 0x30, 0x90, 0x110):
        assert wanted in sizes, f"{wanted:#x} missing from {[hex(s) for s in sizes]}"


def test_freed_chunks_are_in_their_tcache_bins(clean):
    bins = {entry["size"]: entry for entry in clean.data["tcache"]}
    assert 0x20 in bins and bins[0x20]["count"] == 1
    assert 0x30 in bins and bins[0x30]["count"] == 1
    # One entry means a chain of exactly one pointer, not a walk into mangled bytes.
    assert len(bins[0x20]["chain"]) == 1


def test_a_clean_heap_produces_no_findings(clean):
    assert clean.data["findings"] == [], clean.data["findings"]


def test_the_libc_is_identified(clean):
    assert clean.data["libc"] and "libc" in clean.data["libc"]


def test_poisoned_bin_is_detected(poisoned):
    kinds = {f["kind"] for f in poisoned.data["findings"]}
    assert "poisoned bin" in kinds
    detail = next(f["detail"] for f in poisoned.data["findings"] if f["kind"] == "poisoned bin")
    assert "0xdeadbeef" in detail


def test_count_mismatch_is_detected(poisoned):
    kinds = {f["kind"] for f in poisoned.data["findings"]}
    assert "count mismatch" in kinds


def test_breaking_before_any_malloc_says_so(target):
    report = heapscope.inspect(target("heap_play"), breakpoint_at="_start")
    assert report.data.get("heap") is None
    assert report.notes or report.warnings


def test_unknown_symbol_is_reported(target):
    report = heapscope.inspect(target("heap_play"), breakpoint_at="no_such_function")
    assert report.data.get("heap") is None
    assert any("no symbol" in w for w in report.warnings)
