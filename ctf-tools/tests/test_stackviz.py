"""stackviz lays a payload over a frame whose layout we know."""

from __future__ import annotations

from ctftools.tools import stackviz


def _slot(report, name):
    return next(s for s in report.data["slots"] if s["name"] == name)


def test_frame_matches_the_known_layout(target):
    report = stackviz.visualise(target("stack_basic"), discover=False)
    assert report.data["buffer_size"] == 64
    assert report.data["return_address_offset"] == 72
    assert _slot(report, "saved rbp")["offset"] == 64
    assert _slot(report, "return address")["offset"] == 72


def test_canary_is_placed_inside_the_buffer(target):
    report = stackviz.visualise(target("canary_guard"), discover=False)
    assert report.data["canary_displacement"] == 8
    canary = _slot(report, "canary")
    assert canary["offset"] == 56
    assert canary["frame"] == "rbp-0x8"


def test_payload_overlay_says_what_it_reaches(target):
    payload = b"A" * 72 + b"\xb6\x11\x40\x00\x00\x00\x00\x00"
    report = stackviz.visualise(target("stack_basic"), payload=payload, discover=False)
    assert report.data["fills_buffer"] is True
    assert report.data["controls_return_address"] is True
    assert report.data["smashes_canary"] is False


def test_short_payload_reaches_nothing(target):
    report = stackviz.visualise(target("stack_basic"), payload=b"A" * 8, discover=False)
    assert report.data["fills_buffer"] is False
    assert report.data["controls_return_address"] is False


def test_canary_smash_is_called_out(target):
    report = stackviz.visualise(target("canary_guard"), payload=b"A" * 80, discover=False)
    assert report.data["smashes_canary"] is True
    assert any("canary" in w for w in report.warnings)


def test_partial_return_address_is_warned_about(target):
    report = stackviz.visualise(target("stack_basic"), payload=b"A" * 72 + b"\xb6\x11\x40", discover=False)
    assert report.data["controls_return_address"] is True
    assert any("non-canonical" in w for w in report.warnings)
