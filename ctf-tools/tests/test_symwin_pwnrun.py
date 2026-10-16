"""symwin's plan, and pwnrun driving a target end to end."""

from __future__ import annotations

import ast

import pytest

from ctftools.tools import pwnrun, symwin

PASSWORD = b"ctf7wn"


# -------------------------------------------------------------------- symwin
def test_plan_resolves_the_target_symbol(target):
    spec = symwin.plan(target("passcheck"), "win")
    assert spec.find is not None
    assert spec.find_name == "win"
    assert not [p for p in spec.problems if "no function" in p]


def test_plan_accepts_an_address(target):
    from ctftools.core.binary import load_binary

    address = load_binary(target("passcheck")).symbol("win")
    spec = symwin.plan(target("passcheck"), hex(address))
    assert spec.find == address


def test_plan_reports_an_unknown_symbol_with_candidates(target):
    spec = symwin.plan(target("passcheck"), "nonexistent_function")
    assert spec.find is None
    assert any("no function" in p for p in spec.problems)
    assert any("win" in p for p in spec.problems)


def test_plan_collects_default_avoid_addresses(target):
    spec = symwin.plan(target("passcheck"), "win")
    # exit/_exit come from libc and are linked in, so at least one should resolve.
    assert len(spec.avoid) == len(spec.avoid_names)


def test_pie_binaries_are_flagged(target):
    spec = symwin.plan(target("pie_win"), "win")
    assert spec.pie is True
    assert any("PIE" in p for p in spec.problems)


def test_report_is_honest_when_angr_is_missing(target):
    report = symwin.find_input(target("passcheck"), "win")
    available, _ = symwin.angr_available()
    assert report.data["angr_available"] is available
    if not available:
        assert "solved" not in report.data
        assert report.data["plan"]["find"] is not None


def test_verify_runs_the_real_program(target):
    ok, detail = symwin.verify(target("passcheck"), PASSWORD + b"\n")
    assert ok, detail
    assert "flag{" in detail


@pytest.mark.skipif(not symwin.angr_available()[0], reason="angr is not installed")
def test_angr_solves_the_password(target):
    report = symwin.find_input(target("passcheck"), "win", length=16, timeout=300)
    assert report.data["solved"] is True
    assert report.data["verified"] is True


# -------------------------------------------------------------------- pwnrun
def test_steps_drive_the_target(target):
    tube, how = pwnrun.open_tube(target("passcheck"), None, None)
    steps = [pwnrun.Step("recv-until", b"password:"), pwnrun.Step("sendline", PASSWORD)]
    try:
        transcript = pwnrun.run_steps(tube, steps, timeout=5.0)
    finally:
        tube.close()

    assert how.startswith("process")
    received = "".join(e["data"] for e in transcript.entries if e["direction"] == "recv")
    assert "flag{symbolic_execution}" in received


def test_transcript_records_both_directions(target):
    tube, _ = pwnrun.open_tube(target("passcheck"), None, None)
    try:
        transcript = pwnrun.run_steps(
            tube, [pwnrun.Step("recv-until", b"password:"), pwnrun.Step("sendline", b"wrong")], 5.0
        )
    finally:
        tube.close()
    directions = {e["direction"] for e in transcript.entries}
    assert directions == {"recv", "send"}


def test_generated_script_is_valid_python(target):
    steps = [
        pwnrun.Step("recv-until", b"password:"),
        pwnrun.Step("sendline", PASSWORD),
        pwnrun.Step("send", b"\x41\x42"),
        pwnrun.Step("recv", 16),
        pwnrun.Step("sleep", 0.5),
    ]
    script = pwnrun.to_script(target("passcheck"), steps)
    ast.parse(script)
    assert "io.recvuntil(b'password:')" in script
    assert "io.sendline(b'ctf7wn')" in script


def test_step_codegen_round_trips():
    assert pwnrun.Step("recv", 8).code() == "io.recv(8)"
    assert pwnrun.Step("send", b"\x00\xff").code() == r"io.send(b'\x00\xff')"
    assert pwnrun.Step("sleep", 1.5).code() == "time.sleep(1.5)"
