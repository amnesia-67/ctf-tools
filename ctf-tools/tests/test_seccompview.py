"""The BPF decoder, against a filter whose rules we wrote by hand."""

from __future__ import annotations

import struct

import pytest

from ctftools.core import bpf
from ctftools.tools import seccompview

# The same filter seccomp_jail.c installs, packed by hand.
def _stmt(code, k):
    return struct.pack("<HBBI", code, 0, 0, k)


def _jump(code, k, jt, jf):
    return struct.pack("<HBBI", code, jt, jf, k)


FILTER = b"".join([
    _stmt(bpf.LD | bpf.W | bpf.ABS, 4),
    _jump(bpf.JMP | bpf.JEQ | bpf.K, bpf.AUDIT_ARCH_X86_64, 1, 0),
    _stmt(bpf.RET | bpf.K, 0x80000000),
    _stmt(bpf.LD | bpf.W | bpf.ABS, 0),
    _jump(bpf.JMP | bpf.JEQ | bpf.K, 59, 4, 0),    # execve
    _jump(bpf.JMP | bpf.JEQ | bpf.K, 322, 3, 0),   # execveat
    _jump(bpf.JMP | bpf.JEQ | bpf.K, 56, 2, 0),    # clone
    _jump(bpf.JMP | bpf.JEQ | bpf.K, 57, 1, 0),    # fork
    _stmt(bpf.RET | bpf.K, 0x7FFF0000),
    _stmt(bpf.RET | bpf.K, 0x80000000),
])


def test_disassembly_reads_the_fields():
    instructions = bpf.parse(FILTER)
    assert instructions[0].text() == "A = arch"
    assert instructions[3].text() == "A = nr"
    assert instructions[2].text() == "return KILL_PROCESS"
    assert instructions[8].text() == "return ALLOW"


def test_execve_is_killed_and_read_is_allowed():
    instructions = bpf.parse(FILTER)
    assert bpf.evaluate(instructions, 59).action == "KILL_PROCESS"     # execve
    assert bpf.evaluate(instructions, 322).action == "KILL_PROCESS"    # execveat
    assert bpf.evaluate(instructions, 0).action == "ALLOW"             # read
    assert bpf.evaluate(instructions, 1).action == "ALLOW"             # write
    assert bpf.evaluate(instructions, 257).action == "ALLOW"           # openat


def test_a_different_architecture_is_killed():
    instructions = bpf.parse(FILTER)
    assert bpf.evaluate(instructions, 0, arch=bpf.AUDIT_ARCH_I386).action == "KILL_PROCESS"


def test_summary_lists_the_four_blocked_syscalls():
    summary = bpf.summarise(bpf.parse(FILTER))
    blocked = {e["name"] for e in summary["blocked"]}
    assert {"execve", "execveat", "clone", "fork"} <= blocked
    assert "read" not in blocked
    assert summary["default_action"] == "ALLOW"


def test_errno_actions_keep_their_value():
    assert bpf.action_name(0x00050001) == "ERRNO(1)"
    assert bpf.action_name(0x7FFF0000) == "ALLOW"


def test_validator_accepts_a_real_filter_and_rejects_code(target):
    assert bpf.looks_like_filter(bpf.parse(FILTER))
    with open(target("stack_basic"), "rb") as fh:
        data = fh.read()
    # No 80-byte window of ordinary program text should pass as a filter.
    windows = [bpf.parse(data[i:i + 80]) for i in range(0, len(data) - 80, 61)]
    assert not any(bpf.looks_like_filter(w) for w in windows)


def test_filter_is_caught_at_runtime(target, have_gdb):
    if not have_gdb:
        pytest.skip("gdb is required")
    report = seccompview.view(target("seccomp_jail"), timeout=60.0)
    assert report.data["filter_found"] is True
    summary = report.data["summary"]
    assert summary["default_action"] == "ALLOW"
    assert "read" in summary["allowed"]
    assert "execve" not in summary["allowed"]


def test_binary_without_a_filter_reports_none(target):
    report = seccompview.view(target("stack_basic"), static_only=True)
    assert report.data["filter_found"] is False
