"""pwngen writes scripts that parse, and for ret2win, actually land the flag."""

from __future__ import annotations

import ast
import subprocess
import sys

import pytest

from ctftools.core.binary import load_binary
from ctftools.tools import pwngen


@pytest.mark.parametrize(
    "path_name",
    ["ret2win", "ret2plt leak then ret2libc", "Shellcode on the stack", "execve syscall chain", "generic"],
)
def test_every_template_is_valid_python(target, path_name):
    info = load_binary(target("ret2win"))
    win = ("win", info.symbol("win") or 0)
    script = pwngen.generate(info, 56, path_name, win=win)
    ast.parse(script)


def test_prefix_is_sent_before_the_payload(target):
    info = load_binary(target("menu_prefix"))
    script = pwngen.generate(info, 88, "generic", prefix=b"1\n")
    ast.parse(script)
    assert "io.send(b'1\\n')" in script


def test_pie_template_warns_about_the_base(target):
    info = load_binary(target("pie_win"))
    script = pwngen.generate(info, 72, "ret2win", win=("win", 0x1189))
    assert "exe.address" in script


def test_generated_ret2win_exploit_actually_works(target, tmp_path):
    info = load_binary(target("ret2win"))
    script = pwngen.generate(info, 56, "ret2win", win=("win", info.symbol("win")))
    out = tmp_path / "exploit.py"
    out.write_text(script)

    proc = subprocess.run(
        [sys.executable, str(out)],
        capture_output=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
        cwd=tmp_path,
    )
    combined = proc.stdout + proc.stderr
    assert b"flag{ret2win_reached}" in combined, combined[-800:]
