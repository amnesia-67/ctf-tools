"""The gadget engine finds the gadgets we planted, and only the real ones."""

from __future__ import annotations

from ctftools.core import gadgets as gadget_mod
from ctftools.core.binary import load_binary
from ctftools.tools import gadgetfind


def test_planted_gadgets_are_found(target):
    info = load_binary(target("nx_rop"))
    found = gadget_mod.find_gadgets(info)
    for wanted in ["pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rax ; ret", "syscall"]:
        assert gadget_mod.best(found, wanted) is not None, wanted


def test_leave_ret_is_a_gadget_not_a_terminator(target):
    info = load_binary(target("nx_rop"))
    gadget = gadget_mod.best(gadget_mod.find_gadgets(info), "leave ; ret")
    assert gadget is not None
    assert gadget.text.endswith("leave ; ret")


def test_gadget_bytes_match_their_address(target):
    info = load_binary(target("nx_rop"))
    gadget = gadget_mod.best(gadget_mod.find_gadgets(info), "pop rdi ; ret")
    assert gadget.bytes_ == b"\x5f\xc3"
    data = info.elf.read(gadget.address, len(gadget.bytes_))
    assert data == gadget.bytes_


def test_wildcard_query(target):
    info = load_binary(target("nx_rop"))
    found = gadget_mod.find_gadgets(info)
    assert gadget_mod.search(found, "pop ? ; ret")
    assert not gadget_mod.search(found, "pop rdi ; pop rdi ; pop rdi ; ret")


def test_bad_bytes_drop_the_matching_addresses(target):
    info = load_binary(target("nx_rop"))
    found = gadget_mod.find_gadgets(info)
    pop_rdi = gadget_mod.best(found, "pop rdi ; ret")
    bad = bytes([pop_rdi.address & 0xFF])
    survivors = gadget_mod.without_badchars(found, bad, info.bits)
    assert pop_rdi not in survivors
    assert all(bad[0] not in g.address.to_bytes(8, "little") for g in survivors)


def test_chain_readiness_is_reported(target):
    report = gadgetfind.find(target("nx_rop"))
    readiness = report.data["chain_readiness"]
    assert readiness["execve syscall chain"]["ready"] is True
    assert readiness["ret2libc (one argument)"]["ready"] is True


def test_query_mode_returns_matches(target):
    report = gadgetfind.find(target("nx_rop"), query="pop rdi ; ret")
    assert report.data["matches"]
    assert report.data["matches"][0]["text"] == "pop rdi ; ret"
