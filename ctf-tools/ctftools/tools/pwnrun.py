"""pwnrun: one runner for local, GDB and remote, with a script recorder.

Drive a target through a few steps from the command line, see the whole
transcript, and get the pwntools code that reproduces it.

    pwnrun ./vuln -r 'input:' -s 'hello' -r 'done'
    pwnrun --remote 10.0.0.1 1337 -r '> ' -x 4141414141414141
    pwnrun ./vuln --record < session.txt
    pwnrun ./vuln -r 'input:' -s AAAA --script solve.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from ctftools.core import term
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail, parse_escapes
from ctftools.core.report import Report


@dataclass
class Step:
    """One thing to do to the target."""

    kind: str          # recv-until | recv | send | sendline | sleep
    value: object = b""

    def code(self) -> str:
        if self.kind == "recv-until":
            return f"io.recvuntil({self.value!r})"
        if self.kind == "recv":
            return f"io.recv({self.value})"
        if self.kind == "send":
            return f"io.send({self.value!r})"
        if self.kind == "sendline":
            return f"io.sendline({self.value!r})"
        if self.kind == "sleep":
            return f"time.sleep({self.value})"
        return f"# unknown step {self.kind}"

    def as_dict(self) -> dict:
        value = self.value
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        return {"kind": self.kind, "value": value}


@dataclass
class Transcript:
    entries: list = field(default_factory=list)

    def add(self, direction: str, data: bytes) -> None:
        self.entries.append({"direction": direction, "data": data.decode("latin-1", "replace")})

    def render(self) -> list:
        lines = []
        for entry in self.entries:
            arrow = term.good("<-") if entry["direction"] == "recv" else term.warn("->")
            for line in entry["data"].splitlines() or [""]:
                lines.append(f"  {arrow} {line}")
        return lines


def open_tube(binary: str | None, host: str | None, port: int | None,
              gdb_break: str | None = None, timeout: float = 5.0):
    from pwnlib.context import context

    context.clear()
    context.log_level = "error"
    context.timeout = timeout

    if host:
        from pwnlib.tubes.remote import remote

        return remote(host, port), f"remote({host!r}, {port})"
    if gdb_break:
        from pwnlib import gdb as pwngdb

        return (pwngdb.debug([binary], gdbscript=f"break {gdb_break}\ncontinue"),
                f"gdb.debug([exe.path], gdbscript=GDBSCRIPT)")
    from pwnlib.tubes.process import process

    return process([binary]), "process([exe.path])"


def run_steps(tube, steps: list, timeout: float = 5.0) -> Transcript:
    transcript = Transcript()
    for step in steps:
        if step.kind == "recv-until":
            data = tube.recvuntil(step.value, timeout=timeout)
            transcript.add("recv", data or b"")
        elif step.kind == "recv":
            data = tube.recv(step.value, timeout=timeout)
            transcript.add("recv", data or b"")
        elif step.kind == "send":
            tube.send(step.value)
            transcript.add("send", step.value)
        elif step.kind == "sendline":
            tube.sendline(step.value)
            transcript.add("send", step.value + b"\n")
        elif step.kind == "sleep":
            import time

            time.sleep(step.value)
    try:
        tail = tube.recvrepeat(min(timeout, 1.0))
        if tail:
            transcript.add("recv", tail)
    except Exception:
        pass
    return transcript


def record(tube, timeout: float = 5.0) -> tuple[list, Transcript]:
    """Read lines from our own stdin, send each one, and remember the exchange."""
    steps: list[Step] = []
    transcript = Transcript()

    banner = tube.recvrepeat(min(timeout, 1.0))
    if banner:
        transcript.add("recv", banner)
        steps.append(Step("recv-until", banner.splitlines()[-1] if banner.splitlines() else banner))

    for raw in sys.stdin.buffer:
        line = raw.rstrip(b"\n")
        tube.sendline(line)
        steps.append(Step("sendline", line))
        transcript.add("send", line + b"\n")
        reply = tube.recvrepeat(min(timeout, 1.0))
        if reply:
            transcript.add("recv", reply)
            tail = reply.splitlines()[-1] if reply.splitlines() else reply
            steps.append(Step("recv-until", tail))
    return steps, transcript


SCRIPT = '''\
#!/usr/bin/env python3
# Recorded by ctftools pwnrun.
from pwn import *

exe = context.binary = ELF({binary!r}, checksec=False)

GDBSCRIPT = """
break main
continue
"""


def start():
    if args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=GDBSCRIPT)
    return process([exe.path])


io = start()

{steps}

io.interactive()
'''


def to_script(binary: str, steps: list) -> str:
    body = "\n".join(step.code() for step in steps) or "# no steps recorded"
    return SCRIPT.format(binary=binary or "./target", steps=body)


def parse_steps(args) -> list:
    """Turn the ordered command line flags into steps."""
    steps = []
    for kind, value in args.steps:
        if kind == "recv-until":
            steps.append(Step("recv-until", parse_escapes(value)))
        elif kind == "recv":
            steps.append(Step("recv", int(value)))
        elif kind == "send":
            steps.append(Step("send", parse_escapes(value)))
        elif kind == "sendline":
            steps.append(Step("sendline", parse_escapes(value)))
        elif kind == "sendhex":
            steps.append(Step("send", bytes.fromhex(value.replace(" ", ""))))
        elif kind == "sleep":
            steps.append(Step("sleep", float(value)))
    return steps


class _Ordered:
    """Collect -r/-s/-l/-x into one ordered list instead of separate ones."""

    def __init__(self, kind):
        self.kind = kind

    def __call__(self, parser, namespace, value, option_string=None):
        namespace.steps.append((self.kind, value))


def build_parser():
    import argparse

    parser = base_parser("pwnrun", "Drive a target locally, under GDB or remotely, and record the script.")
    parser.add_argument("binary", nargs="?", help="the local ELF to run")
    parser.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"), help="connect to a remote service")
    parser.add_argument("--gdb", dest="gdb_break", metavar="SYMBOL", help="run under GDB, breaking here")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-step timeout (default: 5s)")
    parser.add_argument("--record", action="store_true", help="read lines from stdin and record the session")
    parser.add_argument("--script", metavar="FILE", help="write a pwntools script of the session here")
    parser.add_argument("--interactive", action="store_true", help="hand the connection over when the steps are done")

    class Action(argparse.Action):
        def __init__(self, option_strings, dest, kind=None, **kwargs):
            self.kind = kind
            super().__init__(option_strings, dest, **kwargs)

        def __call__(self, parser_, namespace, value, option_string=None):
            namespace.steps.append((self.kind, value))

    steps = parser.add_argument_group("steps, applied in the order you give them")
    steps.add_argument("-r", "--recv-until", action=Action, kind="recv-until", dest="steps",
                       default=[], metavar="TEXT", help="read until this text appears")
    steps.add_argument("-n", "--recv", action=Action, kind="recv", dest="steps",
                       metavar="N", help="read N bytes")
    steps.add_argument("-s", "--send", action=Action, kind="send", dest="steps",
                       metavar="DATA", help="send these bytes (python escapes)")
    steps.add_argument("-l", "--sendline", action=Action, kind="sendline", dest="steps",
                       metavar="DATA", help="send these bytes and a newline")
    steps.add_argument("-x", "--sendhex", action=Action, kind="sendhex", dest="steps",
                       metavar="HEX", help="send these bytes, given as hex")
    steps.add_argument("--sleep", action=Action, kind="sleep", dest="steps",
                       metavar="SECONDS", help="wait")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)

    host = port = None
    if args.remote:
        host, port = args.remote[0], int(args.remote[1])
    elif not args.binary:
        fail("give a local binary, or --remote HOST PORT")

    try:
        steps = parse_steps(args)
    except ValueError as exc:
        fail(str(exc))

    tube, how = open_tube(args.binary, host, port, args.gdb_break, args.timeout)
    report = Report(tool="pwnrun", target=args.binary or f"{host}:{port}")

    try:
        if args.record:
            steps, transcript = record(tube, args.timeout)
        else:
            transcript = run_steps(tube, steps, args.timeout)
        if args.interactive:
            tube.interactive()
    finally:
        try:
            tube.close()
        except Exception:
            pass

    report.data.update({
        "connection": how,
        "steps": [s.as_dict() for s in steps],
        "transcript": transcript.entries,
    })

    sec = report.section("Session")
    sec.add(f"  {term.dim('connection:')} {how}")
    sec.add("")
    for line in transcript.render():
        sec.add(line)

    script = to_script(args.binary, steps)
    report.data["script"] = script
    if args.script:
        with open(args.script, "w") as fh:
            fh.write(script)
        import os

        os.chmod(args.script, 0o755)
        report.data["script_path"] = os.path.abspath(args.script)
        written = report.section("Script")
        written.add(f"  {term.good(args.script)} written")
    elif args.record:
        written = report.section("Script")
        for line in script.splitlines():
            written.add(f"    {line}")

    report.emit(as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
