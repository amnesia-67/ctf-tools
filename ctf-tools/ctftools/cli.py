"""The ``ctftools`` umbrella command: a dispatcher for every tool."""

from __future__ import annotations

import importlib
import sys

from ctftools import TOOLS, __version__

SUMMARIES = {
    "pwnscan": "checksec, offset to the return address, and a verified exploit path",
    "pwngen": "write an exploit.py from a pwnscan result",
    "vulnhunt": "static scan for overflow and format string sinks",
    "fuzzlite": "fuzz the input surface and classify the crashes",
    "seccompview": "dump and decode a binary's seccomp filter",
    "gadgetfind": "search ROP gadgets with bad-byte filtering",
    "ropchain": "build ret2plt, ret2libc and execve chains",
    "sropkit": "build SROP frames and ret2dlresolve payloads",
    "shellgen": "generate and test shellcode",
    "pwninit_lite": "patch a binary to run against a challenge libc",
    "fmtool": "find the format string offset and build writes",
    "canbrute": "brute force canaries and addresses against a forking server",
    "stackviz": "draw the stack frame and overlay a payload",
    "heapscope": "inspect glibc heap state through GDB",
    "symwin": "use angr to reach a chosen function",
    "pwnrun": "one runner for local, GDB and remote targets",
}

ALIASES = {"pwninit-lite": "pwninit_lite"}


def usage() -> str:
    lines = [
        f"ctftools {__version__} - a binary exploitation toolkit",
        "",
        "usage: ctftools <tool> [options]",
        "",
        "tools:",
    ]
    width = max(len(name) for name in TOOLS)
    for name in TOOLS:
        display = name.replace("_", "-")
        lines.append(f"  {display.ljust(width)}  {SUMMARIES.get(name, '')}")
    lines += [
        "",
        "Every tool is also installed as its own command, and accepts --help and --json.",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(usage())
        return 0
    if argv[0] in ("-V", "--version"):
        print(f"ctftools {__version__}")
        return 0

    name = ALIASES.get(argv[0], argv[0].replace("-", "_"))
    if name not in TOOLS:
        print(f"ctftools: unknown tool {argv[0]!r}\n", file=sys.stderr)
        print(usage(), file=sys.stderr)
        return 2

    module = importlib.import_module(f"ctftools.tools.{name}")
    return module.main(argv[1:]) or 0


if __name__ == "__main__":
    sys.exit(main())
