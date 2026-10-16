"""Argument parsing helpers shared by every tool's CLI."""

from __future__ import annotations

import argparse
import os
import sys

from ctftools import __version__
from ctftools.core import term


def base_parser(prog: str, description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"ctftools {__version__}")
    return parser


def add_common_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Flags every tool accepts."""
    group = parser.add_argument_group("output")
    group.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of a report")
    group.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    group.add_argument("-q", "--quiet", action="store_true", help="only print the essentials")
    return parser


def add_run_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Flags for tools that execute the target."""
    group = parser.add_argument_group("execution")
    group.add_argument("--timeout", type=float, default=5.0, help="wall clock timeout per run (default: 5s)")
    group.add_argument("--arg", action="append", default=[], dest="argv",
                       help="argument passed to the target (repeatable)")
    group.add_argument("--no-sandbox", action="store_true",
                       help="do not apply CPU/memory/core limits to the target")
    group.add_argument("--prefix", default=None,
                       help="bytes sent before the payload, e.g. menu choices (python escapes allowed)")
    return parser


def apply_output_flags(args) -> None:
    if getattr(args, "no_color", False) or getattr(args, "json", False):
        term.set_color(False)


def resolve_binary(path: str) -> str:
    """Check that *path* is an executable file and return its absolute path."""
    full = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(full):
        fail(f"no such file: {path}")
    if os.path.isdir(full):
        fail(f"{path} is a directory")
    with open(full, "rb") as fh:
        if fh.read(4) != b"\x7fELF":
            fail(f"{path} is not an ELF file")
    return full


def parse_escapes(value: str | None) -> bytes:
    """Turn a command-line string with python escapes into bytes."""
    if value is None:
        return b""
    return value.encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1")


def fail(message: str, code: int = 2):
    sys.stderr.write(term.bad(f"error: {message}") + "\n")
    raise SystemExit(code)
