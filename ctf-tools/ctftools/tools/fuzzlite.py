"""fuzzlite: a small, targeted fuzzer for CTF binaries.

Not a coverage-guided fuzzer: a quick sweep of the inputs that break CTF
binaries (long strings, format specifiers, integer boundaries, menu choices),
with every crash classified and deduplicated by where it happened.

    fuzzlite ./vuln
    fuzzlite ./vuln --prefix '1\\n' --save crashes/
    fuzzlite ./vuln --cases 400 --json
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from ctftools.core import term
from ctftools.core.binary import load_binary
from ctftools.core.cliutil import (
    add_common_args,
    add_run_args,
    apply_output_flags,
    base_parser,
    parse_escapes,
    resolve_binary,
)
from ctftools.core.crash import gdb_available, gdb_crash
from ctftools.core.report import Report
from ctftools.core.runner import Limits, run_target

INTEGERS = [
    "0", "-1", "1", "2147483647", "-2147483648", "4294967295", "4294967296",
    "9223372036854775807", "-9223372036854775808", "018446744073709551616",
    "0x41414141", "+0", "   -1", "1e9", "NaN", "",
]
FORMATS = [
    "%p", "%p" * 8, "%s", "%s" * 8, "%n", "%n" * 4,
    "%999999999s", "%1$p", "%100$p", "%hn", "AAAA" + "%p" * 20,
    "%x" * 40, "%.2000d%n",
]
METACHARS = ["; id", "$(id)", "`id`", "| id", "../" * 16, "\x00AAAA", "\n\n\n\n"]


@dataclass
class Case:
    """One fuzz input and what the target did with it."""

    name: str
    payload: bytes
    classification: str = ""
    pc: int | None = None
    stderr_hint: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "payload": self.payload.decode("latin-1"),
            "payload_length": len(self.payload),
            "classification": self.classification,
            "pc": self.pc,
            "hint": self.stderr_hint,
        }


@dataclass
class FuzzResult:
    cases_run: int = 0
    crashes: list = field(default_factory=list)
    unique: dict = field(default_factory=dict)
    leaks: list = field(default_factory=list)


def generate(word: int = 8, cases: int = 200, prefix: bytes = b"") -> list:
    """The input corpus, in the order worth trying."""
    from pwnlib.util.cyclic import cyclic

    out: list[Case] = []
    for length in (16, 32, 64, 100, 128, 200, 256, 512, 1024, 2048, 4096):
        out.append(Case(f"cyclic-{length}", prefix + cyclic(length, n=word) + b"\n"))
    for length in (64, 256, 1024):
        out.append(Case(f"repeat-A-{length}", prefix + b"A" * length + b"\n"))
        out.append(Case(f"repeat-nul-{length}", prefix + b"\x00" * length + b"\n"))
        out.append(Case(f"high-bytes-{length}", prefix + bytes([0xFF]) * length + b"\n"))
    for text in FORMATS:
        out.append(Case(f"format:{text[:16]}", prefix + text.encode() + b"\n"))
    for text in INTEGERS:
        out.append(Case(f"int:{text.strip() or 'empty'}", prefix + text.encode() + b"\n"))
    for text in METACHARS:
        out.append(Case(f"meta:{text[:12]!r}", prefix + text.encode("latin-1") + b"\n"))
    out.append(Case("empty", prefix))
    out.append(Case("newlines", prefix + b"\n" * 64))
    out.append(Case("no-newline-long", prefix + b"B" * 4096))

    # Menu-style programs: try each choice on its own.
    for choice in range(0, 10):
        out.append(Case(f"menu:{choice}", f"{choice}\n".encode() + b"A" * 512 + b"\n"))

    return out[:cases]


def fuzz(path: str, prefix: bytes = b"", args=(), timeout: float = 3.0,
         cases: int = 200, sandbox: bool = True, triage: bool = True,
         save_dir: str | None = None) -> Report:
    info = load_binary(path)
    report = Report(tool="fuzzlite", target=path)
    limits = Limits(enabled=sandbox)

    corpus = generate(info.word, cases, prefix)
    result = FuzzResult()
    baseline = run_target(path, prefix + b"\n", args=args, timeout=timeout, limits=limits)

    for case in corpus:
        run = run_target(path, case.payload, args=args, timeout=timeout, limits=limits)
        result.cases_run += 1
        case.classification = run.classify()

        # A format string that leaks stack memory shows up as hex in the output.
        if case.name.startswith("format:") and _looks_like_leak(run.stdout, baseline.stdout):
            result.leaks.append({
                "payload": case.payload.decode("latin-1"),
                "output": run.stdout[:200].decode("latin-1", "replace"),
            })

        if not (run.crashed or run.timed_out):
            continue

        if run.stderr:
            case.stderr_hint = run.stderr.strip().splitlines()[-1][:120].decode("latin-1", "replace")

        if triage and gdb_available() and not run.timed_out:
            state = gdb_crash(path, case.payload, args=args, bits=info.bits, timeout=max(20.0, timeout * 5))
            case.pc = state.pc
            if state.canary_abort:
                case.classification = "canary-abort"

        result.crashes.append(case)
        key = (case.classification, case.pc)
        result.unique.setdefault(key, case)

    report.data.update({
        "cases_run": result.cases_run,
        "crashes": len(result.crashes),
        "unique_crashes": len(result.unique),
        "findings": [c.as_dict() for c in result.unique.values()],
        "format_string_leaks": result.leaks,
    })

    if save_dir and result.unique:
        os.makedirs(save_dir, exist_ok=True)
        for index, case in enumerate(result.unique.values()):
            name = f"{index:02d}-{case.classification}-{case.name.replace('/', '_')[:40]}.bin"
            with open(os.path.join(save_dir, name), "wb") as fh:
                fh.write(case.payload)
        report.data["saved_to"] = os.path.abspath(save_dir)

    _render(report, result, save_dir)
    return report


def _looks_like_leak(output: bytes, baseline: bytes) -> bool:
    new = output.replace(baseline, b"", 1)
    return b"0x" in new and any(c in new for c in b"abcdef0123456789")


def _render(report: Report, result: FuzzResult, save_dir: str | None) -> None:
    sec = report.section("Run")
    sec.add(f"  {result.cases_run} inputs, {len(result.crashes)} crashes, "
            f"{term.c(str(len(result.unique)), 'bold')} unique")

    findings = report.section(f"Unique crashes ({len(result.unique)})")
    if not result.unique:
        findings.add("  " + term.dim("nothing crashed; try --prefix to get past a menu, or --cases 400"))
    else:
        rows = []
        for case in result.unique.values():
            rows.append([
                _classification_colour(case.classification),
                case.name,
                str(len(case.payload)),
                hex(case.pc) if case.pc else term.dim("-"),
                term.dim(case.stderr_hint),
            ])
        findings.add(term.table(rows, headers=["Class", "Input", "Bytes", "PC", "Hint"]))

    if result.leaks:
        leaks = report.section(f"Format string leaks ({len(result.leaks)})")
        for leak in result.leaks[:5]:
            leaks.add(f"  {term.bad(leak['payload'].strip())} -> {term.dim(leak['output'][:100])}")
        leaks.add("")
        leaks.add("  " + term.dim("printf is printing stack memory: run fmtool to turn this into a read/write"))

    if any(c.classification == "segfault" for c in result.unique.values()):
        report.note("a segfault on a long input means an overflow: run pwnscan for the exact offset")
    if any(c.classification == "canary-abort" for c in result.unique.values()):
        report.note("the canary aborts before the return address is used: leak it or brute force it")
    if save_dir and result.unique:
        report.note(f"crashing inputs written to {save_dir}")


def _classification_colour(classification: str) -> str:
    if classification in ("segfault", "bus-error", "illegal-instruction"):
        return term.bad(classification)
    if classification in ("canary-abort", "heap-abort", "abort"):
        return term.warn(classification)
    return term.dim(classification)


def build_parser():
    parser = base_parser("fuzzlite", "Fuzz a binary's input surface and classify the crashes.")
    parser.add_argument("binary", help="the ELF to fuzz")
    parser.add_argument("--cases", type=int, default=200, help="how many inputs to try (default: 200)")
    parser.add_argument("--save", dest="save_dir", help="write one file per unique crash into this directory")
    parser.add_argument("--no-triage", action="store_true", help="do not re-run crashes under GDB for the PC")
    add_run_args(parser)
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)
    report = fuzz(
        resolve_binary(args.binary),
        prefix=parse_escapes(args.prefix),
        args=args.argv,
        timeout=args.timeout if args.timeout else 3.0,
        cases=args.cases,
        sandbox=not args.no_sandbox,
        triage=not args.no_triage,
        save_dir=args.save_dir,
    )
    report.emit(as_json=args.json)
    return 0 if report.data.get("unique_crashes") else 1


if __name__ == "__main__":
    sys.exit(main())
