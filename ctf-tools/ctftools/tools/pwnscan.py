"""pwnscan: triage a binary, find the offset to the return address, and
decide which exploit path is actually open.

    pwnscan ./vuln
    pwnscan ./vuln --json
    pwnscan ./vuln --prefix '1\\n' --timeout 10
"""

from __future__ import annotations

import sys

from ctftools.core import gadgets as gadget_mod
from ctftools.core import paths as path_mod
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
from ctftools.core.offset import find_offset
from ctftools.core.report import Report

DESCRIPTION = """\
Run checksec on a binary, explain what each mitigation means, find the distance
from the input buffer to the saved return address, and verify which exploit
path that distance actually supports.
"""


def build_parser():
    parser = base_parser("pwnscan", DESCRIPTION)
    parser.add_argument("binary", help="the ELF to analyse")
    parser.add_argument("--no-offset", action="store_true", help="checksec only, do not run the target")
    parser.add_argument("--no-verify", action="store_true", help="do not test candidate exploit paths")
    parser.add_argument("--no-static", action="store_true", help="skip the static frame cross-check")
    parser.add_argument("--max-length", type=int, default=3000, help="longest pattern to try (default: 3000)")
    parser.add_argument("--gadgets", action="store_true", help="also list the gadgets that matter for the chosen path")
    add_run_args(parser)
    add_common_args(parser)
    return parser


def scan(path: str, run: bool = True, verify: bool = True, static: bool = True,
         prefix: bytes = b"", args=(), timeout: float = 5.0, sandbox: bool = True,
         max_length: int = 3000, show_gadgets: bool = False) -> Report:
    """Analyse *path* and return a filled report."""
    info = load_binary(path)
    report = Report(tool="pwnscan", target=path)
    report.data["binary"] = info.as_dict()

    _section_checksec(report, info)
    _section_inputs(report, info)

    offset_result = None
    if run:
        lengths = tuple(n for n in (200, 500, 1200, 3000) if n <= max_length) or (max_length,)
        offset_result = find_offset(
            info, prefix=prefix, args=args, timeout=timeout,
            lengths=lengths, sandbox=sandbox, static=static,
        )
        report.data["offset"] = offset_result.as_dict()
        _section_offset(report, info, offset_result)
    else:
        report.note("offset discovery skipped (--no-offset)")

    gadget_list = []
    try:
        gadget_list = gadget_mod.find_gadgets(info, max_instructions=5, max_bytes=16)
    except Exception as exc:
        report.warn(f"gadget scan failed: {exc}")

    exploit_paths = path_mod.rule(
        info, offset_result, gadget_list, verify=verify and run,
        prefix=prefix, args=args, timeout=timeout, sandbox=sandbox,
    )
    report.data["exploit_paths"] = [p.as_dict() for p in exploit_paths]
    _section_paths(report, exploit_paths)

    if show_gadgets:
        _section_gadgets(report, info, gadget_list)
    report.data["gadget_count"] = len(gadget_list)

    return report


# ----------------------------------------------------------------- sections
def _section_checksec(report: Report, info) -> None:
    sec = report.section("Checksec")
    rows = []
    for mitigation in info.mitigations():
        if mitigation.name in ("Linkage", "Symbols"):
            colour = term.dim(mitigation.value)
        elif mitigation.name == "RWX segments":
            colour = term.bad(mitigation.value) if not mitigation.enabled else term.good(mitigation.value)
        else:
            colour = term.good(mitigation.value) if mitigation.enabled else term.bad(mitigation.value)
        rows.append([mitigation.name, colour, term.dim(mitigation.impact)])
    sec.add(term.table(rows, headers=["Mitigation", "State", "What it means"]))
    sec.add("")
    sec.add(f"  {term.dim('arch')}    {info.arch} / {info.bits}-bit / {info.endian} endian")
    sec.add(f"  {term.dim('sha256')}  {info.sha256[:32]}...")


def _section_inputs(report: Report, info) -> None:
    sec = report.section("Input and attack surface")
    if info.input_sinks:
        rows = [
            [name, term.good("bounded") if bounded else term.bad("unbounded"), term.dim(note)]
            for name, bounded, note in info.input_sinks
        ]
        sec.add(term.table(rows, headers=["Sink", "Bounded", "Note"]))
    else:
        sec.add("  " + term.dim("no classic input sink imported; the read may be inlined or a syscall"))

    wins = info.win_candidates()
    if wins:
        sec.add("")
        sec.add("  " + term.c("interesting functions:", "bold"))
        sec.add(term.table([[name, hex(addr)] for name, addr in wins], indent=4))
    if info.useful_imports:
        sec.add("")
        names = ", ".join(sorted(info.useful_imports))
        sec.add(f"  {term.dim('imports:')} {names}")


def _section_offset(report: Report, info, result) -> None:
    sec = report.section("Offset to the saved return address")

    status_colour = {
        "confirmed": term.good,
        "likely": term.warn,
        "canary-blocked": term.warn,
        "unknown": term.bad,
    }.get(result.status, term.dim)

    if result.offset is not None:
        headline = f"{result.offset} bytes"
        sec.add(f"  {term.c(headline, 'bold')}   {status_colour(result.status)}")
    else:
        sec.add("  " + term.bad("not found"))

    rows = [
        ["method", result.method or "-"],
        ["pattern length", str(result.pattern_length or "-")],
        ["static cross-check", result.agreement],
        ["instruction pointer control", term.good("yes") if result.pc_control else term.bad("no")],
    ]
    if result.buffer_size is not None:
        rows.append(["buffer size (static)", f"{result.buffer_size} bytes"])
    if result.canary_offset is not None:
        rows.append(["canary at", f"{result.canary_offset} bytes"])
    if result.verification:
        marker = result.verification.get("marker")
        observed = result.verification.get("observed_pc")
        where = result.verification.get("where")
        if result.verification.get("matched"):
            text = term.good(f"marker {marker:#x} landed in the {where}")
        else:
            seen = f", observed {observed:#x}" if observed else ""
            text = term.warn(f"marker {marker:#x} not reproduced{seen}")
        rows.append(["verification", text])
    sec.add(term.table(rows))

    if result.static_note:
        sec.add("")
        sec.add("  " + term.dim(result.static_note))

    if result.offset is not None and result.pc_control:
        sec.add("")
        sec.add("  " + term.c("payload skeleton:", "bold"))
        pack = "p64" if info.bits == 64 else "p32"
        sec.add(f"    payload = b'A' * {result.offset} + {pack}(target_address)")

    for note in result.notes:
        report.note(note)


def _section_paths(report: Report, exploit_paths) -> None:
    sec = report.section("Exploit paths")
    if not exploit_paths:
        sec.add("  " + term.dim("no path identified"))
        return

    for path in exploit_paths:
        badge = {
            "proven": term.good("[proven]"),
            "open": term.good("[open]"),
            "tried, failed": term.bad("[tried, failed]"),
            "blocked": term.dim("[blocked]"),
        }.get(path.verdict, term.dim(f"[{path.verdict}]"))
        sec.add(f"  {badge} {term.c(path.name, 'bold')}")
        sec.add(f"      {term.dim(path.summary)}")
        for req in path.requirements:
            mark = term.good("yes") if req.met else term.bad("no ")
            detail = term.dim(f" - {req.detail}") if req.detail else ""
            sec.add(f"      {mark}  {req.text}{detail}")
        if path.verification_detail:
            sec.add(f"      {term.c('verified:', 'bold')} {path.verification_detail}")
        if path.next_step:
            sec.add(f"      {term.dim('next:')} {path.next_step}")
        sec.add("")


def _section_gadgets(report: Report, info, gadget_list) -> None:
    sec = report.section("Key gadgets")
    queries = ["pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rax ; ret",
               "syscall", "jmp rsp", "leave ; ret"]
    rows = []
    for query in queries:
        gadget = gadget_mod.best(gadget_list, query)
        rows.append([query, hex(gadget.address) if gadget else term.dim("not found"),
                     gadget.text if gadget else ""])
    sec.add(term.table(rows, headers=["Wanted", "Address", "Gadget"]))
    sec.add("")
    sec.add(f"  {term.dim('total unique gadgets:')} {len(gadget_list)}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)
    path = resolve_binary(args.binary)

    report = scan(
        path,
        run=not args.no_offset,
        verify=not args.no_verify,
        static=not args.no_static,
        prefix=parse_escapes(args.prefix),
        args=args.argv,
        timeout=args.timeout,
        sandbox=not args.no_sandbox,
        max_length=args.max_length,
        show_gadgets=args.gadgets,
    )
    report.emit(as_json=args.json)
    offset = report.data.get("offset") or {}
    return 0 if offset.get("offset") is not None or args.no_offset else 1


if __name__ == "__main__":
    sys.exit(main())
