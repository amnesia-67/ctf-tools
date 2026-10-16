"""gadgetfind: ranked ROP gadget search with bad-byte filtering.

    gadgetfind ./vuln                          # the gadgets that matter, ranked
    gadgetfind ./vuln 'pop rdi ; ret'          # a specific gadget
    gadgetfind ./libc.so.6 'pop ? ; ret' --bad '0a00'
    gadgetfind ./vuln --all --json
"""

from __future__ import annotations

import sys

from ctftools.core import gadgets as gadget_mod
from ctftools.core import term
from ctftools.core.binary import load_binary
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail, resolve_binary
from ctftools.core.report import Report

# The gadgets worth knowing about before anything else, in the order a chain
# usually needs them.
WANTED_64 = [
    ("pop rdi ; ret", "first argument"),
    ("pop rsi ; ret", "second argument"),
    ("pop rdx ; ret", "third argument"),
    ("pop rcx ; ret", "fourth argument"),
    ("pop rax ; ret", "syscall number"),
    ("syscall", "syscall"),
    ("ret", "stack alignment"),
    ("leave ; ret", "stack pivot through rbp"),
    ("pop rsp", "stack pivot"),
    ("jmp rsp", "jump into the buffer"),
    ("mov qword ptr [?], ?", "write what where"),
    ("xchg ?, rsp", "stack pivot"),
]
WANTED_32 = [
    ("pop ebx ; ret", "first argument"),
    ("pop ecx ; ret", "second argument"),
    ("pop edx ; ret", "third argument"),
    ("pop eax ; ret", "syscall number"),
    ("int 0x80", "syscall"),
    ("ret", "stack alignment"),
    ("leave ; ret", "stack pivot through ebp"),
    ("jmp esp", "jump into the buffer"),
]


def find(path: str, query: str | None = None, bad: bytes = b"", base: int | None = None,
         max_instructions: int = 6, show_all: bool = False, limit: int = 40) -> Report:
    info = load_binary(path)
    report = Report(tool="gadgetfind", target=path)

    all_gadgets = gadget_mod.find_gadgets(info, max_instructions=max_instructions, base=base)
    usable = gadget_mod.without_badchars(all_gadgets, bad, info.bits)
    filtered_out = len(all_gadgets) - len(usable)

    report.data["gadget_count"] = len(all_gadgets)
    report.data["usable_count"] = len(usable)
    report.data["bad_bytes"] = bad.hex()
    if info.pie and base is None:
        report.warn("the binary is PIE: these are offsets, pass --base <leaked base> for real addresses")

    if query:
        matches = gadget_mod.search(usable, query)
        matches.sort(key=lambda g: (len(g.instructions), g.address))
        report.data["query"] = query
        report.data["matches"] = [g.as_dict() for g in matches[:limit if not show_all else len(matches)]]
        sec = report.section(f"Gadgets matching {query!r} ({len(matches)})")
        if not matches:
            sec.add("  " + term.dim("nothing matched"))
            if filtered_out:
                sec.add("  " + term.dim(f"{filtered_out} gadgets were dropped for containing a bad byte"))
        else:
            shown = matches if show_all else matches[:limit]
            sec.add(term.table(
                [[term.c(hex(g.address), "cyan"), g.text] for g in shown],
                headers=["Address", "Gadget"],
            ))
            if not show_all and len(matches) > limit:
                sec.add("  " + term.dim(f"... {len(matches) - limit} more, pass --all"))
        return report

    wanted = WANTED_64 if info.bits == 64 else WANTED_32
    rows = []
    summary = {}
    for pattern, purpose in wanted:
        gadget = gadget_mod.best(usable, pattern)
        summary[pattern] = gadget.as_dict() if gadget else None
        rows.append([
            pattern,
            term.c(hex(gadget.address), "cyan") if gadget else term.bad("not found"),
            gadget.text if gadget else "",
            term.dim(purpose),
        ])
    report.data["key_gadgets"] = summary

    sec = report.section("Key gadgets")
    sec.add(term.table(rows, headers=["Wanted", "Address", "Gadget", "Use"]))
    sec.add("")
    found = sum(1 for v in summary.values() if v)
    sec.add(f"  {found}/{len(wanted)} found, {len(usable)} usable gadgets in total"
            + (f", {filtered_out} dropped for bad bytes" if filtered_out else ""))

    if show_all:
        listing = report.section(f"All gadgets ({len(usable)})")
        listing.add(term.table([[hex(g.address), g.text] for g in usable], headers=["Address", "Gadget"]))
        report.data["gadgets"] = [g.as_dict() for g in usable]

    _chain_readiness(report, info, summary)
    return report


def _chain_readiness(report: Report, info, summary: dict) -> None:
    """Say which chain the available gadgets are enough for."""
    sec = report.section("What these gadgets support")
    have = {k: v is not None for k, v in summary.items()}

    if info.bits == 64:
        checks = [
            ("ret2libc (one argument)", ["pop rdi ; ret"]),
            ("execve syscall chain", ["pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rax ; ret", "syscall"]),
            ("stack pivot", ["leave ; ret"]),
            ("jump into the buffer", ["jmp rsp"]),
        ]
    else:
        checks = [
            ("ret2libc (stack arguments)", ["ret"]),
            ("int 0x80 execve chain", ["pop ebx ; ret", "pop ecx ; ret", "pop edx ; ret", "pop eax ; ret", "int 0x80"]),
            ("stack pivot", ["leave ; ret"]),
        ]

    rows = []
    for name, needed in checks:
        missing = [n for n in needed if not have.get(n)]
        rows.append([
            term.good("yes") if not missing else term.bad("no"),
            name,
            term.dim("missing: " + ", ".join(missing)) if missing else "",
        ])
    sec.add(term.table(rows))
    report.data["chain_readiness"] = {
        name: {"ready": not [n for n in needed if not have.get(n)],
               "missing": [n for n in needed if not have.get(n)]}
        for name, needed in checks
    }


def build_parser():
    parser = base_parser("gadgetfind", "Search ROP gadgets, filter bad bytes, and say what they support.")
    parser.add_argument("binary", help="the ELF to search (a binary or a libc)")
    parser.add_argument("query", nargs="?", help="gadget query, e.g. 'pop rdi ; ret' ('?' matches a register)")
    parser.add_argument("--bad", default="", help="bad bytes as hex, e.g. 000a20; gadget addresses containing one are dropped")
    parser.add_argument("--base", type=lambda v: int(v, 0), default=None,
                        help="load address to add to every gadget (for PIE or libc)")
    parser.add_argument("--max-instructions", type=int, default=6, help="longest gadget to report (default: 6)")
    parser.add_argument("--all", action="store_true", dest="show_all", help="list every gadget, not just the top matches")
    parser.add_argument("--limit", type=int, default=40, help="matches to show without --all (default: 40)")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)

    try:
        bad = bytes.fromhex(args.bad.replace("0x", "").replace("\\x", "").replace(" ", ""))
    except ValueError:
        fail(f"--bad must be hex, got {args.bad!r}")

    report = find(
        resolve_binary(args.binary),
        query=args.query,
        bad=bad,
        base=args.base,
        max_instructions=args.max_instructions,
        show_all=args.show_all,
        limit=args.limit,
    )
    report.emit(as_json=args.json)
    if args.query:
        return 0 if report.data.get("matches") else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
