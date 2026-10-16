"""heapscope: look at the glibc heap through GDB.

Walks the chunks, reads the tcache, and reports what is wrong with the
state: a pointer in a bin twice, a size that walks off the heap, a
prev_size that disagrees with the chunk before it.

    heapscope ./chal --break getchar
    heapscope ./chal --break main --input 'd\\n'
    heapscope ./chal --json
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
    parse_escapes,
    resolve_binary,
)
from ctftools.core.crash import extract_json, gdb_available, run_gdb_script
from ctftools.core.report import Report

GDB_SCRIPT = r"""
break {breakpoint}
run {args} < {stdin}
python
import gdb, json

out = {"stopped": True, "heap": None, "chunks": [], "tcache": [], "errors": [], "libc": None}
inferior = gdb.selected_inferior()


def read(address, size):
    return bytes(inferior.read_memory(address, size))


def word(address):
    return int.from_bytes(read(address, 8), "little")


try:
    mappings = gdb.execute("info proc mappings", to_string=True)
except Exception as exc:
    mappings = ""
    out["errors"].append("mappings: %s" % exc)

out["mappings"] = mappings

heap_start = heap_end = None
for line in mappings.splitlines():
    parts = line.split()
    if len(parts) >= 5 and parts[-1] == "[heap]":
        heap_start, heap_end = int(parts[0], 16), int(parts[1], 16)
    if len(parts) >= 5 and "libc" in parts[-1] and out["libc"] is None:
        out["libc"] = parts[-1]

if heap_start is None:
    out["errors"].append("no [heap] mapping: nothing has been malloc'd yet")
else:
    out["heap"] = {"start": heap_start, "end": heap_end}
    cursor = heap_start
    guard = 0
    while cursor < heap_end and guard < 4096:
        guard += 1
        try:
            prev_size = word(cursor)
            size_field = word(cursor + 8)
        except Exception as exc:
            out["errors"].append("chunk read at %#x: %s" % (cursor, exc))
            break
        size = size_field & ~0x07
        chunk = {
            "address": cursor,
            "prev_size": prev_size,
            "size_field": size_field,
            "size": size,
            "prev_inuse": bool(size_field & 1),
            "is_mmapped": bool(size_field & 2),
            "non_main_arena": bool(size_field & 4),
        }
        try:
            chunk["fd"] = word(cursor + 16)
            chunk["bk"] = word(cursor + 24)
        except Exception:
            chunk["fd"] = chunk["bk"] = None
        out["chunks"].append(chunk)
        if size < 0x20 or cursor + size > heap_end:
            chunk["malformed"] = True
            break
        cursor += size

    # glibc >= 2.26 puts tcache_perthread_struct in the first heap chunk.
    try:
        tcache = heap_start + 0x10
        counts_are_short = True
        for index in range(64):
            if counts_are_short:
                raw = read(tcache + index * 2, 2)
                count = int.from_bytes(raw, "little")
                entry = word(tcache + 128 + index * 8)
            else:
                count = read(tcache + index, 1)[0]
                entry = word(tcache + 64 + index * 8)
            if count == 0 and entry == 0:
                continue
            bin_size = 0x20 + index * 0x10
            chain = []
            pointer = entry
            seen = set()
            corrupt = None
            while pointer and len(chain) < 32:
                chain.append(pointer)
                if pointer in seen:
                    break
                seen.add(pointer)
                try:
                    raw = word(pointer)
                except Exception:
                    break
                if raw == 0:
                    break
                # glibc 2.32+ stores next as (chunk_address >> 12) ^ next, so a
                # terminating NULL reads back as the mangling key itself.
                demangled = raw ^ (pointer >> 12)
                if demangled == 0:
                    break
                usable = [
                    value for value in (demangled, raw)
                    if heap_start <= value < heap_end and value % 16 == 0
                ]
                if not usable:
                    corrupt = raw
                    break
                pointer = usable[0]
            out["tcache"].append({
                "index": index, "size": bin_size, "count": count,
                "entry": entry, "chain": chain, "corrupt_next": corrupt,
            })
    except Exception as exc:
        out["errors"].append("tcache: %s" % exc)

print("CTFTOOLS_JSON:" + json.dumps(out))
end
"""


def inspect(path: str, breakpoint_at: str = "main", stdin_data: bytes = b"\n",
            args=(), timeout: float = 60.0) -> Report:
    info = load_binary(path)
    report = Report(tool="heapscope", target=path)

    if not gdb_available():
        report.warn("gdb is not installed; heapscope needs it")
        report.data["available"] = False
        return report

    script = GDB_SCRIPT.replace("{breakpoint}", breakpoint_at)
    raw = run_gdb_script(path, script, stdin_data=stdin_data, args=args, timeout=timeout)
    data = extract_json(raw) or {}
    report.data["available"] = True
    report.data["breakpoint"] = breakpoint_at

    if not data or data.get("heap") is None:
        sec = report.section("Heap")
        sec.add("  " + term.dim("no heap mapped at this breakpoint"))
        if "Function \"" in raw and "not defined" in raw:
            report.warn(f"there is no symbol called {breakpoint_at!r}; pass --break with one that exists")
        else:
            report.note("break later (after the first malloc) with --break")
        for error in data.get("errors", []):
            report.warn(error)
        return report

    heap = data["heap"]
    chunks = data.get("chunks", [])
    tcache = data.get("tcache", [])
    findings = analyse(chunks, tcache, heap)

    report.data.update({
        "heap": heap,
        "libc": data.get("libc"),
        "chunks": chunks,
        "tcache": tcache,
        "findings": findings,
    })

    _render(report, heap, chunks, tcache, findings, data.get("libc"))
    for error in data.get("errors", []):
        report.warn(error)
    return report


def analyse(chunks: list, tcache: list, heap: dict) -> list:
    """What is wrong with this heap."""
    findings = []

    for entry in tcache:
        chain = entry["chain"]
        duplicates = {p for p in chain if chain.count(p) > 1}
        for pointer in duplicates:
            findings.append({
                "severity": "critical",
                "kind": "double free",
                "detail": f"{pointer:#x} appears twice in the {entry['size']:#x} tcache bin: "
                          "that is a double free, and the bin is already poisoned",
            })
        if entry["count"] > len(chain):
            findings.append({
                "severity": "medium",
                "kind": "count mismatch",
                "detail": f"the {entry['size']:#x} bin says {entry['count']} entries but the chain "
                          f"walks {len(chain)}: the count field may have been overwritten",
            })
        for pointer in chain:
            if not (heap["start"] <= pointer < heap["end"]):
                findings.append({
                    "severity": "high",
                    "kind": "poisoned bin",
                    "detail": f"the {entry['size']:#x} bin points at {pointer:#x}, outside the heap: "
                              "a tcache poisoning write has already landed, or the bin is corrupt",
                })
        if entry.get("corrupt_next") is not None:
            findings.append({
                "severity": "high",
                "kind": "poisoned bin",
                "detail": f"the next pointer after {chain[-1]:#x} in the {entry['size']:#x} bin reads "
                          f"{entry['corrupt_next']:#x}, which is not a heap address either raw or "
                          "demangled: this bin has been written to",
            })

    previous = None
    for chunk in chunks:
        if chunk.get("malformed"):
            findings.append({
                "severity": "high",
                "kind": "bad size",
                "detail": f"the chunk at {chunk['address']:#x} has size {chunk['size']:#x}, which runs "
                          "past the end of the heap: the size field is corrupt",
            })
        if chunk["size"] and chunk["size"] % 0x10:
            findings.append({
                "severity": "high",
                "kind": "unaligned size",
                "detail": f"the chunk at {chunk['address']:#x} has size {chunk['size']:#x}, not a "
                          "multiple of 16",
            })
        if previous and not chunk["prev_inuse"]:
            if chunk["prev_size"] and chunk["prev_size"] != previous["size"]:
                findings.append({
                    "severity": "medium",
                    "kind": "prev_size mismatch",
                    "detail": f"the chunk at {chunk['address']:#x} says the one before it is "
                              f"{chunk['prev_size']:#x} bytes, but it is {previous['size']:#x}: "
                              "a consolidation attack sets this up",
                })
        previous = chunk

    return findings


def _render(report: Report, heap: dict, chunks: list, tcache: list, findings: list, libc) -> None:
    sec = report.section("Heap")
    sec.add(term.table([
        ["range", f"{heap['start']:#x} - {heap['end']:#x}"],
        ["size", f"{heap['end'] - heap['start']:#x}"],
        ["chunks walked", str(len(chunks))],
        ["libc", libc or term.dim("not identified")],
    ]))

    listing = report.section(f"Chunks ({len(chunks)})")
    rows = []
    for chunk in chunks[:40]:
        flags = []
        if chunk["prev_inuse"]:
            flags.append("P")
        if chunk["is_mmapped"]:
            flags.append("M")
        if chunk["non_main_arena"]:
            flags.append("N")
        note = term.bad("malformed") if chunk.get("malformed") else ""
        rows.append([
            f"{chunk['address']:#x}",
            f"{chunk['size']:#x}",
            "".join(flags) or "-",
            f"{chunk['prev_size']:#x}",
            note,
        ])
    listing.add(term.table(rows, headers=["Address", "Size", "Flags", "prev_size", "Note"]))
    if len(chunks) > 40:
        listing.add("  " + term.dim(f"... {len(chunks) - 40} more"))

    bins = report.section(f"tcache ({len(tcache)} bins in use)")
    if not tcache:
        bins.add("  " + term.dim("every bin empty"))
    else:
        rows = []
        for entry in tcache:
            chain = " -> ".join(f"{p:#x}" for p in entry["chain"][:6])
            rows.append([f"{entry['size']:#x}", str(entry["count"]), chain or term.dim("empty")])
        bins.add(term.table(rows, headers=["Bin", "Count", "Chain"]))

    found = report.section(f"Findings ({len(findings)})")
    if not findings:
        found.add("  " + term.good("nothing obviously corrupt"))
    else:
        for finding in findings:
            colour = term.bad if finding["severity"] in ("critical", "high") else term.warn
            found.add(f"  {colour(finding['severity'])}  {term.c(finding['kind'], 'bold')}")
            found.add(f"      {term.dim(finding['detail'])}")

    hints = report.section("Where to go next")
    sizes = sorted({entry["size"] for entry in tcache})
    if sizes:
        hints.add(f"  {term.dim('tcache poisoning:')} free two chunks of the same size, overwrite the "
                  "first one's fd with the target address, then malloc twice")
        hints.add(f"  {term.dim('on glibc 2.32+ the fd is mangled:')} write target ^ (chunk_address >> 12)")
    hints.add(f"  {term.dim('a chunk whose size you control lets you overlap the next one')}")


def build_parser():
    parser = base_parser("heapscope", "Inspect glibc heap state through GDB.")
    parser.add_argument("binary", help="the ELF to inspect")
    parser.add_argument("--break", dest="breakpoint", default="main",
                        help="where to stop and look (symbol or file:line, default: main)")
    parser.add_argument("--input", default="\\n", help="stdin to feed before the breakpoint (python escapes)")
    add_run_args(parser)
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)
    report = inspect(
        resolve_binary(args.binary),
        breakpoint_at=args.breakpoint,
        stdin_data=parse_escapes(args.input),
        args=args.argv,
        timeout=max(60.0, args.timeout * 10),
    )
    report.emit(as_json=args.json)
    return 0 if report.data.get("heap") else 1


if __name__ == "__main__":
    sys.exit(main())
