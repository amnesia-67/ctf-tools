"""stackviz: draw the stack frame and show what a payload overwrites.

    stackviz ./vuln                              # the frame, from static analysis
    stackviz ./vuln --payload-hex 4141...        # with your payload laid over it
    stackviz ./vuln --payload-file payload.bin --offset 72
"""

from __future__ import annotations

import sys

from ctftools.core import disasm, term
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


def frame_layout(info, buffer_size: int, canary_at: int | None, function: str = "?") -> list:
    """The slots of a standard frame, from the buffer up past the return address."""
    word = info.word
    slots = []
    position = 0
    while position < buffer_size:
        remaining = buffer_size - position
        size = min(word, remaining)
        label = "buffer"
        if canary_at is not None and position == buffer_size - canary_at:
            label = "canary"
        slots.append({
            "offset": position,
            "size": size,
            "name": label,
            "frame": f"rbp-{buffer_size - position:#x}",
        })
        position += size

    slots.append({"offset": buffer_size, "size": word, "name": "saved rbp", "frame": "rbp"})
    slots.append({"offset": buffer_size + word, "size": word, "name": "return address",
                  "frame": f"rbp+{word:#x}"})
    slots.append({"offset": buffer_size + 2 * word, "size": word, "name": "caller frame",
                  "frame": f"rbp+{2 * word:#x}"})
    return slots


def render(info, slots: list, payload: bytes = b"", target_offset: int | None = None) -> list:
    """One line per stack slot, with the payload bytes that land on it."""
    lines = []
    word = info.word
    head = f"  {'offset':>7}  {'frame':<10}  {'what':<16}  bytes"
    lines.append(term.c(head, "bold"))
    lines.append(term.dim("  " + "-" * (len(head) + 24)))

    for slot in slots:
        start, size = slot["offset"], slot["size"]
        chunk = payload[start:start + size] if payload else b""
        overwritten = bool(chunk)

        if chunk:
            hexes = chunk.hex(" ")
            if len(chunk) == word:
                value = int.from_bytes(chunk, "little")
                shown = f"{hexes}  {term.dim(f'= {value:#x}')}"
            else:
                shown = hexes
            printable = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            shown += term.dim(f"  |{printable}|")
        else:
            shown = term.dim("(untouched)") if payload else ""

        name = slot["name"]
        colour = {
            "canary": term.bad if overwritten else term.warn,
            "return address": term.bad if overwritten else term.good,
            "saved rbp": term.warn if overwritten else term.dim,
        }.get(name, term.dim if not overwritten else (lambda s: s))

        marker = term.bad("<<") if overwritten and name in ("canary", "return address") else "  "
        lines.append(f"  {start:>7}  {slot['frame']:<10}  {colour(name):<16}  {shown} {marker}")

    if target_offset is not None:
        lines.append("")
        lines.append(f"  {term.dim('the return address starts at offset')} {term.c(str(target_offset), 'bold')}")
    return lines


def visualise(path: str, payload: bytes = b"", offset: int | None = None,
              buffer_size: int | None = None, discover: bool = True,
              prefix: bytes = b"", timeout: float = 5.0, sandbox: bool = True) -> Report:
    info = load_binary(path)
    report = Report(tool="stackviz", target=path)

    analysis = disasm.analyse(info)
    best = analysis.best() if analysis.available else None
    canary_at = best.canary_displacement if best else None
    function = best.function if best else "?"

    if buffer_size is None:
        buffer_size = best.buffer_displacement if best and best.buffer_displacement else None

    if offset is None and buffer_size is not None:
        offset = buffer_size + info.word
    if offset is None and discover:
        from ctftools.core.offset import find_offset

        found = find_offset(info, prefix=prefix, timeout=timeout, sandbox=sandbox)
        offset = found.offset
        if buffer_size is None and offset is not None:
            buffer_size = offset - info.word
        report.data["offset_discovery"] = found.as_dict()

    if buffer_size is None:
        fail("could not work out the buffer size; pass --buffer-size or --offset")

    slots = frame_layout(info, buffer_size, canary_at, function)
    report.data.update({
        "function": function,
        "buffer_size": buffer_size,
        "canary_displacement": canary_at,
        "return_address_offset": offset,
        "payload_length": len(payload),
        "slots": slots,
    })

    sec = report.section(f"Stack frame of {function}")
    sec.add(f"  buffer {buffer_size} bytes"
            + (f", canary at rbp-{canary_at:#x}" if canary_at else ", no canary")
            + f", return address at offset {offset}")
    sec.add("")
    for line in render(info, slots, payload, offset):
        sec.add(line)

    if payload:
        verdict = report.section("What this payload does")
        reaches_canary = canary_at is not None and len(payload) > buffer_size - canary_at
        reaches_ret = len(payload) > (offset or 0)
        rows = [
            ["fills the buffer", _yes(len(payload) >= buffer_size)],
            ["smashes the canary", _yes(reaches_canary, bad=True) if canary_at else term.dim("no canary")],
            ["reaches the return address", _yes(reaches_ret)],
        ]
        if reaches_ret:
            value = payload[offset:offset + info.word]
            rows.append(["returns to", term.c(f"{int.from_bytes(value.ljust(info.word, bytes(1)), 'little'):#x}", "bold")])
        verdict.add(term.table(rows))
        report.data.update({
            "fills_buffer": len(payload) >= buffer_size,
            "smashes_canary": reaches_canary,
            "controls_return_address": reaches_ret,
        })
        if reaches_canary:
            report.warn("this payload overwrites the canary: the process will abort at the return "
                        "unless the canary bytes are correct")
        if len(payload) < (offset or 0) + info.word and len(payload) > (offset or 0):
            report.warn("the payload ends inside the return address: the top bytes stay as they were, "
                        "which usually makes the address non-canonical")

    return report


def _yes(value: bool, bad: bool = False) -> str:
    if value:
        return term.bad("yes") if bad else term.good("yes")
    return term.dim("no")


def build_parser():
    parser = base_parser("stackviz", "Draw the stack frame and overlay a payload on it.")
    parser.add_argument("binary", help="the ELF to draw")
    parser.add_argument("--payload-hex", help="payload as hex")
    parser.add_argument("--payload-file", help="payload read from this file")
    parser.add_argument("--payload", help="payload as a string with python escapes")
    parser.add_argument("--offset", type=int, help="offset of the return address")
    parser.add_argument("--buffer-size", type=int, help="buffer size, if the static analysis misses it")
    parser.add_argument("--no-run", action="store_true", help="never run the target to find the offset")
    add_run_args(parser)
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)

    payload = b""
    if args.payload_hex:
        try:
            payload = bytes.fromhex(args.payload_hex.replace(" ", ""))
        except ValueError:
            fail("--payload-hex must be hex")
    elif args.payload_file:
        with open(args.payload_file, "rb") as fh:
            payload = fh.read()
    elif args.payload:
        payload = parse_escapes(args.payload)

    report = visualise(
        resolve_binary(args.binary), payload=payload, offset=args.offset,
        buffer_size=args.buffer_size, discover=not args.no_run,
        prefix=parse_escapes(args.prefix), timeout=args.timeout,
        sandbox=not args.no_sandbox,
    )
    report.emit(as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
