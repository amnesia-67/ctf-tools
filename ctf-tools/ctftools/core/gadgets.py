"""ROP gadget discovery.

A self-contained gadget finder so the toolkit does not depend on ROPgadget
or ropper being installed.  It walks backwards from every gadget terminator
(``ret``, ``syscall``, ``int 0x80``, ``jmp reg``, ``call reg``) and keeps the
decodings that end exactly on that terminator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# Terminators: byte pattern -> (length, label)
TERMINATORS = {
    b"\xc3": (1, "ret"),
    b"\xcb": (1, "retf"),
    b"\x0f\x05": (2, "syscall"),
    b"\xcd\x80": (2, "int 0x80"),
    b"\x0f\x34": (2, "sysenter"),
}
# jmp/call through a register: ff /4 and ff /2 with mod=11
_REG_BRANCH = re.compile(rb"\xff[\xd0-\xd7\xe0-\xe7]")

# Instructions that must not appear in the middle of a gadget: anything that
# takes control away before the terminator is reached.  `leave` is allowed,
# since `leave ; ret` is one of the most useful pivots there is.
_BAD_MID = re.compile(r"^(ret|retf|iret|jmp|je|jne|jz|jnz|ja|jb|jg|jl|call|int|syscall|sysenter|hlt|loop|ud2)\b")


@dataclass
class Gadget:
    address: int
    instructions: list = field(default_factory=list)
    bytes_: bytes = b""

    @property
    def text(self) -> str:
        return " ; ".join(self.instructions)

    def __len__(self) -> int:
        return len(self.instructions)

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "text": self.text,
            "bytes": self.bytes_.hex(),
            "length": len(self.instructions),
        }


def _capstone(bits: int):
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
    md.detail = False
    md.syntax = capstone.CS_OPT_SYNTAX_INTEL
    return md


def executable_chunks(elf) -> list[tuple[int, bytes]]:
    """(vaddr, bytes) for every executable segment of *elf*."""
    chunks = []
    try:
        for segment in elf.iter_segments():
            if segment.header["p_type"] != "PT_LOAD":
                continue
            if not (segment.header["p_flags"] & 1):  # PF_X
                continue
            chunks.append((int(segment.header["p_vaddr"]), segment.data()))
    except Exception:
        pass
    if not chunks:
        for name in (".text", ".plt", ".init", ".fini"):
            section = elf.get_section_by_name(name)
            if section is not None:
                chunks.append((int(section.header["sh_addr"]), section.data()))
    return chunks


def find_gadgets(
    info,
    max_instructions: int = 6,
    max_bytes: int = 24,
    base: int | None = None,
    limit: int = 200000,
) -> list[Gadget]:
    """Every unique gadget in the executable parts of *info*."""
    md = _capstone(info.bits)
    out: dict[str, Gadget] = {}
    offset = 0 if base is None else base

    for vaddr, data in executable_chunks(info.elf):
        for end, term_len in _terminator_sites(data):
            for back in range(0, max_bytes):
                start = end - back
                if start < 0:
                    continue
                window = data[start : end + term_len]
                address = vaddr + start + offset
                instructions = []
                ok = True
                consumed = 0
                for ins in md.disasm(window, address):
                    text = f"{ins.mnemonic} {ins.op_str}".strip()
                    consumed += ins.size
                    instructions.append(text)
                    if consumed == len(window):
                        break
                    if _BAD_MID.match(text):
                        ok = False
                        break
                    if len(instructions) > max_instructions:
                        ok = False
                        break
                if not ok or consumed != len(window) or not instructions:
                    continue
                gadget = Gadget(address=address, instructions=instructions, bytes_=bytes(window))
                out.setdefault(gadget.text, gadget)
                if len(out) >= limit:
                    return sorted(out.values(), key=lambda g: g.address)
    return sorted(out.values(), key=lambda g: g.address)


def _terminator_sites(data: bytes) -> Iterable[tuple[int, int]]:
    for pattern, (length, _label) in TERMINATORS.items():
        start = 0
        while True:
            index = data.find(pattern, start)
            if index == -1:
                break
            yield index, length
            start = index + 1
    for match in _REG_BRANCH.finditer(data):
        yield match.start(), 2


def search(gadgets: list[Gadget], query: str) -> list[Gadget]:
    """Filter *gadgets* by a loose query such as ``pop rdi`` or ``syscall``.

    Each semicolon-separated term must appear, in order, in the gadget.
    ``?`` matches any single register.
    """
    terms = [t.strip().lower() for t in query.split(";") if t.strip()]
    if not terms:
        return gadgets
    patterns = [re.compile(_term_to_regex(t)) for t in terms]
    out = []
    for gadget in gadgets:
        text = gadget.text.lower()
        position = 0
        matched = True
        for pattern in patterns:
            found = pattern.search(text, position)
            if not found:
                matched = False
                break
            position = found.end()
        if matched:
            out.append(gadget)
    return out


def _term_to_regex(term: str) -> str:
    escaped = re.escape(term)
    escaped = escaped.replace(r"\?", r"\w+")
    escaped = escaped.replace(r"\ ", r"\s+")
    return escaped


def without_badchars(gadgets: list[Gadget], bad: bytes, bits: int = 64) -> list[Gadget]:
    """Keep only the gadgets whose address contains no byte from *bad*."""
    if not bad:
        return gadgets
    size = bits // 8
    out = []
    for gadget in gadgets:
        packed = gadget.address.to_bytes(size, "little")
        if not any(byte in bad for byte in packed):
            out.append(gadget)
    return out


def best(gadgets: list[Gadget], query: str) -> Gadget | None:
    """The shortest gadget matching *query*."""
    matches = search(gadgets, query)
    if not matches:
        return None
    return min(matches, key=lambda g: (len(g.instructions), len(g.bytes_)))
