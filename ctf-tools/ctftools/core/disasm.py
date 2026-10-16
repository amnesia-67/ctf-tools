"""Static reasoning about stack frames.

Used as a cross-check for the dynamically discovered overflow offset: find
the call to the input sink, read the buffer's displacement from the frame
pointer, and predict the distance to the saved return address.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# The register holding the destination buffer, per sink, in the SysV ABI.
DEST_REGISTER = {
    "gets": 0,
    "fgets": 0,
    "strcpy": 0,
    "strcat": 0,
    "sprintf": 0,
    "vsprintf": 0,
    "memcpy": 0,
    "read": 1,
    "recv": 1,
    "scanf": 1,
    "__isoc99_scanf": 1,
    "sscanf": 2,
    "__isoc99_sscanf": 2,
}
ARG_REGS_64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


@dataclass
class StackBuffer:
    """A buffer on the stack that attacker data is read into."""

    function: str
    sink: str
    call_address: int
    buffer_displacement: int | None = None
    size_argument: int | None = None
    frame_pointer: bool = True
    canary_displacement: int | None = None
    predicted_offset: int | None = None
    confidence: str = "heuristic"
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "sink": self.sink,
            "call_address": self.call_address,
            "buffer_displacement": self.buffer_displacement,
            "size_argument": self.size_argument,
            "canary_displacement": self.canary_displacement,
            "predicted_offset": self.predicted_offset,
            "confidence": self.confidence,
            "note": self.note,
        }


@dataclass
class DisasmResult:
    buffers: list = field(default_factory=list)
    available: bool = True
    error: str = ""

    def best(self) -> StackBuffer | None:
        """The most likely overflow site: unbounded sinks first."""
        scored = [b for b in self.buffers if b.predicted_offset is not None]
        if not scored:
            return self.buffers[0] if self.buffers else None
        unbounded = [b for b in scored if b.sink in ("gets", "strcpy", "scanf", "__isoc99_scanf", "sprintf", "strcat")]
        pool = unbounded or scored
        return max(pool, key=lambda b: b.predicted_offset or 0)


def _capstone(bits: int):
    import capstone

    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = False
    md.syntax = capstone.CS_OPT_SYNTAX_INTEL
    return md


def _plt_map(info) -> dict[int, str]:
    """Call target address -> function name.

    pwntools reports a PLT entry's address after the ``endbr64`` that
    CET-enabled toolchains emit, while a ``call`` goes to the start of the
    entry, so each name is registered at both addresses.
    """
    out: dict[int, str] = {}
    elf = info.elf
    for table in ("plt", "symbols"):
        try:
            for name, addr in getattr(elf, table, {}).items():
                name = str(name)
                if name.startswith("got."):
                    continue
                clean = name.split("@")[0].replace("plt.", "")
                addr = int(addr)
                out.setdefault(addr, clean)
                if table == "plt":
                    out.setdefault(addr - 4, clean)
        except Exception:
            continue
    return out


_LEA_RBP = re.compile(r"^lea\s+(\w+),\s*\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]")
_LEA_RSP = re.compile(r"^lea\s+(\w+),\s*\[(?:rsp|esp)\s*\+\s*(0x[0-9a-f]+|\d+)\]")
_MOV_IMM = re.compile(r"^mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)$")
_MOV_REG = re.compile(r"^mov\s+(\w+),\s*(\w+)$")
_CANARY_STORE = re.compile(r"^mov\s+qword ptr \[rbp\s*-\s*(0x[0-9a-f]+|\d+)\],\s*(\w+)")
_SUB_RSP = re.compile(r"^sub\s+(?:rsp|esp),\s*(0x[0-9a-f]+|\d+)")


def analyse(info, max_lookback: int = 24) -> DisasmResult:
    """Find stack buffers written by input sinks in *info*."""
    result = DisasmResult()
    if info.arch not in ("amd64", "i386"):
        result.available = False
        result.error = f"static frame analysis supports x86 only, not {info.arch}"
        return result

    try:
        md = _capstone(info.bits)
    except Exception as exc:  # pragma: no cover - capstone ships with pwntools
        result.available = False
        result.error = f"capstone unavailable: {exc}"
        return result

    elf = info.elf
    text = elf.get_section_by_name(".text")
    if text is None:
        result.available = False
        result.error = "no .text section"
        return result

    code = text.data()
    base = text.header["sh_addr"]
    plt = _plt_map(info)
    word = info.bits // 8

    instructions = list(md.disasm(code, base))
    index = {ins.address: i for i, ins in enumerate(instructions)}
    functions = sorted(((addr, name) for name, addr in info.functions.items()), key=lambda t: t[0])

    def owner(address: int) -> str:
        name = "?"
        for addr, fname in functions:
            if addr <= address:
                name = fname
            else:
                break
        return name

    for i, ins in enumerate(instructions):
        if ins.mnemonic != "call":
            continue
        target = _immediate(ins.op_str)
        if target is None:
            continue
        sink = plt.get(target)
        if sink is None:
            continue
        sink = sink.lstrip("_")
        key = sink if sink in DEST_REGISTER else ("__isoc99_" + sink if "__isoc99_" + sink in DEST_REGISTER else None)
        if key is None:
            continue

        arg_index = DEST_REGISTER[key]
        want = ARG_REGS_64[arg_index] if info.bits == 64 else None
        buf = StackBuffer(function=owner(ins.address), sink=sink, call_address=ins.address)

        start = max(0, i - max_lookback)
        # gcc commonly emits `lea rax, [rbp-0x40]` then `mov rdi, rax`, so
        # follow register-to-register moves backwards from the argument
        # register to whichever register the lea actually wrote.
        wanted = {want} if want else set()
        for prev in reversed(instructions[start:i]):
            op = f"{prev.mnemonic} {prev.op_str}".strip()

            match = _LEA_RBP.match(op)
            if match and (not wanted or _in_set(match.group(1), wanted)):
                buf.buffer_displacement = int(match.group(2), 0)
                break
            match = _LEA_RSP.match(op)
            if match and (not wanted or _in_set(match.group(1), wanted)):
                buf.frame_pointer = False
                buf.note = "buffer addressed from rsp; the frame size is needed for an exact offset"
                break
            match = _MOV_REG.match(op)
            if match and wanted and _in_set(match.group(1), wanted):
                wanted = {_canonical(match.group(2))}

        # A bounded sink's size argument, if it is an immediate.
        if key in ("read", "recv", "fgets", "memcpy"):
            size_reg = ARG_REGS_64[2] if key in ("read", "recv", "memcpy") else ARG_REGS_64[1]
            for prev in reversed(instructions[start:i]):
                match = _MOV_IMM.match(f"{prev.mnemonic} {prev.op_str}".strip())
                if match and _same_register(match.group(1), size_reg):
                    buf.size_argument = int(match.group(2), 0)
                    break

        buf.canary_displacement = _canary_slot(instructions, index, ins.address, max_lookback * 4)

        if buf.buffer_displacement is not None and buf.frame_pointer:
            buf.predicted_offset = buf.buffer_displacement + word
            if buf.canary_displacement is not None:
                buf.note = (
                    f"canary at rbp-{buf.canary_displacement:#x}: an overflow past "
                    f"{buf.buffer_displacement - buf.canary_displacement} bytes smashes it"
                )
            if buf.size_argument is not None and buf.size_argument <= buf.buffer_displacement:
                buf.note = (
                    f"{sink} reads at most {buf.size_argument} bytes into a "
                    f"{buf.buffer_displacement} byte slot: no overflow here"
                )
                buf.confidence = "bounded"
        result.buffers.append(buf)

    return result


def _canary_slot(instructions, index, call_address: int, lookback: int) -> int | None:
    """Find the ``mov [rbp-N], rax`` that stores the canary before *call_address*."""
    i = index.get(call_address)
    if i is None:
        return None
    seen_fs = False
    start = max(0, i - lookback)
    for ins in instructions[start:i]:
        op = f"{ins.mnemonic} {ins.op_str}".strip()
        if "fs:" in op and ("0x28" in op or "0x14" in op):
            seen_fs = True
            continue
        if seen_fs:
            match = _CANARY_STORE.match(op)
            if match:
                return int(match.group(1), 0)
    return None


def _immediate(op_str: str) -> int | None:
    op_str = op_str.strip()
    try:
        return int(op_str, 0)
    except ValueError:
        return None


_ALIASES = {
    "rdi": {"edi", "di", "dil"},
    "rsi": {"esi", "si", "sil"},
    "rdx": {"edx", "dx", "dl"},
    "rcx": {"ecx", "cx", "cl"},
    "rax": {"eax", "ax", "al"},
    "rbx": {"ebx", "bx", "bl"},
    "r8": {"r8d", "r8w", "r8b"},
    "r9": {"r9d", "r9w", "r9b"},
    "r10": {"r10d", "r10w", "r10b"},
    "r11": {"r11d", "r11w", "r11b"},
    "r12": {"r12d", "r12w", "r12b"},
    "r13": {"r13d", "r13w", "r13b"},
    "r14": {"r14d", "r14w", "r14b"},
    "r15": {"r15d", "r15w", "r15b"},
}


def _canonical(name: str) -> str:
    """The 64 bit name of a register, given any of its widths."""
    name = name.lower()
    for full, alts in _ALIASES.items():
        if name == full or name in alts:
            return full
    return name


def _in_set(name: str, wanted: set) -> bool:
    return _canonical(name) in {_canonical(w) for w in wanted}


def _same_register(name: str, full: str) -> bool:
    """True when *name* is the 64, 32, 16 or 8 bit form of *full*."""
    return _canonical(name) == _canonical(full)
