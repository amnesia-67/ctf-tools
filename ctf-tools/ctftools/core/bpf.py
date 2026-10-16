"""A cBPF disassembler and evaluator for seccomp filters.

Enough of classic BPF to read, print and reason about the filters seccomp
uses: which syscalls a filter allows, which it kills, and which it only
allows under a condition on the arguments.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Instruction classes
LD, LDX, ST, STX, ALU, JMP, RET, MISC = range(8)
# Size / mode
W, H, B = 0x00, 0x08, 0x10
IMM, ABS, IND, MEM, LEN, MSH = 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0
# ALU and JMP operations
ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG, MOD, XOR = [i << 4 for i in range(11)]
JA, JEQ, JGT, JGE, JSET = [i << 4 for i in range(5)]
K, X = 0x00, 0x08

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_I386 = 0x40000003
AUDIT_ARCH_AARCH64 = 0xC00000B7

ARCH_NAMES = {
    AUDIT_ARCH_X86_64: "x86_64",
    AUDIT_ARCH_I386: "i386",
    AUDIT_ARCH_AARCH64: "aarch64",
}

# seccomp_data field offsets
FIELDS = {0: "nr", 4: "arch", 8: "instruction_pointer", 12: "instruction_pointer_hi"}
for _i in range(6):
    FIELDS[16 + 8 * _i] = f"args[{_i}]"
    FIELDS[20 + 8 * _i] = f"args[{_i}]_hi"

ACTIONS = {
    0x00000000: "KILL_THREAD",
    0x80000000: "KILL_PROCESS",
    0x00030000: "TRAP",
    0x00050000: "ERRNO",
    0x7FC00000: "USER_NOTIF",
    0x7FF00000: "TRACE",
    0x7FFC0000: "LOG",
    0x7FFF0000: "ALLOW",
}
ALLOWING = {"ALLOW", "LOG", "TRACE", "USER_NOTIF"}


def action_name(value: int) -> str:
    """Decode a seccomp return value, keeping the errno where there is one."""
    masked = value & 0xFFFF0000
    name = ACTIONS.get(value) or ACTIONS.get(masked)
    if name == "ERRNO":
        return f"ERRNO({value & 0xFFFF})"
    if name == "TRACE" and (value & 0xFFFF):
        return f"TRACE({value & 0xFFFF})"
    return name or f"UNKNOWN({value:#x})"


@dataclass
class Instruction:
    index: int
    code: int
    jt: int
    jf: int
    k: int

    @property
    def cls(self) -> int:
        return self.code & 0x07

    def text(self) -> str:
        cls, code, k = self.cls, self.code, self.k
        if cls == LD:
            mode = code & 0xE0
            if mode == ABS:
                return f"A = {FIELDS.get(k, f'data[{k}]')}"
            if mode == IMM:
                return f"A = {k:#x}"
            if mode == MEM:
                return f"A = M[{k}]"
            if mode == LEN:
                return "A = len"
            return f"ld {code:#x} {k:#x}"
        if cls == LDX:
            mode = code & 0xE0
            if mode == IMM:
                return f"X = {k:#x}"
            if mode == MEM:
                return f"X = M[{k}]"
            return f"ldx {code:#x} {k:#x}"
        if cls == ST:
            return f"M[{k}] = A"
        if cls == STX:
            return f"M[{k}] = X"
        if cls == ALU:
            op = {ADD: "+=", SUB: "-=", MUL: "*=", DIV: "/=", OR: "|=", AND: "&=",
                  LSH: "<<=", RSH: ">>=", MOD: "%=", XOR: "^="}.get(code & 0xF0)
            if (code & 0xF0) == NEG:
                return "A = -A"
            operand = "X" if code & X else f"{k:#x}"
            return f"A {op or '?='} {operand}"
        if cls == JMP:
            op = code & 0xF0
            operand = "X" if code & X else f"{k:#x}"
            if op == JA:
                return f"goto {self.index + 1 + k}"
            names = {JEQ: "==", JGT: ">", JGE: ">=", JSET: "&"}
            cond = f"A {names.get(op, '?')} {operand}"
            return f"if ({cond}) goto {self.index + 1 + self.jt} else goto {self.index + 1 + self.jf}"
        if cls == RET:
            if code & X:
                return "return X"
            return f"return {action_name(k)}"
        if cls == MISC:
            return "A = X" if (code & 0xF8) == 0x80 else "X = A"
        return f"unknown {code:#x}"

    def as_dict(self) -> dict:
        return {"index": self.index, "code": self.code, "jt": self.jt, "jf": self.jf,
                "k": self.k, "text": self.text()}


def parse(data: bytes) -> list:
    """Parse a packed sock_filter array."""
    out = []
    for index, offset in enumerate(range(0, len(data) - 7, 8)):
        code, jt, jf, k = struct.unpack_from("<HBBI", data, offset)
        out.append(Instruction(index, code, jt, jf, k))
    return out


def _valid_opcodes() -> set:
    """Every cBPF opcode a real seccomp filter can contain."""
    codes = set()
    for size in (W, H, B):
        for mode in (IMM, ABS, IND, MEM, LEN, MSH):
            codes.add(LD | size | mode)
            codes.add(LDX | size | mode)
    codes.add(ST)
    codes.add(STX)
    for op in (ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG, MOD, XOR):
        codes.add(ALU | op | K)
        codes.add(ALU | op | X)
    for op in (JA, JEQ, JGT, JGE, JSET):
        codes.add(JMP | op | K)
        codes.add(JMP | op | X)
    codes.add(RET | K)
    codes.add(RET | X)
    codes.add(MISC | 0x80)  # tax
    codes.add(MISC | 0x00)  # txa
    return codes


VALID_OPCODES = _valid_opcodes()


def looks_like_filter(instructions: list) -> bool:
    """Whether a byte range decodes as a real seccomp filter.

    Scanning a binary for a packed ``sock_filter`` array turns up plenty of
    code that happens to decode, so this is deliberately strict: every
    opcode must be a real one, every jump must land inside the program, the
    loads must read ``seccomp_data`` fields, and every return value must be a
    known seccomp action.
    """
    if len(instructions) < 4:
        return False
    if instructions[-1].cls != RET:
        return False

    loads_a_field = False
    has_comparison = False

    for ins in instructions:
        if ins.code not in VALID_OPCODES:
            return False
        if ins.cls == JMP:
            op = ins.code & 0xF0
            if op == JA:
                if ins.index + 1 + ins.k > len(instructions):
                    return False
            else:
                has_comparison = True
                if ins.index + 1 + max(ins.jt, ins.jf) > len(instructions):
                    return False
        elif ins.cls == RET:
            if not (ins.code & X) and action_name(ins.k).startswith("UNKNOWN"):
                return False
        elif ins.cls == LD and (ins.code & 0xE0) == ABS:
            if ins.k not in FIELDS:
                return False
            loads_a_field = True
        elif ins.cls in (ST, STX) and ins.k > 15:
            return False

    return loads_a_field and has_comparison


@dataclass
class Evaluation:
    action: str
    conditional: bool = False
    steps: int = 0


def evaluate(instructions: list, nr: int, arch: int = AUDIT_ARCH_X86_64,
             args=(0, 0, 0, 0, 0, 0), max_steps: int = 4096) -> Evaluation:
    """Run the filter for one syscall number.

    Argument values are unknown in a static analysis, so any branch that
    reads ``args[n]`` marks the result conditional.
    """
    data = bytearray(64)
    struct.pack_into("<I", data, 0, nr & 0xFFFFFFFF)
    struct.pack_into("<I", data, 4, arch & 0xFFFFFFFF)
    for i, value in enumerate(args[:6]):
        struct.pack_into("<Q", data, 16 + 8 * i, value & 0xFFFFFFFFFFFFFFFF)

    a = x = 0
    mem = [0] * 16
    pc = 0
    conditional = False
    steps = 0

    while pc < len(instructions) and steps < max_steps:
        steps += 1
        ins = instructions[pc]
        cls, code, k = ins.cls, ins.code, ins.k
        pc += 1

        if cls == LD:
            mode = code & 0xE0
            if mode == ABS:
                if k >= 16:
                    conditional = True
                a = struct.unpack_from("<I", data, k)[0] if k + 4 <= len(data) else 0
            elif mode == IMM:
                a = k
            elif mode == MEM:
                a = mem[k % 16]
            elif mode == LEN:
                a = len(data)
        elif cls == LDX:
            mode = code & 0xE0
            if mode == IMM:
                x = k
            elif mode == MEM:
                x = mem[k % 16]
        elif cls == ST:
            mem[k % 16] = a
        elif cls == STX:
            mem[k % 16] = x
        elif cls == ALU:
            operand = x if code & X else k
            op = code & 0xF0
            if op == ADD:
                a = (a + operand) & 0xFFFFFFFF
            elif op == SUB:
                a = (a - operand) & 0xFFFFFFFF
            elif op == MUL:
                a = (a * operand) & 0xFFFFFFFF
            elif op == DIV:
                a = a // operand if operand else 0
            elif op == OR:
                a |= operand
            elif op == AND:
                a &= operand
            elif op == LSH:
                a = (a << operand) & 0xFFFFFFFF
            elif op == RSH:
                a >>= operand
            elif op == NEG:
                a = (-a) & 0xFFFFFFFF
            elif op == MOD:
                a = a % operand if operand else 0
            elif op == XOR:
                a ^= operand
        elif cls == JMP:
            op = code & 0xF0
            operand = x if code & X else k
            if op == JA:
                pc += k
                continue
            if op == JEQ:
                taken = a == operand
            elif op == JGT:
                taken = a > operand
            elif op == JGE:
                taken = a >= operand
            elif op == JSET:
                taken = bool(a & operand)
            else:
                taken = False
            pc += ins.jt if taken else ins.jf
        elif cls == RET:
            value = x if code & X else k
            return Evaluation(action_name(value), conditional, steps)
        elif cls == MISC:
            if (code & 0xF8) == 0x80:
                a = x
            else:
                x = a

    return Evaluation("FALLTHROUGH", conditional, steps)


def syscall_table(arch: str = "amd64") -> dict:
    """Syscall number -> name, from pwntools' constants."""
    try:
        from pwnlib.constants import linux

        module = getattr(linux, arch)
    except Exception:  # pragma: no cover - pwntools always ships these
        return {}
    table = {}
    for name in dir(module):
        if not name.startswith("SYS_"):
            continue
        try:
            table[int(getattr(module, name))] = name[4:]
        except Exception:
            continue
    return table


def summarise(instructions: list, arch_value: int = AUDIT_ARCH_X86_64, arch: str = "amd64") -> dict:
    """Per-syscall verdicts for a parsed filter."""
    table = syscall_table(arch)
    highest = max(table) if table else 400
    allowed, blocked, conditional = [], [], []

    for nr in range(0, highest + 1):
        result = evaluate(instructions, nr, arch_value)
        entry = {"nr": nr, "name": table.get(nr, f"syscall_{nr}"), "action": result.action}
        if result.conditional:
            entry["conditional"] = True
            conditional.append(entry)
        elif result.action.split("(")[0] in ALLOWING:
            allowed.append(entry)
        else:
            blocked.append(entry)

    default = evaluate(instructions, 0xFFFF, arch_value).action
    wrong_arch = evaluate(instructions, 59, 0xDEADBEEF).action

    return {
        "allowed": allowed,
        "blocked": blocked,
        "conditional": conditional,
        "default_action": default,
        "other_arch_action": wrong_arch,
        "instruction_count": len(instructions),
    }
