"""Crash inspection through GDB.

Core dumps are disabled on most systems (``ulimit -c 0``), so the reliable
way to see the register state at a crash is to run the target under GDB in
batch mode and read the registers out with GDB's Python API.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Sequence

X86_64_REGS = [
    "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags",
]
I386_REGS = ["eip", "esp", "ebp", "eax", "ebx", "ecx", "edx", "esi", "edi", "eflags"]

_GDB_PY = r'''
python
import json, gdb

out = {"regs": {}, "errors": []}
for name in __REGS__:
    try:
        value = gdb.parse_and_eval("$" + name)
        out["regs"][name] = int(value) & ((1 << 64) - 1)
    except Exception as exc:
        out["errors"].append("reg %s: %s" % (name, exc))

sp = out["regs"].get("rsp") or out["regs"].get("esp")
if sp:
    inferior = gdb.selected_inferior()
    for back, size in ((64, 320), (0, 256), (0, 64)):
        try:
            data = inferior.read_memory(sp - back, size)
            out["stack"] = bytes(data).hex()
            out["stack_base"] = sp - back
            break
        except Exception as exc:
            out["errors"].append("stack: %s" % exc)

pc = out["regs"].get("rip") or out["regs"].get("eip")
if pc:
    try:
        out["pc_disasm"] = gdb.execute("x/1i $pc", to_string=True).strip()
    except Exception as exc:
        out["errors"].append("disasm: %s" % exc)
    try:
        out["pc_block"] = gdb.execute("info symbol $pc", to_string=True).strip()
    except Exception:
        pass

try:
    out["backtrace"] = gdb.execute("bt 8", to_string=True).strip()
except Exception:
    out["backtrace"] = ""

try:
    out["mappings"] = gdb.execute("info proc mappings", to_string=True)
except Exception:
    out["mappings"] = ""

print("CTFTOOLS_JSON:" + json.dumps(out))
end
'''


@dataclass
class CrashState:
    """Register and stack state at the moment a target died."""

    crashed: bool = False
    signal: str | None = None
    regs: dict = field(default_factory=dict)
    stack: bytes = b""
    stack_base: int = 0
    pc_disasm: str = ""
    backtrace: str = ""
    mappings: str = ""
    raw: str = ""
    errors: list = field(default_factory=list)
    bits: int = 64

    @property
    def pc(self) -> int | None:
        return self.regs.get("rip", self.regs.get("eip"))

    @property
    def sp(self) -> int | None:
        return self.regs.get("rsp", self.regs.get("esp"))

    @property
    def canary_abort(self) -> bool:
        return "__stack_chk_fail" in self.backtrace or "stack smashing" in self.raw

    def stack_word(self, offset: int = 0) -> int | None:
        """Read a word from the stack, *offset* bytes from the stack pointer."""
        if not self.stack or self.sp is None:
            return None
        size = self.bits // 8
        index = (self.sp + offset) - self.stack_base
        if index < 0 or index + size > len(self.stack):
            return None
        return int.from_bytes(self.stack[index : index + size], "little")

    def as_dict(self) -> dict:
        return {
            "crashed": self.crashed,
            "signal": self.signal,
            "pc": self.pc,
            "sp": self.sp,
            "registers": {k: v for k, v in self.regs.items()},
            "pc_disasm": self.pc_disasm,
            "canary_abort": self.canary_abort,
        }


def gdb_available() -> bool:
    return shutil.which("gdb") is not None


def run_gdb_script(
    path: str,
    commands: str,
    stdin_data: bytes = b"",
    args: Sequence[str] = (),
    timeout: float = 30.0,
    env: dict | None = None,
) -> str:
    """Run *commands* under GDB against *path* and return everything it printed.

    ``{stdin}`` in *commands* is replaced by the path of a file holding
    *stdin_data*, so a script can say ``run < {stdin}``.
    """
    if not gdb_available():
        raise RuntimeError("gdb is not installed")

    workdir = tempfile.mkdtemp(prefix="ctftools-gdb-")
    stdin_path = os.path.join(workdir, "stdin.bin")
    script_path = os.path.join(workdir, "run.gdb")
    with open(stdin_path, "wb") as fh:
        fh.write(stdin_data)

    preamble = "set confirm off\nset pagination off\nset height 0\nset width 0\n"
    with open(script_path, "w") as fh:
        fh.write(preamble + commands.replace("{stdin}", stdin_path).replace("{args}", " ".join(args)))

    full_env = dict(os.environ if env is None else env)
    full_env.setdefault("LC_ALL", "C")
    try:
        proc = subprocess.run(
            ["gdb", "-batch", "-nx", "-x", script_path, os.path.abspath(path)],
            capture_output=True,
            timeout=timeout,
            env=full_env,
        )
        return (proc.stdout + proc.stderr).decode("latin-1")
    except subprocess.TimeoutExpired as exc:
        return ((exc.stdout or b"") + (exc.stderr or b"")).decode("latin-1")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def extract_json(raw: str, tag: str = "CTFTOOLS_JSON:") -> dict | None:
    """The last tagged JSON object printed by a GDB script."""
    blob = None
    for line in raw.splitlines():
        if line.startswith(tag):
            blob = line[len(tag):]
    if blob is None:
        return None
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None


def gdb_crash(
    path: str,
    stdin_data: bytes = b"",
    args: Sequence[str] = (),
    timeout: float = 25.0,
    bits: int = 64,
    env: dict | None = None,
) -> CrashState:
    """Run *path* under GDB with *stdin_data* and report the crash state."""
    if not gdb_available():
        raise RuntimeError("gdb is not installed; pwnscan needs it to read the crash state")

    regs = X86_64_REGS if bits == 64 else I386_REGS
    workdir = tempfile.mkdtemp(prefix="ctftools-gdb-")
    stdin_path = os.path.join(workdir, "stdin.bin")
    script_path = os.path.join(workdir, "run.gdb")

    with open(stdin_path, "wb") as fh:
        fh.write(stdin_data)

    arg_string = " ".join(args)
    script = "\n".join(
        [
            "set confirm off",
            "set pagination off",
            "set height 0",
            "set width 0",
            "set disassembly-flavor intel",
            "set backtrace past-main on",
            f"run {arg_string} < {stdin_path}",
            _GDB_PY.replace("__REGS__", json.dumps(regs)),
        ]
    )
    with open(script_path, "w") as fh:
        fh.write(script)

    full_env = dict(os.environ if env is None else env)
    full_env.setdefault("LC_ALL", "C")

    try:
        proc = subprocess.run(
            ["gdb", "-batch", "-nx", "-x", script_path, os.path.abspath(path)],
            capture_output=True,
            timeout=timeout,
            env=full_env,
        )
        raw = (proc.stdout + proc.stderr).decode("latin-1")
    except subprocess.TimeoutExpired as exc:
        raw = ((exc.stdout or b"") + (exc.stderr or b"")).decode("latin-1")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return _parse(raw, bits)


def _parse(raw: str, bits: int) -> CrashState:
    state = CrashState(raw=raw, bits=bits)

    match = re.search(r"Program received signal (\w+)", raw)
    if match:
        state.crashed = True
        state.signal = match.group(1)
    elif "Program terminated with signal" in raw:
        state.crashed = True
        sig = re.search(r"Program terminated with signal (\w+)", raw)
        state.signal = sig.group(1) if sig else "unknown"

    blob = None
    for line in raw.splitlines():
        if line.startswith("CTFTOOLS_JSON:"):
            blob = line[len("CTFTOOLS_JSON:") :]
    if blob:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError:
            data = {}
        state.regs = {k: int(v) for k, v in data.get("regs", {}).items()}
        state.stack = bytes.fromhex(data.get("stack", ""))
        state.stack_base = int(data.get("stack_base", 0))
        state.pc_disasm = data.get("pc_disasm", "")
        state.backtrace = data.get("backtrace", "")
        state.mappings = data.get("mappings", "")
        state.errors = data.get("errors", [])

    return state
