"""ELF loading and mitigation detection.

Wraps :class:`pwnlib.elf.ELF` so that every tool sees the same view of a
target: architecture, mitigations, interesting imports and the exploitation
consequences of each mitigation.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

# Functions that read attacker-controlled data into a buffer.  The value is
# (is_bounded, note) -- unbounded reads are the classic stack overflow sinks.
INPUT_SINKS = {
    "gets": (False, "unbounded read from stdin, always overflowable"),
    "fgets": (True, "bounded, overflows only if the size argument is wrong"),
    "scanf": (False, "%s with no width is unbounded"),
    "__isoc99_scanf": (False, "%s with no width is unbounded"),
    "sscanf": (False, "%s with no width is unbounded"),
    "__isoc99_sscanf": (False, "%s with no width is unbounded"),
    "read": (True, "bounded by its third argument, check it against the buffer"),
    "recv": (True, "bounded by its third argument, check it against the buffer"),
    "strcpy": (False, "copies until a NUL byte, unbounded"),
    "strcat": (False, "appends until a NUL byte, unbounded"),
    "sprintf": (False, "formats into a fixed buffer, unbounded"),
    "vsprintf": (False, "formats into a fixed buffer, unbounded"),
    "memcpy": (True, "bounded by its third argument, check where it comes from"),
    "getline": (True, "allocates, but the result may be copied unsafely"),
}

# Functions worth knowing about for building an exploit.
USEFUL_IMPORTS = [
    "system",
    "execve",
    "execl",
    "execlp",
    "puts",
    "printf",
    "write",
    "open",
    "read",
    "mprotect",
    "setvbuf",
    "exit",
    "_exit",
    "malloc",
    "free",
    "fopen",
    "syscall",
]


@dataclass
class Mitigation:
    """One security mitigation and what it means for exploitation."""

    name: str
    value: str
    enabled: bool
    impact: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "value": self.value, "enabled": self.enabled, "impact": self.impact}


@dataclass
class BinaryInfo:
    """Everything the tools need to know about a target binary."""

    path: str
    elf: Any = field(repr=False, default=None)
    sha256: str = ""
    arch: str = ""
    bits: int = 64
    endian: str = "little"
    statically_linked: bool = False
    stripped: bool = False
    interpreter: str | None = None
    relro: str = "No RELRO"
    canary: bool = False
    nx: bool = True
    pie: bool = False
    fortify: bool = False
    rwx_segments: int = 0
    rpath: Any = None
    runpath: Any = None
    input_sinks: list = field(default_factory=list)
    useful_imports: dict = field(default_factory=dict)
    functions: dict = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers
    @property
    def word(self) -> int:
        """Size of a machine word in bytes."""
        return self.bits // 8

    @property
    def pointer_size(self) -> int:
        return self.word

    def symbol(self, name: str) -> int | None:
        """Address of *name*, or None.  Looks in symbols then PLT."""
        if self.elf is None:
            return None
        for table in (self.elf.symbols, getattr(self.elf, "plt", {}), getattr(self.elf, "got", {})):
            try:
                if name in table:
                    return int(table[name])
            except TypeError:
                continue
        return None

    def win_candidates(self) -> list[tuple[str, int]]:
        """Functions that look like a deliberately planted 'win' target."""
        hints = ("win", "flag", "shell", "getshell", "give_shell", "backdoor", "secret", "admin", "pwn", "magic")
        out = []
        for name, addr in sorted(self.functions.items()):
            low = name.lower().lstrip("_")
            if any(h in low for h in hints):
                out.append((name, int(addr)))
        return out

    def mitigations(self) -> list[Mitigation]:
        """The checksec view, each row carrying its exploitation impact."""
        relro_enabled = self.relro == "Full RELRO"
        if self.relro == "Full RELRO":
            relro_impact = "GOT is read-only: GOT overwrite is ruled out, use ROP or writable hooks"
        elif self.relro == "Partial RELRO":
            relro_impact = "GOT is writable: a single write primitive can hijack a PLT call"
        else:
            relro_impact = "GOT and .dynamic are writable: GOT overwrite and dl_resolve both open"

        return [
            Mitigation("RELRO", self.relro, relro_enabled, relro_impact),
            Mitigation(
                "Stack canary",
                "Canary found" if self.canary else "No canary found",
                self.canary,
                "A linear stack overflow aborts unless the canary is leaked or brute forced"
                if self.canary
                else "A linear stack overflow reaches the saved return address directly",
            ),
            Mitigation(
                "NX",
                "NX enabled" if self.nx else "NX disabled",
                self.nx,
                "The stack is not executable: use ROP or ret2libc"
                if self.nx
                else "The stack is executable: shellcode on the stack works",
            ),
            Mitigation(
                "PIE",
                "PIE enabled" if self.pie else ("No PIE (0x%x)" % self._load_address()),
                self.pie,
                "Code addresses are randomised: you need a leak before using any binary address"
                if self.pie
                else "Code addresses are fixed: gadgets and functions can be used directly",
            ),
            Mitigation(
                "FORTIFY",
                "Enabled" if self.fortify else "Not found",
                self.fortify,
                "Some libc calls check their destination size at runtime"
                if self.fortify
                else "No _chk wrappers: libc copies are unchecked",
            ),
            Mitigation(
                "RWX segments",
                str(self.rwx_segments) if self.rwx_segments else "None",
                self.rwx_segments == 0,
                "A writable and executable segment exists: shellcode can be staged there"
                if self.rwx_segments
                else "No writable executable memory in the image",
            ),
            Mitigation(
                "Linkage",
                "Static" if self.statically_linked else "Dynamic",
                True,
                "Statically linked: no libc leak needed, build the chain from the binary's own gadgets"
                if self.statically_linked
                else "Dynamically linked: a libc leak unlocks system() and one-gadgets",
            ),
            Mitigation(
                "Symbols",
                "Stripped" if self.stripped else "Present",
                not self.stripped,
                "Stripped: function names are gone, work from addresses and cross references"
                if self.stripped
                else "Symbols present: functions can be referenced by name",
            ),
        ]

    def _load_address(self) -> int:
        try:
            return int(self.elf.address)
        except Exception:
            return 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": os.path.abspath(self.path),
            "sha256": self.sha256,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "statically_linked": self.statically_linked,
            "stripped": self.stripped,
            "interpreter": self.interpreter,
            "load_address": self._load_address(),
            "mitigations": {
                "relro": self.relro,
                "canary": self.canary,
                "nx": self.nx,
                "pie": self.pie,
                "fortify": self.fortify,
                "rwx_segments": self.rwx_segments,
                "rpath": self.rpath,
                "runpath": self.runpath,
            },
            "input_sinks": [
                {"name": n, "bounded": b, "note": note} for n, b, note in self.input_sinks
            ],
            "useful_imports": self.useful_imports,
            "win_candidates": [{"name": n, "address": a} for n, a in self.win_candidates()],
        }


def load_binary(path: str, checksec_quiet: bool = True) -> BinaryInfo:
    """Load *path* as an ELF and collect everything the tools need."""
    from pwnlib.elf import ELF

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    elf = ELF(path, checksec=False)

    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()

    info = BinaryInfo(path=path, elf=elf, sha256=digest)
    info.arch = elf.arch
    info.bits = elf.bits
    info.endian = elf.endian
    info.statically_linked = bool(getattr(elf, "statically_linked", False))
    info.relro = _relro(elf)
    info.canary = bool(elf.canary)
    info.nx = bool(elf.nx)
    info.pie = bool(elf.pie)
    info.fortify = bool(getattr(elf, "fortify", False))
    info.rwx_segments = len(getattr(elf, "rwx_segments", []) or [])
    info.rpath = getattr(elf, "rpath", None)
    info.runpath = getattr(elf, "runpath", None)
    info.stripped = _stripped(elf)

    try:
        interp = elf.get_section_by_name(".interp")
        info.interpreter = interp.data().rstrip(b"\x00").decode() if interp else None
    except Exception:
        info.interpreter = None

    symbols = {}
    try:
        symbols = {str(k): int(v) for k, v in elf.symbols.items()}
    except Exception:
        pass
    info.functions = _functions(elf, symbols)

    names = set(symbols)
    try:
        names |= {str(k) for k in elf.plt}
        names |= {str(k) for k in elf.got}
    except Exception:
        pass

    for name, (bounded, note) in INPUT_SINKS.items():
        if name in names:
            info.input_sinks.append((name, bounded, note))

    for name in USEFUL_IMPORTS:
        addr = info.symbol(name)
        if addr is not None:
            info.useful_imports[name] = addr

    return info


def _relro(elf) -> str:
    value = getattr(elf, "relro", None)
    if value in (None, False):
        return "No RELRO"
    if isinstance(value, str):
        return value if value.endswith("RELRO") else f"{value} RELRO"
    return "Partial RELRO"


def _stripped(elf) -> bool:
    try:
        section = elf.get_section_by_name(".symtab")
        return section is None or section.num_symbols() <= 1
    except Exception:
        return not bool(getattr(elf, "symbols", {}))


def _functions(elf, symbols: dict[str, int]) -> dict[str, int]:
    """Defined functions in the image, by name."""
    out: dict[str, int] = {}
    try:
        from elftools.elf.sections import SymbolTableSection

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC":
                    continue
                if not sym.name or sym["st_value"] == 0:
                    continue
                out[sym.name] = int(sym["st_value"])
    except Exception:
        pass
    if not out:
        # Fall back to pwntools' symbol table, filtering obvious non-functions.
        for name, addr in symbols.items():
            if name.startswith(("got.", "plt.", "_GLOBAL", "__gmon")):
                continue
            out[name] = addr
    return out
