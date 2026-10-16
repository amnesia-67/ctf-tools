"""symwin: find an input that reaches a chosen function.

Uses angr to solve the checks standing between the program's entry and the
function you want to reach, which beats reading the decompilation when the
path is a chain of comparisons.

    symwin ./chal win
    symwin ./chal 0x401196 --avoid lose --length 48
    symwin ./chal win --json

angr is an optional dependency: pip install 'ctftools[symbolic]'
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from ctftools.core import term
from ctftools.core.binary import load_binary
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail, resolve_binary
from ctftools.core.report import Report
from ctftools.core.runner import run_target

# Functions worth avoiding by default: a path through one of these is a path
# that already failed.
DEFAULT_AVOID = ["lose", "fail", "wrong", "exit", "_exit", "abort", "nope", "bad", "denied"]


def angr_available() -> tuple[bool, str]:
    try:
        import angr  # noqa: F401
    except Exception as exc:
        return False, str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return True, ""


@dataclass
class Plan:
    """What to hand angr: where to go, what to avoid, how long the input is."""

    binary: str
    find: int | None = None
    find_name: str = ""
    avoid: list = field(default_factory=list)
    avoid_names: list = field(default_factory=list)
    length: int = 64
    pie: bool = False
    base: int = 0x400000
    problems: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "binary": self.binary,
            "find": self.find,
            "find_name": self.find_name,
            "avoid": self.avoid,
            "avoid_names": self.avoid_names,
            "length": self.length,
            "pie": self.pie,
            "problems": self.problems,
        }


def plan(path: str, target: str, avoid: list | None = None, length: int = 64,
         use_defaults: bool = True) -> Plan:
    """Resolve the target and the addresses to avoid, before any solving."""
    info = load_binary(path)
    result = Plan(binary=path, length=length, pie=info.pie)

    address = _resolve(info, target)
    if address is None:
        result.problems.append(
            f"no function called {target!r}; pass an address instead, or check the symbol names "
            f"(candidates: {', '.join(n for n, _ in info.win_candidates()[:5]) or 'none found'})"
        )
    else:
        result.find = address
        result.find_name = target

    names = list(avoid or [])
    if use_defaults:
        names += [n for n in DEFAULT_AVOID if info.symbol(n) is not None]
    for name in dict.fromkeys(names):
        value = _resolve(info, name)
        if value is not None:
            result.avoid.append(value)
            result.avoid_names.append(name)

    if info.pie:
        result.problems.append(
            "the binary is PIE: angr loads it at its own base, so addresses in the report are "
            "relative to that base, not to a running process"
        )
    return result


def _resolve(info, target: str) -> int | None:
    try:
        return int(target, 0)
    except (TypeError, ValueError):
        pass
    return info.symbol(target)


def solve(spec: Plan, timeout: float = 120.0, quiet: bool = True) -> dict:
    """Run angr and return the input that reaches the target."""
    import logging

    import angr
    import claripy

    if quiet:
        for name in ("angr", "cle", "pyvex", "claripy", "archinfo"):
            logging.getLogger(name).setLevel(logging.ERROR)

    project = angr.Project(spec.binary, auto_load_libs=False)
    symbolic = claripy.BVS("stdin", spec.length * 8)
    state = project.factory.full_init_state(
        stdin=angr.SimFileStream(name="stdin", content=symbolic, has_end=False),
        add_options=angr.options.unicorn,
    )
    simulation = project.factory.simulation_manager(state)
    simulation.explore(find=spec.find, avoid=spec.avoid or None)

    if not simulation.found:
        return {"solved": False, "reason": "no path reached the target",
                "deadended": len(simulation.deadended), "avoided": len(simulation.avoid)}

    found = simulation.found[0]
    data = found.solver.eval(symbolic, cast_to=bytes)
    return {
        "solved": True,
        "input": data,
        "stdout": found.posix.dumps(1),
        "deadended": len(simulation.deadended),
        "avoided": len(simulation.avoid),
    }


def verify(path: str, data: bytes, marker: bytes = b"", timeout: float = 5.0) -> tuple[bool, str]:
    """Feed the solved input to the real program and see what it does."""
    result = run_target(path, data, timeout=timeout)
    output = result.stdout
    if marker and marker in output:
        return True, f"the program printed {marker.decode('latin-1')!r}"
    for hint in (b"flag{", b"FLAG{", b"ctf{"):
        if hint in output:
            line = next(l for l in output.splitlines() if hint in l)
            return True, f"the program printed {line.decode('latin-1')!r}"
    return False, f"the program printed {output[:80].decode('latin-1', 'replace')!r}"


def find_input(path: str, target: str, avoid: list | None = None, length: int = 64,
               timeout: float = 120.0, check: bool = True, marker: bytes = b"") -> Report:
    report = Report(tool="symwin", target=path)
    spec = plan(path, target, avoid, length)
    report.data["plan"] = spec.as_dict()

    sec = report.section("Plan")
    sec.add(term.table([
        ["reach", f"{spec.find:#x} ({spec.find_name})" if spec.find else term.bad("unresolved")],
        ["avoid", ", ".join(f"{n}@{a:#x}" for n, a in zip(spec.avoid_names, spec.avoid)) or term.dim("nothing")],
        ["input length", f"{spec.length} symbolic bytes"],
    ]))
    for problem in spec.problems:
        report.warn(problem)

    available, reason = angr_available()
    report.data["angr_available"] = available
    if not available:
        sec.add("")
        sec.add("  " + term.warn("angr is not installed, so nothing was solved"))
        sec.add("  " + term.dim(f"({reason})"))
        sec.add("  " + term.dim("install it with: pip install 'ctftools[symbolic]'"))
        report.note("the plan above is what would be handed to angr")
        return report

    if spec.find is None:
        return report

    result = solve(spec, timeout=timeout)
    report.data["solved"] = result["solved"]
    report.data["states_deadended"] = result.get("deadended")
    report.data["states_avoided"] = result.get("avoided")

    found = report.section("Result")
    if not result["solved"]:
        found.add("  " + term.bad("no input reaches that function"))
        found.add(f"  {term.dim('states explored:')} {result.get('deadended')} dead ended, "
                  f"{result.get('avoided')} avoided")
        found.add("  " + term.dim("try a longer --length, or check that the target is really reachable"))
        return report

    data = result["input"]
    trimmed = data.rstrip(b"\x00")
    report.data["input_hex"] = data.hex()
    report.data["input_repr"] = repr(trimmed)
    report.data["program_output"] = result["stdout"].decode("latin-1", "replace")

    found.add(f"  {term.good('found an input')} ({len(trimmed)} meaningful bytes)")
    found.add(f"    {term.c('python:', 'bold')} {trimmed!r}")
    found.add(f"    {term.dim('hex:')}    {trimmed.hex()}")
    found.add("")
    found.add("  " + term.dim("angr's view of the output:"))
    for line in result["stdout"].decode("latin-1", "replace").splitlines()[:6]:
        found.add(f"    {line}")

    if check:
        ok, detail = verify(path, data, marker)
        report.data["verified"] = ok
        check_section = report.section("Check against the real program")
        check_section.add("  " + (term.good("works") if ok else term.warn("did not reproduce")) + f"  {detail}")

    return report


def build_parser():
    parser = base_parser("symwin", "Use angr to find an input that reaches a function.")
    parser.add_argument("binary", help="the ELF to solve")
    parser.add_argument("target", help="function name or address to reach")
    parser.add_argument("--avoid", action="append", default=[], help="function or address to avoid (repeatable)")
    parser.add_argument("--length", type=int, default=64, help="symbolic stdin length (default: 64)")
    parser.add_argument("--timeout", type=float, default=120.0, help="give up after this long (default: 120s)")
    parser.add_argument("--marker", default="", help="text that proves the solved input worked")
    parser.add_argument("--no-check", action="store_true", help="do not run the real program afterwards")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)
    report = find_input(
        resolve_binary(args.binary), args.target, avoid=args.avoid, length=args.length,
        timeout=args.timeout, check=not args.no_check, marker=args.marker.encode(),
    )
    report.emit(as_json=args.json)
    return 0 if report.data.get("solved") else 1


if __name__ == "__main__":
    sys.exit(main())
