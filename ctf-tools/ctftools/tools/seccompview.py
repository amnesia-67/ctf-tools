"""seccompview: dump and decode a binary's seccomp filter.

Two ways to get at the filter, tried in this order:

* dynamically, by catching the ``prctl``/``seccomp`` syscall under GDB and
  reading the ``sock_fprog`` out of the process;
* statically, by scanning the binary's sections for a packed ``sock_filter``
  array that decodes as a plausible filter.

    seccompview ./jail
    seccompview ./jail --static
    seccompview ./jail --json
"""

from __future__ import annotations

import sys

from ctftools.core import bpf, term
from ctftools.core.binary import load_binary
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, resolve_binary
from ctftools.core.crash import extract_json, gdb_available, run_gdb_script
from ctftools.core.report import Report

# Syscalls worth calling out explicitly in the verdict, and why each one
# matters when it survives a filter.
ESCAPE_SYSCALLS = {
    "execve": "run a shell directly",
    "execveat": "run a shell directly, by fd",
    "fork": "a child inherits the filter, but can be used to brute force",
    "vfork": "a child inherits the filter, but can be used to brute force",
    "clone": "spawn a thread or process",
    "clone3": "spawn a process; filters that only block clone miss this one",
    "ptrace": "attach to another process and run code outside this filter",
    "process_vm_writev": "write into another process's memory",
    "open": "open the flag file",
    "openat": "open the flag file",
    "mprotect": "make a page executable for staged shellcode",
}
FILE_SYSCALLS = ["open", "openat", "openat2", "read", "pread64", "readv", "write", "sendfile"]

GDB_SCRIPT = r"""
catch syscall prctl seccomp
run {args} < {stdin}
python
import gdb, json

out = {"found": False, "attempts": []}


def reg(name):
    return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF


for _ in range(16):
    # At a syscall-entry catchpoint rax holds -ENOSYS; the number is in orig_rax.
    try:
        nr = reg("orig_rax") & 0xFFFFFFFF
    except Exception:
        try:
            nr = reg("rax") & 0xFFFFFFFF
        except Exception:
            break
    # prctl(PR_SET_SECCOMP=22, SECCOMP_MODE_FILTER=2, prog) or
    # seccomp(SECCOMP_SET_MODE_FILTER=1, flags, prog)
    prog = None
    if nr == 157 and reg("rdi") == 22 and reg("rsi") == 2:
        prog = reg("rdx")
        out["attempts"].append("prctl(PR_SET_SECCOMP, FILTER)")
    elif nr == 317 and reg("rdi") == 1:
        prog = reg("rdx")
        out["attempts"].append("seccomp(SET_MODE_FILTER)")
    if prog:
        try:
            inferior = gdb.selected_inferior()
            header = bytes(inferior.read_memory(prog, 16))
            length = int.from_bytes(header[0:2], "little")
            pointer = int.from_bytes(header[8:16], "little")
            if 0 < length < 4096 and pointer:
                out["length"] = length
                out["filter"] = bytes(inferior.read_memory(pointer, length * 8)).hex()
                out["found"] = True
                break
        except Exception as exc:
            out["attempts"].append("read failed: %s" % exc)
    try:
        gdb.execute("continue", to_string=True)
    except gdb.error:
        break

print("CTFTOOLS_JSON:" + json.dumps(out))
end
"""


def from_process(path: str, args=(), timeout: float = 30.0) -> tuple[bytes, str]:
    """Catch the seccomp installation under GDB and read the filter out."""
    raw = run_gdb_script(path, GDB_SCRIPT, stdin_data=b"\n", args=args, timeout=timeout)
    data = extract_json(raw) or {}
    if data.get("found"):
        return bytes.fromhex(data["filter"]), data.get("attempts", ["dynamic"])[-1]
    return b"", ""


def from_image(info) -> tuple[bytes, str]:
    """Scan the binary's data sections for a packed filter."""
    best: tuple[bytes, str] = (b"", "")
    for section in info.elf.iter_sections():
        name = section.name
        if name not in (".data", ".rodata", ".data.rel.ro", ".text", ".bss"):
            continue
        try:
            data = section.data()
        except Exception:
            continue
        for start in range(0, max(0, len(data) - 24), 4):
            window = data[start:]
            length = min(len(window) // 8, 512)
            for count in range(length, 2, -1):
                chunk = window[: count * 8]
                instructions = bpf.parse(chunk)
                if bpf.looks_like_filter(instructions) and len(chunk) > len(best[0]):
                    best = (chunk, f"{name}+{start:#x}")
                    break
    return best


def view(path: str, static_only: bool = False, dynamic_only: bool = False,
         args=(), timeout: float = 30.0) -> Report:
    info = load_binary(path)
    report = Report(tool="seccompview", target=path)

    filter_bytes, source = b"", ""
    if not static_only and gdb_available():
        filter_bytes, source = from_process(path, args=args, timeout=timeout)
        if filter_bytes:
            source = f"caught at runtime: {source}"
    elif not static_only:
        report.warn("gdb is not installed; falling back to a static scan")

    if not filter_bytes and not dynamic_only:
        filter_bytes, where = from_image(info)
        if filter_bytes:
            source = f"found in the image at {where}"

    report.data["filter_found"] = bool(filter_bytes)
    report.data["source"] = source

    if not filter_bytes:
        sec = report.section("Seccomp filter")
        sec.add("  " + term.dim("no filter found"))
        if "prctl" in (info.useful_imports or {}) or info.symbol("prctl") or info.symbol("seccomp"):
            sec.add("  " + term.warn("but prctl/seccomp is imported: the filter may be installed "
                                     "after input, try --arg or a longer --timeout"))
        report.note("a binary with no filter puts no restriction on execve")
        return report

    instructions = bpf.parse(filter_bytes)
    arch = bpf.AUDIT_ARCH_X86_64 if info.bits == 64 else bpf.AUDIT_ARCH_I386
    summary = bpf.summarise(instructions, arch, "amd64" if info.bits == 64 else "i386")

    report.data["instructions"] = [i.as_dict() for i in instructions]
    report.data["summary"] = {
        "default_action": summary["default_action"],
        "allowed": [e["name"] for e in summary["allowed"]],
        "blocked_count": len(summary["blocked"]),
        "conditional": [e["name"] for e in summary["conditional"]],
        "other_arch_action": summary["other_arch_action"],
    }

    _render(report, info, instructions, summary, source)
    return report


def _render(report: Report, info, instructions, summary, source: str) -> None:
    sec = report.section("Filter")
    sec.add(f"  {term.dim('source:')} {source}")
    sec.add(f"  {term.dim('length:')} {len(instructions)} instructions")
    sec.add("")
    rows = [[f"{i.index:04d}", term.dim(f"{i.code:#06x} {i.jt:02x} {i.jf:02x} {i.k:#010x}"), i.text()]
            for i in instructions]
    sec.add(term.table(rows, headers=["#", "Raw", "Meaning"]))

    allowed = summary["allowed"]
    verdict = report.section("Verdict")
    verdict.add(f"  {term.dim('default action:')} {_action_colour(summary['default_action'])}")
    verdict.add(f"  {term.dim('other architecture:')} {_action_colour(summary['other_arch_action'])}")
    verdict.add("")

    names = {e["name"] for e in allowed}
    conditional = {e["name"] for e in summary["conditional"]}

    rows = []
    for name in ESCAPE_SYSCALLS:
        if name in names:
            rows.append([term.bad("allowed"), name, term.dim(ESCAPE_SYSCALLS[name])])
        elif name in conditional:
            rows.append([term.warn("conditional"), name, term.dim("allowed for some argument values")])
        else:
            rows.append([term.good("blocked"), name, ""])
    verdict.add("  " + term.c("escape syscalls:", "bold"))
    verdict.add(term.table(rows, indent=4))

    open_read_write = [n for n in FILE_SYSCALLS if n in names or n in conditional]
    verdict.add("")
    if "execve" in names or "execveat" in names:
        verdict.add("  " + term.bad("execve is allowed: a plain shellcode or ret2system still works"))
    elif {"open", "openat"} & set(open_read_write) and {"read", "pread64", "readv"} & set(open_read_write) \
            and {"write", "sendfile"} & set(open_read_write):
        verdict.add("  " + term.warn("execve is blocked, but open/read/write are not: "
                                     "use open-read-write shellcode to print the flag"))
        verdict.add("  " + term.dim("shellgen --orw /flag.txt builds that payload"))
    else:
        verdict.add("  " + term.dim("neither execve nor a full open/read/write trio is available; "
                                    "look at what is allowed below"))

    # Print whichever list is the short one: a default-allow filter is
    # described by what it blocks, a default-deny filter by what it permits.
    verdict.add("")
    blocked = [e["name"] for e in summary["blocked"] if not e["name"].startswith("syscall_")]
    permitted = [n for n in sorted(names) if not n.startswith("syscall_")]
    if len(blocked) <= len(permitted):
        verdict.add(f"  {term.c('blocked', 'bold')} ({len(blocked)}): "
                    + (", ".join(blocked) if blocked else "(nothing)"))
        verdict.add(f"  {term.dim('everything else is allowed')}")
    else:
        verdict.add(f"  {term.c('allowed', 'bold')} ({len(permitted)}): "
                    + (", ".join(permitted) if permitted else "(nothing)"))
        verdict.add(f"  {term.dim('everything else is')} {summary['default_action']}")
    if conditional:
        verdict.add(f"  {term.dim('conditional on argument values:')} {', '.join(sorted(conditional))}")


def _action_colour(action: str) -> str:
    head = action.split("(")[0]
    if head in bpf.ALLOWING:
        return term.bad(action)
    return term.good(action)


def build_parser():
    parser = base_parser("seccompview", "Dump and decode a binary's seccomp filter.")
    parser.add_argument("binary", help="the ELF to inspect")
    parser.add_argument("--static", action="store_true", dest="static_only",
                        help="only scan the image, never run the binary")
    parser.add_argument("--dynamic", action="store_true", dest="dynamic_only",
                        help="only catch the filter at runtime, no static scan")
    parser.add_argument("--timeout", type=float, default=30.0, help="GDB timeout (default: 30s)")
    parser.add_argument("--arg", action="append", default=[], dest="argv", help="argument for the target")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)
    report = view(
        resolve_binary(args.binary),
        static_only=args.static_only,
        dynamic_only=args.dynamic_only,
        args=args.argv,
        timeout=args.timeout,
    )
    report.emit(as_json=args.json)
    return 0 if report.data.get("filter_found") else 1


if __name__ == "__main__":
    sys.exit(main())
