"""vulnhunt: find the bug without running anything.

Scans an ELF (or C source) for the sinks that cause memory corruption and
reports, per call site, the buffer it writes and whether the write is bounded.

    vulnhunt ./vuln
    vulnhunt ./vuln --json
    vulnhunt --source chal.c
"""

from __future__ import annotations

import os
import re
import sys

from ctftools.core import disasm, term
from ctftools.core.binary import INPUT_SINKS, load_binary
from ctftools.core.cliutil import add_common_args, apply_output_flags, base_parser, fail, resolve_binary
from ctftools.core.report import Report

# Severity by sink: how much the call is worth looking at first.
SEVERITY = {
    "gets": "critical",
    "strcpy": "high",
    "strcat": "high",
    "sprintf": "high",
    "vsprintf": "high",
    "scanf": "high",
    "__isoc99_scanf": "high",
    "sscanf": "medium",
    "__isoc99_sscanf": "medium",
    "read": "medium",
    "recv": "medium",
    "memcpy": "medium",
    "fgets": "low",
    "getline": "low",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Source patterns, for --source.
SOURCE_PATTERNS = [
    (r"\bgets\s*\(", "critical", "gets() cannot be bounded; always an overflow"),
    (r"\bstrcpy\s*\(", "high", "strcpy() copies until NUL with no bound"),
    (r"\bstrcat\s*\(", "high", "strcat() appends with no bound"),
    (r"\bsprintf\s*\(", "high", "sprintf() formats into a fixed buffer with no bound"),
    (r"\bscanf\s*\(\s*\"[^\"]*%s", "high", "scanf(\"%s\") with no width is unbounded"),
    (r"\bprintf\s*\(\s*(?!\")[A-Za-z_]\w*\s*\)", "critical", "printf() with a non-literal format: format string bug"),
    (r"\b(fprintf|sprintf|snprintf)\s*\([^,]+,\s*(?!\")[A-Za-z_]\w*\s*\)", "critical",
     "non-literal format argument: format string bug"),
    (r"\bsystem\s*\(", "high", "system() reachable: a command injection or ret2system target"),
    (r"\balloca\s*\(", "medium", "alloca() with a user-controlled size moves the stack pointer"),
    (r"\bmemcpy\s*\([^;]*\b(len|size|n|count)\b", "medium", "memcpy() with a variable length: check its bound"),
    (r"\bfree\s*\(", "info", "free(): check for double free and use after free"),
    (r"\[\s*(i|idx|index|n)\s*\]\s*=", "medium", "indexed write: check the bound on the index"),
]


def scan_binary(path: str, min_severity: str = "info") -> Report:
    info = load_binary(path)
    report = Report(tool="vulnhunt", target=path)
    report.data["binary"] = info.as_dict()

    analysis = disasm.analyse(info)
    findings = []

    for buf in analysis.buffers:
        severity = SEVERITY.get(buf.sink, "medium")
        bounded = buf.confidence == "bounded"
        if bounded:
            severity = "info"
        elif buf.size_argument is not None and buf.buffer_displacement is not None:
            if buf.size_argument > buf.buffer_displacement:
                severity = "critical"

        findings.append({
            "severity": severity,
            "sink": buf.sink,
            "function": buf.function,
            "address": buf.call_address,
            "buffer_size": buf.buffer_displacement,
            "read_size": buf.size_argument,
            "offset_to_return_address": None if bounded else buf.predicted_offset,
            "canary_displacement": buf.canary_displacement,
            "detail": _detail(buf, bounded),
        })

    # Imported-but-not-located sinks still deserve a mention.
    located = {f["sink"] for f in findings}
    for name, bounded, note in info.input_sinks:
        if name in located:
            continue
        findings.append({
            "severity": SEVERITY.get(name, "medium") if not bounded else "info",
            "sink": name,
            "function": "?",
            "address": None,
            "buffer_size": None,
            "read_size": None,
            "offset_to_return_address": None,
            "canary_displacement": None,
            "detail": f"imported but no call site resolved: {note}",
        })

    if "printf" in info.useful_imports:
        findings.append({
            "severity": "medium",
            "sink": "printf",
            "function": "?",
            "address": info.useful_imports["printf"],
            "buffer_size": None,
            "read_size": None,
            "offset_to_return_address": None,
            "canary_displacement": None,
            "detail": "printf is imported: check whether user input reaches it as the format argument (fmtool)",
        })
    if "system" in info.useful_imports:
        findings.append({
            "severity": "info",
            "sink": "system",
            "function": "?",
            "address": info.useful_imports["system"],
            "buffer_size": None,
            "read_size": None,
            "offset_to_return_address": None,
            "canary_displacement": None,
            "detail": "system() is imported: a ret2system target already in the binary",
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["function"]))
    findings = _filter(findings, min_severity)
    report.data["findings"] = findings
    if not analysis.available:
        report.warn(analysis.error)

    _render(report, findings, info)
    return report


def _detail(buf, bounded: bool) -> str:
    if bounded:
        return (f"{buf.sink} reads at most {buf.size_argument} bytes into a "
                f"{buf.buffer_displacement} byte buffer: correctly bounded")
    if buf.size_argument is not None and buf.buffer_displacement is not None:
        return (f"{buf.sink} reads up to {buf.size_argument} bytes into a "
                f"{buf.buffer_displacement} byte buffer: {buf.size_argument - buf.buffer_displacement} bytes past it")
    if buf.buffer_displacement is not None:
        note = f"{buf.sink} writes an unbounded amount into a {buf.buffer_displacement} byte buffer"
        if buf.canary_displacement is not None:
            note += f"; the canary sits {buf.buffer_displacement - buf.canary_displacement} bytes in"
        return note
    return buf.note or f"{buf.sink} call site found, buffer not resolved"


def _filter(findings: list, min_severity: str) -> list:
    threshold = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER.get(f["severity"], 9) <= threshold]


def scan_source(path: str, min_severity: str = "info") -> Report:
    report = Report(tool="vulnhunt", target=path)
    with open(path, "r", errors="replace") as fh:
        lines = fh.readlines()

    findings = []
    for number, line in enumerate(lines, 1):
        stripped = line.split("//")[0]
        for pattern, severity, detail in SOURCE_PATTERNS:
            if re.search(pattern, stripped):
                findings.append({
                    "severity": severity,
                    "line": number,
                    "text": line.strip()[:120],
                    "detail": detail,
                })
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"]))
    findings = _filter(findings, min_severity)
    report.data["findings"] = findings

    sec = report.section(f"Source findings ({len(findings)})")
    if not findings:
        sec.add("  " + term.dim("nothing matched"))
    rows = [[_badge(f["severity"]), str(f["line"]), f["text"], term.dim(f["detail"])] for f in findings]
    if rows:
        sec.add(term.table(rows, headers=["Severity", "Line", "Code", "Why"]))
    return report


def _badge(severity: str) -> str:
    return {
        "critical": term.bad("critical"),
        "high": term.bad("high"),
        "medium": term.warn("medium"),
        "low": term.dim("low"),
        "info": term.dim("info"),
    }.get(severity, severity)


def _render(report: Report, findings: list, info) -> None:
    sec = report.section(f"Findings ({len(findings)})")
    if not findings:
        sec.add("  " + term.dim("no known sink found; the read may be inlined or a raw syscall"))
        return
    rows = []
    for finding in findings:
        where = finding["function"]
        if finding["address"]:
            where += f" @ {finding['address']:#x}"
        rows.append([_badge(finding["severity"]), finding["sink"], where, term.dim(finding["detail"])])
    sec.add(term.table(rows, headers=["Severity", "Sink", "Where", "Detail"]))

    actionable = [f for f in findings if f["offset_to_return_address"]]
    if actionable:
        sec.add("")
        sec.add("  " + term.c("predicted offsets to the saved return address:", "bold"))
        sec.add(term.table(
            [[f["function"], f["sink"], str(f["offset_to_return_address"])] for f in actionable],
            headers=["Function", "Sink", "Offset"], indent=4,
        ))
        sec.add("")
        sec.add("  " + term.dim("confirm one with: pwnscan " + os.path.basename(info.path)))


def build_parser():
    parser = base_parser("vulnhunt", "Static scan for overflow and format string sinks.")
    parser.add_argument("target", help="an ELF binary, or a C file with --source")
    parser.add_argument("--source", action="store_true", help="treat the target as C source instead of an ELF")
    parser.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"],
                        default="info", help="hide findings below this severity")
    add_common_args(parser)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    apply_output_flags(args)

    if args.source:
        if not os.path.exists(args.target):
            fail(f"no such file: {args.target}")
        report = scan_source(args.target, args.min_severity)
    else:
        report = scan_binary(resolve_binary(args.target), args.min_severity)

    report.emit(as_json=args.json)
    return 0 if report.data.get("findings") else 1


if __name__ == "__main__":
    sys.exit(main())
