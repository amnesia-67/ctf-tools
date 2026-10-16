"""A common report object so every tool prints and serialises the same way."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any

from ctftools import __version__
from ctftools.core import term


@dataclass
class Section:
    title: str
    lines: list = field(default_factory=list)

    def add(self, line: str = "") -> None:
        self.lines.append(line)


@dataclass
class Report:
    """Human-readable output plus a machine-readable payload.

    Tools append terminal output through :meth:`section` and fill
    :attr:`data` with the same facts for ``--json``.
    """

    tool: str
    target: str = ""
    sections: list = field(default_factory=list)
    data: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def section(self, title: str) -> Section:
        sec = Section(title)
        self.sections.append(sec)
        return sec

    def note(self, text: str) -> None:
        self.notes.append(text)

    def warn(self, text: str) -> None:
        self.warnings.append(text)

    # ------------------------------------------------------------------ output
    def render(self) -> str:
        out = [term.c(f"{self.tool}", "bold", "magenta") + term.dim(f"  v{__version__}")]
        if self.target:
            out.append(term.dim(f"target: {self.target}"))
        for sec in self.sections:
            out.append(term.heading(sec.title))
            out.extend(sec.lines)
        if self.notes:
            out.append(term.heading("Notes"))
            out.extend(f"  - {n}" for n in self.notes)
        if self.warnings:
            out.append(term.heading("Warnings"))
            out.extend("  " + term.warn(f"! {w}") for w in self.warnings)
        return "\n".join(out) + "\n"

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "tool": self.tool,
            "ctftools_version": __version__,
            "target": self.target,
            "notes": self.notes,
            "warnings": self.warnings,
        }
        payload.update(self.data)
        return payload

    def emit(self, as_json: bool = False, stream=None) -> None:
        stream = stream or sys.stdout
        if as_json:
            json.dump(self.as_dict(), stream, indent=2, default=_fallback)
            stream.write("\n")
        else:
            stream.write(self.render())


def emit(report: Report, as_json: bool = False) -> None:
    report.emit(as_json=as_json)


def _fallback(obj):
    if isinstance(obj, bytes):
        return obj.decode("latin-1")
    return str(obj)
