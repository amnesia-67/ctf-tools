"""ctftools: a toolkit for binary exploitation in CTFs.

Every tool is both a CLI entry point and an importable module.  The shared
machinery (ELF parsing, mitigation detection, process launching, crash
analysis, reporting) lives in :mod:`ctftools.core`.
"""

__version__ = "0.1.0"

TOOLS = [
    "pwnscan",
    "pwngen",
    "vulnhunt",
    "fuzzlite",
    "seccompview",
    "gadgetfind",
    "ropchain",
    "sropkit",
    "shellgen",
    "pwninit_lite",
    "fmtool",
    "canbrute",
    "stackviz",
    "heapscope",
    "symwin",
    "pwnrun",
]
