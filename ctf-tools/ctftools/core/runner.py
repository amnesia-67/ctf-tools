"""Running target binaries safely.

Targets in a CTF are untrusted code.  Everything here runs them under a wall
clock timeout and, by default, with CPU, address space and core size limits,
so a runaway or memory-hungry target cannot take the host down.
"""

from __future__ import annotations

import os
import resource
import shlex
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class Limits:
    """Resource limits applied to a target process."""

    cpu_seconds: int = 10
    address_space_mb: int = 2048
    core_size: int = 0
    enabled: bool = True

    def preexec(self):
        if not self.enabled:
            return None

        cpu = self.cpu_seconds
        mem = self.address_space_mb * 1024 * 1024
        core = self.core_size

        def _apply():  # pragma: no cover - runs in the child
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            except (ValueError, OSError):
                pass
            resource.setrlimit(resource.RLIMIT_CORE, (core, core))
            os.setsid()

        return _apply


@dataclass
class RunResult:
    """The outcome of one run of a target."""

    stdout: bytes = b""
    stderr: bytes = b""
    returncode: int | None = None
    signal: int | None = None
    timed_out: bool = False
    argv: list = field(default_factory=list)

    @property
    def crashed(self) -> bool:
        return self.signal in (signal.SIGSEGV, signal.SIGBUS, signal.SIGILL, signal.SIGABRT)

    @property
    def signal_name(self) -> str | None:
        if self.signal is None:
            return None
        try:
            return signal.Signals(self.signal).name
        except ValueError:
            return f"SIG{self.signal}"

    def classify(self) -> str:
        """A short label for what happened."""
        if self.timed_out:
            return "timeout"
        if self.signal == signal.SIGSEGV:
            return "segfault"
        if self.signal == signal.SIGABRT:
            if b"stack smashing detected" in self.stderr:
                return "canary-abort"
            if b"free()" in self.stderr or b"malloc" in self.stderr or b"corrupt" in self.stderr:
                return "heap-abort"
            return "abort"
        if self.signal == signal.SIGBUS:
            return "bus-error"
        if self.signal == signal.SIGILL:
            return "illegal-instruction"
        if self.signal == signal.SIGFPE:
            return "fpe"
        if self.signal == signal.SIGSYS:
            return "seccomp-kill"
        if self.signal is not None:
            return f"signal-{self.signal_name}"
        return "exit-%d" % (self.returncode or 0)

    def as_dict(self) -> dict:
        return {
            "classification": self.classify(),
            "returncode": self.returncode,
            "signal": self.signal_name,
            "timed_out": self.timed_out,
            "stdout": self.stdout[-4096:].decode("latin-1"),
            "stderr": self.stderr[-4096:].decode("latin-1"),
        }


def run_target(
    path: str,
    stdin_data: bytes = b"",
    args: Sequence[str] = (),
    timeout: float = 5.0,
    env: dict | None = None,
    limits: Limits | None = None,
    cwd: str | None = None,
) -> RunResult:
    """Run *path* once with *stdin_data* on its standard input."""
    argv = [os.path.abspath(path), *args]
    limits = limits if limits is not None else Limits()

    full_env = dict(os.environ if env is None else env)
    full_env.setdefault("LC_ALL", "C")

    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=limits.preexec(),
        env=full_env,
        cwd=cwd,
    )
    timed_out = False
    try:
        out, err = proc.communicate(input=stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, err = proc.communicate()

    code = proc.returncode
    sig = -code if code is not None and code < 0 else None
    return RunResult(
        stdout=out or b"",
        stderr=err or b"",
        returncode=code,
        signal=sig,
        timed_out=timed_out,
        argv=argv,
    )


def quote_argv(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
