"""Finding the distance from an input buffer to the saved return address.

The dynamic method is authoritative: send a De Bruijn pattern, read the
register state at the crash, and locate the controlled value in the pattern.
The static frame analysis in :mod:`ctftools.core.disasm` is used as a
cross-check, and a second run with a known marker turns a candidate offset
into a confirmed one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ctftools.core import disasm
from ctftools.core.crash import CrashState, gdb_crash
from ctftools.core.runner import Limits, run_target

# Canonical, non-NUL marker addresses used to confirm control of the
# instruction pointer.  Six bytes on x86-64 so the value stays canonical.
MARKER_64 = 0xDEADBEEFCAFE
MARKER_32 = 0xDEADBEEF

DEFAULT_LENGTHS = (200, 500, 1200, 3000)


@dataclass
class OffsetResult:
    """What we learned about the overflow."""

    offset: int | None = None
    status: str = "unknown"  # confirmed | likely | canary-blocked | unknown
    method: str = ""
    pattern_length: int = 0
    static_offset: int | None = None
    static_note: str = ""
    agreement: str = "not compared"
    pc_control: bool = False
    canary_offset: int | None = None
    buffer_size: int | None = None
    verification: dict = field(default_factory=dict)
    crash: Any = None
    notes: list = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "status": self.status,
            "method": self.method,
            "pattern_length": self.pattern_length,
            "static_offset": self.static_offset,
            "static_note": self.static_note,
            "agreement": self.agreement,
            "pc_control": self.pc_control,
            "canary_offset": self.canary_offset,
            "buffer_size": self.buffer_size,
            "verification": self.verification,
            "crash": self.crash.as_dict() if isinstance(self.crash, CrashState) else None,
            "notes": self.notes,
        }


def cyclic_pattern(length: int, word: int) -> bytes:
    from pwnlib.util.cyclic import cyclic

    return cyclic(length, n=word)


def find_in_pattern(value: int, word: int, pattern: bytes) -> int | None:
    """Locate *value* inside *pattern*, tolerating a partial overwrite."""
    if not value:
        return None
    raw = value.to_bytes(word, "little")
    for size in range(word, 3, -1):
        chunk = raw[:size]
        if not all(0x20 <= b < 0x7F for b in chunk):
            continue
        index = pattern.find(chunk)
        if index != -1 and pattern.find(chunk, index + 1) == -1:
            return index
    return None


def find_offset(
    info,
    prefix: bytes = b"",
    args=(),
    timeout: float = 10.0,
    lengths=DEFAULT_LENGTHS,
    sandbox: bool = True,
    static: bool = True,
) -> OffsetResult:
    """Find and verify the offset from the input buffer to the return address."""
    word = info.word
    result = OffsetResult()

    if static:
        analysis = disasm.analyse(info)
        best = analysis.best() if analysis.available else None
        if best is not None:
            result.buffer_size = best.buffer_displacement
            result.static_note = best.note or (
                f"{best.sink} writes a buffer at rbp-{(best.buffer_displacement or 0):#x} in {best.function}"
            )
            if best.confidence == "bounded":
                result.notes.append(
                    f"the only input sink found ({best.sink} in {best.function}) is correctly bounded; "
                    "any overflow is elsewhere"
                )
            else:
                result.static_offset = best.predicted_offset
        elif not analysis.available:
            result.notes.append(analysis.error)

    limits = Limits(enabled=sandbox)

    # ------------------------------------------------------- dynamic discovery
    crash = None
    pattern = b""
    for length in lengths:
        candidate_pattern = cyclic_pattern(length, word)
        payload = prefix + candidate_pattern + b"\n"
        quick = run_target(info.path, payload, args=args, timeout=timeout, limits=limits)
        if not (quick.crashed or quick.timed_out):
            continue
        attempt = gdb_crash(info.path, payload, args=args, bits=info.bits, timeout=max(25.0, timeout * 4))
        if attempt.crashed:
            crash, pattern = attempt, candidate_pattern
            result.pattern_length = length
            break

    if crash is None:
        result.status = "unknown"
        result.method = "no crash"
        result.notes.append(
            "the target did not crash on any pattern up to %d bytes; it may need a prefix "
            "interaction (--prefix), arguments (--arg), or it takes input another way" % max(lengths)
        )
        return result

    result.crash = crash

    # Canary abort: the overflow never reaches the return address.
    if crash.canary_abort:
        result.status = "canary-blocked"
        result.method = "canary abort observed"
        result.canary_offset = _find_canary_offset(info, prefix, args, timeout, limits, max(lengths))
        if result.canary_offset is not None:
            result.offset = result.canary_offset + 2 * word
            result.notes.append(
                "canary starts at %d bytes; the saved return address is at %d, but the "
                "overflow aborts unless the canary is leaked or brute forced"
                % (result.canary_offset, result.offset)
            )
            result.agreement = _agree(result.offset, result.static_offset)
        else:
            result.notes.append("the canary aborted the process; could not bracket its offset")
        return result

    candidate, method, pc_control = _candidate_from_crash(crash, pattern, word)
    if candidate is None:
        result.status = "unknown"
        result.method = "crash without a recognisable pattern value"
        result.notes.append(
            "the target crashed but neither the instruction pointer nor the top of the "
            "stack held pattern bytes: the overflow may corrupt a pointer used before the return"
        )
        return result

    result.offset = candidate
    result.method = method
    result.pc_control = pc_control
    result.status = "likely"
    result.agreement = _agree(candidate, result.static_offset)

    # --------------------------------------------------------- verification
    marker = MARKER_64 if info.bits == 64 else MARKER_32
    marker_bytes = marker.to_bytes(8, "little")[:6] if info.bits == 64 else marker.to_bytes(4, "little")
    payload = prefix + b"A" * candidate + marker_bytes + b"\n"
    check = gdb_crash(info.path, payload, args=args, bits=info.bits, timeout=max(25.0, timeout * 4))
    observed = check.pc
    mask = (1 << (8 * len(marker_bytes))) - 1
    in_pc = observed == marker
    # A sink that NUL-terminates leaves the byte above the marker untouched, so
    # the attempted return address can be non-canonical.  The CPU then faults on
    # the ret itself and the value stays on the stack: compare the bytes we
    # actually control.
    slot = next(
        (value for value in (check.stack_word(0), check.stack_word(-word))
         if value is not None and (value & mask) == marker),
        None,
    )
    result.verification = {
        "marker": marker,
        "payload_length": len(payload),
        "observed_pc": observed,
        "observed_signal": check.signal,
        "return_slot": slot,
        "matched": in_pc or slot is not None,
        "where": "instruction pointer" if in_pc else ("return slot" if slot is not None else "nowhere"),
    }
    if in_pc:
        result.status = "confirmed"
        result.pc_control = True
        result.notes.append(
            "verified: %d filler bytes then a %d byte address land in the instruction pointer"
            % (candidate, len(marker_bytes))
        )
    elif slot is not None:
        result.status = "confirmed"
        result.pc_control = True
        result.notes.append(
            "verified: the marker reached the saved return address. The fault is on the ret "
            "itself because the byte above the marker is not zero, which makes the address "
            "non-canonical; a real exploit address keeps all 8 bytes under control"
        )
    else:
        result.notes.append(
            "the verification run did not put the marker in the instruction pointer or the "
            "return slot (observed %s): treat the offset as a strong guess, not a fact"
            % (hex(observed) if observed else "nothing")
        )

    return result


def _candidate_from_crash(crash: CrashState, pattern: bytes, word: int):
    """Work out the offset from the register state."""
    pc, sp = crash.pc, crash.sp

    if pc is not None:
        index = find_in_pattern(pc, word, pattern)
        if index is not None:
            return index, "pattern bytes found in the instruction pointer", True

    # On x86-64 a non-canonical return address faults at the ret itself, so
    # the attempted address is still sitting at the stack pointer.
    for shift, label in ((0, "top of stack"), (-word, "just below the stack pointer")):
        value = crash.stack_word(shift)
        if value is None:
            continue
        index = find_in_pattern(value, word, pattern)
        if index is not None:
            return index, f"pattern bytes found at the {label} after a faulting ret", True

    # A saved frame pointer overwrite still tells us where the buffer ends.
    for name in ("rbp", "ebp"):
        value = crash.regs.get(name)
        if value:
            index = find_in_pattern(value, word, pattern)
            if index is not None:
                return index + word, "derived from the overwritten saved frame pointer", False

    return None, "", False


def _find_canary_offset(info, prefix, args, timeout, limits, max_length: int) -> int | None:
    """Bracket the shortest input that smashes the canary."""

    def smashes(length: int) -> bool:
        payload = prefix + b"A" * length + b"\n"
        res = run_target(info.path, payload, args=args, timeout=timeout, limits=limits)
        return b"stack smashing detected" in res.stderr or res.classify() in ("canary-abort", "abort")

    low, high = 0, min(max_length, 4096)
    if not smashes(high):
        return None
    while low + 1 < high:
        mid = (low + high) // 2
        if smashes(mid):
            high = mid
        else:
            low = mid
    # `high` is the shortest input that trips the check; the first canary byte
    # is the one before it (the NUL terminator written at index high-1 lands on
    # the canary's own NUL byte and changes nothing).
    return high - 1


def _agree(dynamic: int | None, static: int | None) -> str:
    if dynamic is None or static is None:
        return "not compared"
    if dynamic == static:
        return "static analysis agrees"
    return f"static analysis predicted {static}, {abs(dynamic - static)} bytes away"
