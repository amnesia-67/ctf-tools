# ctftools

A toolkit for binary exploitation in CTFs. Every tool is a CLI and an importable
Python module, prints a readable report by default and `--json` on request, so
results chain into exploit scripts.

```
pip install -e .
pwnscan ./vuln
```

Or through the umbrella command:

```
ctftools pwnscan ./vuln
ctftools --help
```

## Tools

| Command | What it does |
| --- | --- |
| `pwnscan` | checksec, the offset to the saved return address, and a verified exploit path |
| `pwngen` | writes an `exploit.py` from a `pwnscan` result |
| `vulnhunt` | static scan for overflow and format string sinks |
| `fuzzlite` | fuzzes the input surface and classifies the crashes |
| `seccompview` | dumps and decodes a binary's seccomp filter |
| `gadgetfind` | ROP gadget search with bad-byte filtering |
| `ropchain` | builds ret2plt, ret2libc and `execve` chains |
| `sropkit` | SROP frames and ret2dlresolve payloads |
| `shellgen` | generates and tests shellcode |
| `pwninit-lite` | patches a binary to run against a challenge libc |
| `fmtool` | finds the format string offset and builds writes |
| `canbrute` | brute forces canaries and addresses against a forking server |
| `stackviz` | draws the stack frame and overlays a payload |
| `heapscope` | inspects glibc heap state through GDB |
| `symwin` | uses angr to find an input that reaches a chosen function |
| `pwnrun` | one runner for local, GDB and remote targets |

## pwnscan

The triage tool. It runs the target, so use it on CTF binaries in a sandbox.

```
pwnscan ./vuln                    # full triage
pwnscan ./vuln --json             # machine-readable
pwnscan ./vuln --prefix '1\n'     # send a menu choice before the payload
pwnscan ./vuln --no-offset        # checksec only, never executes the target
pwnscan ./vuln --gadgets          # also list the gadgets the path needs
```

What it does, in order:

1. **Checksec** — RELRO, canary, NX, PIE, FORTIFY, RWX segments, linkage and
   symbols, each row with what it means for exploitation.
2. **Input discovery** — which sinks the binary imports and whether each one is
   bounded.
3. **Offset** — sends a De Bruijn pattern, reads the register state at the crash
   through GDB, and locates the controlled value in the pattern. On x86-64 a
   non-canonical return address faults on the `ret` itself, so the attempted
   address is recovered from the stack as well as from `RIP`.
4. **Cross-check** — disassembles the call to the sink, reads the buffer's
   displacement from `rbp`, and compares that prediction with the dynamic
   result. The report says whether the two agree.
5. **Verification** — replays the overflow with a known marker address. Only
   when the marker turns up in the instruction pointer or the return slot is the
   offset reported as `confirmed` rather than `likely`.
6. **Exploit path** — rules on shellcode, ret2win, ret2plt/ret2libc, `execve`
   chains, GOT overwrite, canary leaks and PIE leaks, listing each requirement
   as met or missing. Paths that can be tested cheaply (ret2win) are actually
   run, and the report says `proven` only if the exploit worked.

Exit status is 0 when an offset was found, 1 when it was not.

### Example

```
Offset to the saved return address
  56 bytes   confirmed
  method                       pattern bytes found at the top of stack after a faulting ret
  static cross-check           static analysis agrees
  instruction pointer control  yes
  verification                 marker 0xdeadbeefcafe landed in the return slot

Exploit paths
  [proven] ret2win (win)
      Return straight into win at 0x401196.
      yes  the overflow reaches the saved return address - confirmed at offset 56
      yes  the target function is at a known address - 0x401196
      verified: direct return: the target printed a flag-like string
```

## The other tools

Each one takes `--help` and `--json`, and prints a report by default.

```
vulnhunt ./vuln                        # static: which sink, which buffer, how far past it
vulnhunt chal.c --source                # the same idea over C source
fuzzlite ./vuln --save crashes/         # fuzz, classify, deduplicate by crash PC
pwngen ./vuln -o solve.py               # write the exploit script
gadgetfind ./vuln 'pop ? ; ret' --bad 0a00
ropchain ./vuln --leak --offset 72      # ret2plt leak, then --system with a libc
sropkit ./vuln --srop --offset 88       # sigreturn frame, or --dlresolve
shellgen orw /flag.txt --test           # shellcode, encoded and run to prove it works
seccompview ./jail                      # decode the filter, per syscall
fmtool ./fmt --got puts --to 0x401196   # format string offset, leaks and writes
pwninit-lite ./vuln --libc ./libc.so.6  # run it against the challenge libc
canbrute --host h --port p --offset 72 --length 8 --marker ok
stackviz ./vuln --payload-hex 4141...   # see exactly what a payload overwrites
heapscope ./chal --break getchar        # chunks, tcache, and what is corrupt
symwin ./chal win                       # angr: an input that reaches a function
pwnrun ./vuln -r 'input:' -l AAAA --script solve.py
```

A few notes on what they do that is not obvious from the name:

- **vulnhunt** reports a correctly bounded read as `info` with the reason, so a
  safe binary reads as safe rather than as an empty result.
- **fuzzlite** deduplicates by crash class and PC: sixteen crashes usually come
  from three bugs.
- **seccompview** catches `prctl(PR_SET_SECCOMP)` under GDB and reads the filter
  out of the live process, then evaluates it per syscall. Rules that depend on
  argument values are reported as conditional rather than guessed.
- **canbrute** needs a server that forks per connection; one that re-execs gets
  a fresh canary each time and cannot be brute forced. It says so when it fails.
- **heapscope** demangles glibc 2.32+ tcache pointers, so a one-entry bin reads
  as one entry instead of walking into the mangling key.
- **symwin** needs angr (`pip install 'ctftools[symbolic]'`). Without it, it
  still prints the plan it would hand to angr instead of failing.

## Requirements

- Python 3.9+ and [pwntools](https://docs.pwntools.com)
- GDB, for reading the crash state (`pwnscan`, `heapscope`)
- Optional: `patchelf`, `angr` (`pip install 'ctftools[symbolic]'`)

## Tests

`tests/vulnerable/` holds small, deliberately vulnerable C programs with known
stack layouts; the suite checks each tool against that ground truth.

```
make -C tests/vulnerable
python -m pytest
```

## Scope

These tools run untrusted binaries. Targets are launched under a wall clock
timeout and with CPU, address space and core limits unless `--no-sandbox` is
given. Use them on CTF challenges and binaries you are authorised to test.
