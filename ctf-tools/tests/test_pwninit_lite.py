"""pwninit-lite identifies a libc and makes the binary run against it."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ctftools.tools import pwninit_lite

SYSTEM_LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
SYSTEM_LOADER = "/lib64/ld-linux-x86-64.so.2"


@pytest.fixture
def challenge(tmp_path: Path, target) -> Path:
    """A challenge directory: the binary, its libc and its loader."""
    if not Path(SYSTEM_LIBC).exists():
        pytest.skip("no glibc to copy")
    directory = tmp_path / "chal"
    directory.mkdir()
    shutil.copy2(target("stack_basic"), directory / "vuln")
    shutil.copy2(SYSTEM_LIBC, directory / "libc.so.6")
    if Path(SYSTEM_LOADER).exists():
        shutil.copy2(SYSTEM_LOADER, directory / "ld-linux-x86-64.so.2")
    return directory


def test_libc_version_is_read_from_the_file(challenge: Path):
    version, banner = pwninit_lite.libc_version(str(challenge / "libc.so.6"))
    assert version and version.startswith("2.")
    assert "GNU C Library" in banner


def test_loader_next_to_the_libc_is_found(challenge: Path):
    version, _ = pwninit_lite.libc_version(str(challenge / "libc.so.6"))
    loader = pwninit_lite.find_loader(str(challenge / "libc.so.6"), version)
    assert loader is not None
    assert Path(loader).name.startswith("ld-")


def test_prepare_produces_something_runnable(challenge: Path):
    report = pwninit_lite.prepare(str(challenge / "vuln"), str(challenge / "libc.so.6"))
    assert report.data["ready"] is True
    assert report.data["libc_version"].startswith("2.")
    assert report.data["method"] in ("patchelf", "inplace", "wrapper")
    assert report.data["verified"] is True


def test_wrapper_runs_the_binary(challenge: Path):
    from ctftools.core.runner import run_target

    report = pwninit_lite.prepare(str(challenge / "vuln"), str(challenge / "libc.so.6"),
                                  method="wrapper", check=False)
    script = Path(report.data["output"] + ".sh")
    assert script.exists() and script.stat().st_mode & 0o111

    text = script.read_text()
    assert "--library-path" in text
    assert str(challenge) in text


def test_missing_loader_is_reported_not_guessed(tmp_path: Path, target):
    directory = tmp_path / "only-libc"
    directory.mkdir()
    shutil.copy2(target("stack_basic"), directory / "vuln")
    # A file that parses as a libc but has no loader beside it.
    shutil.copy2(SYSTEM_LIBC, directory / "libc.so.6")
    monkey = pwninit_lite.find_loader
    try:
        pwninit_lite.find_loader = lambda *a, **k: None
        report = pwninit_lite.prepare(str(directory / "vuln"), str(directory / "libc.so.6"))
    finally:
        pwninit_lite.find_loader = monkey

    assert report.data["ready"] is False
    assert any("loader" in w for w in report.warnings)
