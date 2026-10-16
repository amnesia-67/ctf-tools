"""Build the deliberately vulnerable test targets once per session."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

VULN_DIR = Path(__file__).parent / "vulnerable"

# Known-good ground truth for the sample targets, used across the test suite.
EXPECTED = {
    "stack_basic": {"offset": 72, "canary": False, "pie": False, "nx": True},
    "ret2win": {"offset": 56, "canary": False, "pie": False, "nx": True},
    "canary_guard": {"offset": 72, "canary": True, "pie": False, "nx": True},
    "nx_rop": {"offset": 88, "canary": False, "pie": False, "nx": True},
    "pie_win": {"offset": 72, "canary": False, "pie": True, "nx": True},
    "menu_prefix": {"offset": 88, "canary": False, "pie": False, "nx": True},
}


@pytest.fixture(scope="session")
def vulnerable_dir() -> Path:
    if shutil.which("gcc") is None:
        pytest.skip("gcc is needed to build the test targets")
    subprocess.run(["make", "-s"], cwd=VULN_DIR, check=True, capture_output=True)
    return VULN_DIR


@pytest.fixture(scope="session")
def target(vulnerable_dir):
    def _get(name: str) -> str:
        path = vulnerable_dir / name
        if not path.exists():
            pytest.skip(f"{name} was not built")
        return str(path)

    return _get


@pytest.fixture(scope="session")
def target_module(vulnerable_dir):
    """The same as `target`, usable from module-scoped fixtures."""

    def _get(name: str) -> str:
        path = vulnerable_dir / name
        if not path.exists():
            pytest.skip(f"{name} was not built")
        return str(path)

    return _get


@pytest.fixture(scope="session")
def have_gdb() -> bool:
    return shutil.which("gdb") is not None
