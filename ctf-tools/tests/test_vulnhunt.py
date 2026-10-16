"""vulnhunt finds the planted bug in each target and clears the safe one."""

from __future__ import annotations

from pathlib import Path

from ctftools.tools import vulnhunt


def _findings(report):
    return report.data["findings"]


def test_gets_is_critical(target):
    report = vulnhunt.scan_binary(target("stack_basic"))
    gets = next(f for f in _findings(report) if f["sink"] == "gets")
    assert gets["severity"] == "critical"
    assert gets["function"] == "vuln"
    assert gets["buffer_size"] == 64
    assert gets["offset_to_return_address"] == 72


def test_oversized_read_is_critical(target):
    report = vulnhunt.scan_binary(target("nx_rop"))
    read = next(f for f in _findings(report) if f["sink"] == "read")
    assert read["severity"] == "critical"
    assert read["read_size"] == 400
    assert read["buffer_size"] == 80


def test_bounded_read_is_only_informational(target):
    report = vulnhunt.scan_binary(target("bounded_read"))
    read = next(f for f in _findings(report) if f["sink"] == "read")
    assert read["severity"] == "info"
    assert "correctly bounded" in read["detail"]
    assert read["offset_to_return_address"] is None


def test_canary_position_is_reported(target):
    report = vulnhunt.scan_binary(target("canary_guard"))
    gets = next(f for f in _findings(report) if f["sink"] == "gets")
    assert gets["canary_displacement"] == 8
    assert "canary" in gets["detail"]


def test_min_severity_filters(target):
    full = vulnhunt.scan_binary(target("bounded_read"))
    strict = vulnhunt.scan_binary(target("bounded_read"), min_severity="high")
    assert len(strict.data["findings"]) < len(full.data["findings"])
    assert all(f["severity"] in ("critical", "high") for f in strict.data["findings"])


def test_source_scan_finds_the_format_string(vulnerable_dir: Path):
    report = vulnhunt.scan_source(str(vulnerable_dir / "fmt_string.c"))
    findings = _findings(report)
    assert any("format string" in f["detail"] for f in findings)
    assert all(f["severity"] in vulnhunt.SEVERITY_ORDER for f in findings)


def test_source_scan_flags_gets(vulnerable_dir: Path):
    report = vulnhunt.scan_source(str(vulnerable_dir / "stack_basic.c"))
    assert any(f["detail"].startswith("gets()") for f in _findings(report))
