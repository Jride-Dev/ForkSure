from __future__ import annotations

from pathlib import Path

from .findings import SecurityFinding
from .scripts import scan_unsafe_scripts
from .secrets import scan_secrets


def run_security_audit(path: str | Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    findings.extend(scan_unsafe_scripts(path))
    findings.extend(scan_secrets(path))
    return findings
