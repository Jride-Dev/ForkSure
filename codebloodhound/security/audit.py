from __future__ import annotations

from pathlib import Path

from .dependencies import scan_dependencies
from .findings import SecurityFinding
from .sast import scan_sast
from .secrets import scan_secrets
from .scripts import scan_unsafe_scripts


def run_security_audit(path: str | Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    findings.extend(scan_unsafe_scripts(path))
    findings.extend(scan_dependencies(path))
    findings.extend(scan_secrets(path))
    findings.extend(scan_sast(path))
    return findings
