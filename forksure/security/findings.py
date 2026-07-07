from __future__ import annotations

from dataclasses import dataclass


SUPPORTED_SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class SecurityFinding:
    id: str
    category: str
    severity: str
    title: str
    description: str
    file_path: str | None = None
    line: int | None = None
    evidence: str | None = None
    recommendation: str | None = None
    source_tool: str = "forksure"

    def __post_init__(self) -> None:
        severity = self.severity.lower()
        if severity not in SUPPORTED_SEVERITIES:
            allowed = ", ".join(SUPPORTED_SEVERITIES)
            raise ValueError(f"Unsupported severity '{self.severity}'. Expected one of: {allowed}.")
        object.__setattr__(self, "severity", severity)
