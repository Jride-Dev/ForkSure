from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LicenseFinding:
    repository: str
    license_key: str | None
    status: str


def summarize_license(repository: str, license_key: str | None) -> LicenseFinding:
    status = "unknown" if license_key is None else "detected"
    return LicenseFinding(repository=repository, license_key=license_key, status=status)
