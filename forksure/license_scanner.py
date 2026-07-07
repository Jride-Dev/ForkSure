from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class LicenseFinding:
    repository: str
    license_key: str | None
    status: str


def summarize_license(repository: str, license_key: str | None) -> LicenseFinding:
    status = "unknown" if license_key is None else "detected"
    return LicenseFinding(repository=repository, license_key=license_key, status=status)


def compare_licenses(source_license: Mapping[str, Any], fork_license: Mapping[str, Any]) -> dict[str, str]:
    source_name = format_license(source_license)
    fork_name = format_license(fork_license)

    if source_license.get("error") or fork_license.get("error"):
        return {
            "status": "unknown",
            "severity": "low",
            "summary": "License lookup failed; drift could not be determined.",
        }

    if not source_license.get("found"):
        return {
            "status": "unknown",
            "severity": "low",
            "summary": "Source repository license is missing or unknown; drift could not be determined.",
        }

    if not fork_license.get("found"):
        return {
            "status": "missing",
            "severity": "medium",
            "summary": f"Fork license is missing; source license is {source_name}.",
        }

    source_id = _license_identifier(source_license)
    fork_id = _license_identifier(fork_license)
    if not source_id or not fork_id:
        return {
            "status": "unknown",
            "severity": "low",
            "summary": "One or both licenses could not be identified confidently.",
        }

    if source_id.casefold() == fork_id.casefold():
        return {
            "status": "same",
            "severity": "info",
            "summary": f"Fork license matches source license {source_name}.",
        }

    return {
        "status": "changed",
        "severity": "high",
        "summary": f"Fork license changed from {source_name} to {fork_name}.",
    }


def format_license(license_data: Mapping[str, Any] | None) -> str:
    if not license_data:
        return "unknown"
    if license_data.get("error"):
        return "unknown"
    if not license_data.get("found"):
        return "missing"
    return _license_identifier(license_data) or "unknown"


def _license_identifier(license_data: Mapping[str, Any]) -> str | None:
    for key in ("spdx_id", "key", "name"):
        value = license_data.get(key)
        if value:
            return str(value)
    return None
