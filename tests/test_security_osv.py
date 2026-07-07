import json

from typer.testing import CliRunner

from forksure.cli import app
from forksure.security.findings import SecurityFinding
from forksure.security.osv import _parse_osv_json, scan_osv


def test_osv_scanner_handles_missing_osv_scanner_gracefully(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)

    findings = scan_osv(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].id == "osv-scanner-unavailable"


def test_parser_converts_sample_osv_json_into_findings() -> None:
    raw_json = json.dumps(
        {
            "results": [
                {
                    "source": {"path": "uv.lock"},
                    "packages": [
                        {
                            "package": {"name": "example-lib", "version": "1.2.3"},
                            "vulnerabilities": [
                                {
                                    "id": "OSV-2026-123",
                                    "summary": "Example dependency vulnerability.",
                                    "database_specific": {"severity": "HIGH"},
                                    "affected": [
                                        {
                                            "ranges": [
                                                {
                                                    "events": [
                                                        {"introduced": "0"},
                                                        {"fixed": "1.2.4"},
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )

    findings = _parse_osv_json(raw_json)

    assert len(findings) == 1
    assert findings[0].category == "dependency-vulnerability"
    assert findings[0].severity == "high"
    assert findings[0].title == "OSV-2026-123 in example-lib"
    assert findings[0].description == "Example dependency vulnerability."
    assert findings[0].file_path == "uv.lock"
    assert findings[0].line is None
    assert findings[0].source_tool == "osv-scanner"
    assert "package=example-lib" in (findings[0].evidence or "")
    assert "version=1.2.3" in (findings[0].evidence or "")
    assert "vulnerability=OSV-2026-123" in (findings[0].evidence or "")
    assert "1.2.4" in (findings[0].recommendation or "")


def test_critical_vulnerability_maps_to_critical_severity() -> None:
    raw_json = json.dumps(
        {
            "results": [
                {
                    "source": {"path": "poetry.lock"},
                    "packages": [
                        {
                            "package": {"name": "critical-lib", "version": "0.1.0"},
                            "vulnerabilities": [
                                {
                                    "id": "OSV-CRITICAL",
                                    "summary": "Critical vulnerability.",
                                    "database_specific": {"severity": "CRITICAL"},
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )

    finding = _parse_osv_json(raw_json)[0]

    assert finding.severity == "critical"


def test_malformed_osv_json_returns_medium_finding() -> None:
    findings = _parse_osv_json("not json")

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].id == "osv-malformed-json"


def test_cli_security_osv_invokes_without_real_osv_scanner(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "forksure.cli.scan_osv",
        lambda path: [
            SecurityFinding(
                id="osv-test",
                category="dependency-vulnerability",
                severity="critical",
                title="OSV-TEST in package",
                description="Test OSV finding.",
                file_path="uv.lock",
                evidence="package=package version=1.0.0 vulnerability=OSV-TEST",
                source_tool="osv-scanner",
            )
        ],
    )
    runner = CliRunner()

    result = runner.invoke(app, ["security", "osv", str(tmp_path)])

    assert result.exit_code == 0
    assert "CRITICAL" in result.output
    assert "OSV-TEST in package" in result.output
    assert "Security score" in result.output
