import json

from typer.testing import CliRunner

from forksure.cli import app
from forksure.security.findings import SecurityFinding
from forksure.security.sast import _parse_semgrep_json, scan_sast


def test_sast_scanner_handles_missing_semgrep_gracefully(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    findings = scan_sast(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].id == "sast-semgrep-unavailable"


def test_parser_converts_sample_semgrep_json_into_findings() -> None:
    raw_json = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.flask.security.injection.sql",
                    "path": "app.py",
                    "start": {"line": 12, "col": 5},
                    "extra": {
                        "message": "Possible SQL injection.",
                        "severity": "WARNING",
                        "lines": "db.execute('SELECT * FROM users WHERE id = ' + user_id)",
                    },
                }
            ]
        }
    )

    findings = _parse_semgrep_json(raw_json)

    assert len(findings) == 1
    assert findings[0].category == "sast"
    assert findings[0].severity == "medium"
    assert findings[0].title == "python.flask.security.injection.sql"
    assert findings[0].description == "Possible SQL injection."
    assert findings[0].file_path == "app.py"
    assert findings[0].line == 12
    assert findings[0].source_tool == "semgrep"


def test_semgrep_error_maps_to_high_severity() -> None:
    raw_json = json.dumps(
        {
            "results": [
                {
                    "check_id": "javascript.express.security.audit.xss",
                    "path": "web.js",
                    "start": {"line": 22},
                    "extra": {
                        "message": "Possible XSS.",
                        "severity": "ERROR",
                        "lines": "res.send(req.query.name)",
                    },
                }
            ]
        }
    )

    finding = _parse_semgrep_json(raw_json)[0]

    assert finding.severity == "high"


def test_malformed_semgrep_json_returns_medium_finding() -> None:
    findings = _parse_semgrep_json("not json")

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].id == "sast-semgrep-malformed-json"


def test_semgrep_evidence_is_limited() -> None:
    raw_json = json.dumps(
        {
            "results": [
                {
                    "check_id": "test.long.line",
                    "path": "app.py",
                    "start": {"line": 1},
                    "extra": {
                        "message": "Long evidence.",
                        "severity": "INFO",
                        "lines": "x" * 200,
                    },
                }
            ]
        }
    )

    finding = _parse_semgrep_json(raw_json)[0]

    assert finding.evidence is not None
    assert len(finding.evidence) <= 160


def test_cli_security_sast_invokes_without_real_semgrep(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "forksure.cli.scan_sast",
        lambda path, rules=None: [
            SecurityFinding(
                id="sast-test",
                category="sast",
                severity="high",
                title="test.sast",
                description="Test SAST finding.",
                file_path="app.py",
                line=3,
                evidence="dangerous_call()",
                source_tool="semgrep",
            )
        ],
    )
    runner = CliRunner()

    result = runner.invoke(app, ["security", "sast", str(tmp_path), "--rules", "sql,xss,csrf"])

    assert result.exit_code == 0
    assert "HIGH" in result.output
    assert "test.sast" in result.output
    assert "Security score" in result.output
