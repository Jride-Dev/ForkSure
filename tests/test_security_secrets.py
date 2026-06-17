import json

from typer.testing import CliRunner

from codebloodhound.cli import app
from codebloodhound.security.findings import SecurityFinding
from codebloodhound.security.secrets import _parse_gitleaks_json, scan_secrets


def test_secrets_scanner_handles_missing_gitleaks_gracefully(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("codebloodhound.security.secrets.shutil.which", lambda name: None)

    findings = scan_secrets(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].id == "secrets-gitleaks-unavailable"


def test_parser_converts_sample_gitleaks_json_into_findings() -> None:
    raw_json = json.dumps(
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "settings.py",
                "StartLine": 7,
                "Secret": "abcd1234wxyz",
            }
        ]
    )

    findings = _parse_gitleaks_json(raw_json)

    assert len(findings) == 1
    assert findings[0].category == "secrets"
    assert findings[0].severity == "high"
    assert findings[0].file_path == "settings.py"
    assert findings[0].line == 7
    assert findings[0].source_tool == "gitleaks"


def test_parser_redacts_secrets() -> None:
    raw_json = json.dumps(
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": ".env",
                "StartLine": 1,
                "Secret": "sk_live_super_secret_value",
            }
        ]
    )

    finding = _parse_gitleaks_json(raw_json)[0]

    assert "sk_live_super_secret_value" not in (finding.evidence or "")
    assert "sk_l...REDACTED...alue" in (finding.evidence or "")


def test_critical_looking_token_produces_critical_severity() -> None:
    raw_json = json.dumps(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub token",
                "File": ".env",
                "StartLine": 2,
                "Secret": "ghp_1234567890abcdef",
            }
        ]
    )

    finding = _parse_gitleaks_json(raw_json)[0]

    assert finding.severity == "critical"


def test_parser_handles_malformed_json_gracefully() -> None:
    findings = _parse_gitleaks_json("not json")

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].id == "secrets-gitleaks-malformed-json"


def test_cli_security_secrets_invokes_without_real_gitleaks(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "codebloodhound.cli.scan_secrets",
        lambda path: [
            SecurityFinding(
                id="secret-test",
                category="secrets",
                severity="critical",
                title="Potential secret: test",
                description="Test finding.",
                file_path=".env",
                line=1,
                evidence="secret=[REDACTED]",
            )
        ],
    )
    runner = CliRunner()

    result = runner.invoke(app, ["security", "secrets", str(tmp_path)])

    assert result.exit_code == 0
    assert "CRITICAL" in result.output
    assert "Security score" in result.output
