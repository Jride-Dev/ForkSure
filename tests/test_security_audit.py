from typer.testing import CliRunner

from forksure.cli import app
from forksure.security.audit import run_security_audit
from forksure.security.findings import SecurityFinding
from forksure.security.scoring import calculate_security_score


def test_combined_audit_returns_findings_from_both_scanners(monkeypatch, tmp_path) -> None:
    script_finding = SecurityFinding(
        id="unsafe-script-curl-pipe-shell",
        category="unsafe-script",
        severity="high",
        title="curl output piped to shell",
        description="Script finding.",
    )
    secret_finding = SecurityFinding(
        id="secrets-gitleaks-unavailable",
        category="secrets",
        severity="info",
        title="Gitleaks unavailable",
        description="Secret scanner finding.",
    )
    dependency_finding = SecurityFinding(
        id="deps-python-uv-lockfile-found",
        category="dependencies",
        severity="info",
        title="Python uv lockfile found",
        description="Dependency scanner finding.",
    )
    osv_finding = SecurityFinding(
        id="osv-scanner-unavailable",
        category="dependency-vulnerability",
        severity="info",
        title="OSV Scanner unavailable",
        description="OSV scanner finding.",
    )
    sast_finding = SecurityFinding(
        id="sast-semgrep-unavailable",
        category="sast",
        severity="info",
        title="Semgrep unavailable",
        description="SAST scanner finding.",
    )
    monkeypatch.setattr("forksure.security.audit.scan_unsafe_scripts", lambda path: [script_finding])
    monkeypatch.setattr("forksure.security.audit.scan_dependencies", lambda path: [dependency_finding])
    monkeypatch.setattr("forksure.security.audit.scan_osv", lambda path: [osv_finding])
    monkeypatch.setattr("forksure.security.audit.scan_secrets", lambda path: [secret_finding])
    monkeypatch.setattr("forksure.security.audit.scan_sast", lambda path: [sast_finding])

    findings = run_security_audit(tmp_path)

    assert findings == [script_finding, dependency_finding, osv_finding, secret_finding, sast_finding]


def test_combined_audit_scoring_works(monkeypatch, tmp_path) -> None:
    script = tmp_path / "install.sh"
    script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    score = calculate_security_score(run_security_audit(tmp_path))

    assert score["score"] == 70
    assert score["risk_level"] == "HIGH"
    assert score["finding_count"] == 4
    assert score["counts_by_severity"]["high"] == 1
    assert score["counts_by_severity"]["info"] == 3


def test_cli_security_audit_invokes_without_real_gitleaks_or_semgrep(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)
    runner = CliRunner()

    result = runner.invoke(app, ["security", "audit", str(tmp_path)])

    assert result.exit_code == 0
    assert "OSV Scanner unavailable" in result.output
    assert "Gitleaks unavailable" in result.output
    assert "Semgrep unavailable" in result.output
    assert "Security score" in result.output
    assert "Risk level: INFO" in result.output


def test_audit_includes_gitleaks_unavailable_info_when_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    findings = run_security_audit(tmp_path)

    assert [finding.id for finding in findings] == [
        "osv-scanner-unavailable",
        "secrets-gitleaks-unavailable",
        "sast-semgrep-unavailable",
    ]
    assert all(finding.severity == "info" for finding in findings)


def test_combined_audit_includes_osv_unavailable_info_when_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    findings = run_security_audit(tmp_path)

    assert any(finding.id == "osv-scanner-unavailable" for finding in findings)


def test_combined_audit_includes_semgrep_unavailable_info_when_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    findings = run_security_audit(tmp_path)

    assert any(finding.id == "sast-semgrep-unavailable" for finding in findings)


def test_combined_audit_includes_dependency_findings(monkeypatch, tmp_path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = \"example\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text("version = 1\n", encoding="utf-8")
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    findings = run_security_audit(tmp_path)

    assert any(finding.id == "deps-python-uv-lockfile-found" for finding in findings)


def test_audit_command_detects_unsafe_script_findings(monkeypatch, tmp_path) -> None:
    script = tmp_path / "install.sh"
    script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)
    runner = CliRunner()

    result = runner.invoke(app, ["security", "audit", str(tmp_path)])

    assert result.exit_code == 0
    assert "unsafe-script" in result.output
    assert "HIGH" in result.output
    assert "Risk level: HIGH" in result.output


def test_combined_audit_does_not_report_pytest_temp_fixture_files(monkeypatch, tmp_path) -> None:
    for dirname in (".pytest-tmp", "tmp_pytest_run"):
        script_dir = tmp_path / dirname / "test_scan"
        script_dir.mkdir(parents=True)
        script = script_dir / "install.sh"
        script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")

    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    findings = run_security_audit(tmp_path)

    assert [finding.id for finding in findings] == [
        "osv-scanner-unavailable",
        "secrets-gitleaks-unavailable",
        "sast-semgrep-unavailable",
    ]
    assert calculate_security_score(findings)["score"] == 0


def test_security_audit_ignores_forksure_cache(monkeypatch, tmp_path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = \"example\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    root_uv_lock = tmp_path / "uv.lock"
    root_uv_lock.write_text("version = 1\n", encoding="utf-8")
    cache_root = tmp_path / ".forksure-cache" / "repos" / "cached-repo"
    cache_root.mkdir(parents=True)
    (cache_root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (cache_root / "install.sh").write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")
    monkeypatch.setattr("forksure.security.osv.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.secrets.shutil.which", lambda name: None)
    monkeypatch.setattr("forksure.security.sast.shutil.which", lambda name: None)

    findings = run_security_audit(tmp_path)

    assert any(finding.id == "deps-python-uv-lockfile-found" and finding.file_path == "uv.lock" for finding in findings)
    assert all(".forksure-cache" not in str(finding.file_path) for finding in findings)
    assert all(finding.id != "unsafe-script-curl-pipe-shell" for finding in findings)
