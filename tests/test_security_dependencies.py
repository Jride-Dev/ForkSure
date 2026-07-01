from pathlib import Path

from codebloodhound.security.dependencies import PYTHON_LOCKFILES, scan_dependencies


def test_pyproject_without_uv_lock_produces_missing_lockfile_finding(tmp_path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = \"example\"\nversion = \"0.1.0\"\n", encoding="utf-8")

    findings = scan_dependencies(tmp_path)

    assert [finding.id for finding in findings] == ["deps-python-missing-lockfile"]
    assert findings[0].severity == "medium"
    assert findings[0].file_path == "pyproject.toml"


def test_pyproject_with_uv_lock_produces_lockfile_found_finding(tmp_path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = \"example\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text("version = 1\n", encoding="utf-8")

    findings = scan_dependencies(tmp_path)

    assert [finding.id for finding in findings] == ["deps-python-uv-lockfile-found"]
    assert findings[0].severity == "info"
    assert findings[0].file_path == "uv.lock"


def test_uv_lock_is_recognized_as_python_lockfile() -> None:
    assert "uv.lock" in PYTHON_LOCKFILES


def test_requirements_txt_counts_as_python_dependency_input(tmp_path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = \"example\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("typer>=0.12\n", encoding="utf-8")

    findings = scan_dependencies(tmp_path)

    assert [finding.id for finding in findings] == ["deps-python-lockfile-found"]
    assert findings[0].file_path == "requirements.txt"


def test_dependency_scan_for_codebloodhound_does_not_report_missing_python_lockfile() -> None:
    project_root = Path(__file__).resolve().parents[1]

    findings = scan_dependencies(project_root)

    assert any(finding.id == "deps-python-uv-lockfile-found" for finding in findings)
    assert all(finding.id != "deps-python-missing-lockfile" for finding in findings)


def test_dependency_scan_ignores_lockfiles_inside_generated_dirs(tmp_path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = \"example\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    uv_lock = ignored / "uv.lock"
    uv_lock.write_text("version = 1\n", encoding="utf-8")

    findings = scan_dependencies(tmp_path)

    assert [finding.id for finding in findings] == ["deps-python-missing-lockfile"]
