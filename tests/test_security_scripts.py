from forksure.security.scripts import scan_unsafe_scripts


def test_unsafe_script_scanner_detects_curl_pipe_bash(tmp_path) -> None:
    script = tmp_path / "install.sh"
    script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")

    findings = scan_unsafe_scripts(tmp_path)

    assert [finding.id for finding in findings] == ["unsafe-script-curl-pipe-shell"]
    assert findings[0].file_path == "install.sh"
    assert findings[0].line == 1


def test_unsafe_script_scanner_detects_npm_postinstall(tmp_path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text(
        '{"scripts": {"postinstall": "node scripts/install.js"}}\n',
        encoding="utf-8",
    )

    findings = scan_unsafe_scripts(tmp_path)

    assert [finding.id for finding in findings] == ["unsafe-script-npm-postinstall"]


def test_unsafe_script_scanner_ignores_harmless_files(tmp_path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")
    script = tmp_path / "build.sh"
    script.write_text("echo hello\n", encoding="utf-8")

    findings = scan_unsafe_scripts(tmp_path)

    assert findings == []


def test_unsafe_script_scanner_ignores_pytest_tmp_fixture_files(tmp_path) -> None:
    script_dir = tmp_path / ".pytest-tmp" / "test_scan"
    script_dir.mkdir(parents=True)
    script = script_dir / "install.sh"
    script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")

    findings = scan_unsafe_scripts(tmp_path)

    assert findings == []


def test_unsafe_script_scanner_ignores_tmp_pytest_run_fixture_files(tmp_path) -> None:
    script_dir = tmp_path / "tmp_pytest_run" / "test_scan"
    script_dir.mkdir(parents=True)
    script = script_dir / "install.sh"
    script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")

    findings = scan_unsafe_scripts(tmp_path)

    assert findings == []


def test_unsafe_script_scanner_ignores_node_modules(tmp_path) -> None:
    script_dir = tmp_path / "node_modules" / "example"
    script_dir.mkdir(parents=True)
    script = script_dir / "install.sh"
    script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")

    findings = scan_unsafe_scripts(tmp_path)

    assert findings == []


def test_unsafe_script_scanner_still_detects_install_sh_in_normal_directory(tmp_path) -> None:
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    script = script_dir / "install.sh"
    script.write_text("curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")

    findings = scan_unsafe_scripts(tmp_path)

    assert [finding.id for finding in findings] == ["unsafe-script-curl-pipe-shell"]
    assert findings[0].file_path == "scripts\\install.sh" or findings[0].file_path == "scripts/install.sh"
