from pathlib import Path


def test_github_actions_examples_are_documentation_only() -> None:
    root = Path(__file__).resolve().parents[1]
    docs_dir = root / "docs" / "examples" / "github-actions"

    example_names = {
        "forksure-evidence.yml",
        "forksure-security-audit.yml",
    }

    for example_name in example_names:
        example_path = docs_dir / example_name
        assert example_path.is_file()

        text = example_path.read_text(encoding="utf-8")
        assert "workflow_dispatch" in text
        assert "\n  push:" not in text
        assert "\n  pull_request:" not in text

    assert (docs_dir / "README.md").is_file()

    active_workflows_dir = root / ".github" / "workflows"
    active_workflow_names = {
        path.name
        for path in active_workflows_dir.glob("*.yml")
    } | {
        path.name
        for path in active_workflows_dir.glob("*.yaml")
    }

    assert example_names.isdisjoint(active_workflow_names)
