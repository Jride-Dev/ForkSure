from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

from rich.console import Console
from rich.table import Table

from .github_client import GitHubRepo
from .license_scanner import format_license


def render_forks(
    forks: Iterable[GitHubRepo],
    *,
    console: Console | None = None,
    source_license: Mapping[str, Any] | None = None,
    license_results: Mapping[str, Mapping[str, Any]] | None = None,
    source_readme: Mapping[str, Any] | None = None,
    readme_results: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    output = console or Console()
    fork_list = list(forks)
    audit_license = source_license is not None or license_results is not None
    audit_readme = source_readme is not None or readme_results is not None

    if audit_license:
        output.print(f"Source license: [bold]{format_license(source_license)}[/bold]")
    if audit_readme:
        output.print(f"Source README: [bold]{_format_readme(source_readme)}[/bold]")

    if not fork_list:
        output.print("[yellow]No forks found.[/yellow]")
        return

    if audit_license or audit_readme:
        _render_audit_table(
            fork_list,
            output,
            audit_license=audit_license,
            audit_readme=audit_readme,
            license_results=license_results or {},
            readme_results=readme_results or {},
        )
        return

    table = Table(title="Repository Forks", show_lines=False)
    table.add_column("Name", style="bold")
    table.add_column("Owner")
    table.add_column("Created")
    table.add_column("Pushed")
    table.add_column("Stars", justify="right")
    table.add_column("Default Branch")
    table.add_column("URL", overflow="fold")

    for fork in fork_list:
        table.add_row(
            fork.name,
            fork.owner.login,
            _format_datetime(fork.created_at),
            _format_datetime(fork.pushed_at),
            str(fork.stars),
            fork.default_branch,
            str(fork.html_url),
        )

    output.print(table)


def _render_audit_table(
    forks: Iterable[GitHubRepo],
    output: Console,
    *,
    audit_license: bool,
    audit_readme: bool,
    license_results: Mapping[str, Mapping[str, Any]],
    readme_results: Mapping[str, Mapping[str, Any]],
) -> None:
    table = Table(title="Repository Fork Audit", show_lines=False)
    table.add_column("Owner/Repo", style="bold", overflow="fold")
    table.add_column("Created")
    table.add_column("Pushed")
    table.add_column("Stars", justify="right")
    table.add_column("Default Branch")
    if audit_license:
        table.add_column("License")
        table.add_column("License Status")
        table.add_column("License Risk")
    if audit_readme:
        table.add_column("README Status")
        table.add_column("README Risk")

    for fork in forks:
        row = [
            fork.full_name,
            _format_datetime(fork.created_at),
            _format_datetime(fork.pushed_at),
            str(fork.stars),
            fork.default_branch,
        ]
        if audit_license:
            license_audit = license_results.get(fork.full_name, {})
            fork_license = _mapping_or_empty(license_audit.get("license"))
            license_comparison = _mapping_or_empty(license_audit.get("comparison"))
            row.extend(
                [
                    format_license(fork_license),
                    str(license_comparison.get("status") or "unknown"),
                    str(license_comparison.get("severity") or "low").upper(),
                ]
            )
        if audit_readme:
            readme_audit = readme_results.get(fork.full_name, {})
            readme_comparison = _mapping_or_empty(readme_audit.get("comparison"))
            row.extend(
                [
                    str(readme_comparison.get("status") or "unknown"),
                    str(readme_comparison.get("severity") or "low").upper(),
                ]
            )
        table.add_row(*row)

    output.print(table)


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.date().isoformat()


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _format_readme(readme_data: Mapping[str, Any] | None) -> str:
    if not readme_data:
        return "unknown"
    if readme_data.get("error"):
        return "unknown"
    if not readme_data.get("found"):
        return "missing"
    return str(readme_data.get("path") or readme_data.get("name") or "found")
