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
) -> None:
    output = console or Console()
    fork_list = list(forks)
    audit_license = source_license is not None or license_results is not None

    if audit_license:
        output.print(f"Source license: [bold]{format_license(source_license)}[/bold]")

    if not fork_list:
        output.print("[yellow]No forks found.[/yellow]")
        return

    if audit_license:
        _render_license_audit_table(fork_list, license_results or {}, output)
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


def _render_license_audit_table(
    forks: Iterable[GitHubRepo],
    license_results: Mapping[str, Mapping[str, Any]],
    output: Console,
) -> None:
    table = Table(title="Repository Fork License Audit", show_lines=False)
    table.add_column("Owner/Repo", style="bold", overflow="fold")
    table.add_column("Created")
    table.add_column("Pushed")
    table.add_column("Stars", justify="right")
    table.add_column("Default Branch")
    table.add_column("License")
    table.add_column("License Status")
    table.add_column("Risk")

    for fork in forks:
        audit = license_results.get(fork.full_name, {})
        fork_license = _mapping_or_empty(audit.get("license"))
        comparison = _mapping_or_empty(audit.get("comparison"))
        table.add_row(
            fork.full_name,
            _format_datetime(fork.created_at),
            _format_datetime(fork.pushed_at),
            str(fork.stars),
            fork.default_branch,
            format_license(fork_license),
            str(comparison.get("status") or "unknown"),
            str(comparison.get("severity") or "low").upper(),
        )

    output.print(table)


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.date().isoformat()


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}
