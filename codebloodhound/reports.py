from __future__ import annotations

from datetime import datetime
from typing import Iterable

from rich.console import Console
from rich.table import Table

from .github_client import GitHubRepo


def render_forks(forks: Iterable[GitHubRepo], *, console: Console | None = None) -> None:
    output = console or Console()
    fork_list = list(forks)

    if not fork_list:
        output.print("[yellow]No forks found.[/yellow]")
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


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.date().isoformat()
