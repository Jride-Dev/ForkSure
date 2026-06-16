from __future__ import annotations

import typer
from rich.console import Console

from .fork_auditor import audit_forks
from .github_client import GitHubAPIError, GitHubNotFoundError, GitHubRateLimitError, InvalidOwnerRepoError
from .reports import render_forks


app = typer.Typer(
    name="codebloodhound",
    help="Scan GitHub repository provenance, forks, imposters, and license drift.",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main() -> None:
    """CodeBloodHound command line interface."""


@app.command()
def forks(owner_repo: str = typer.Argument(..., help="Repository in owner/repo format.")) -> None:
    """List forks for a GitHub repository."""
    try:
        fork_list = audit_forks(owner_repo)
    except InvalidOwnerRepoError as exc:
        console.print(f"[red]Invalid repository:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except GitHubNotFoundError as exc:
        console.print(f"[red]Repository not found:[/red] {owner_repo}")
        raise typer.Exit(code=1) from exc
    except GitHubRateLimitError as exc:
        console.print(f"[red]Rate limited:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except GitHubAPIError as exc:
        console.print(f"[red]GitHub error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    render_forks(fork_list, console=console)


if __name__ == "__main__":
    app()
