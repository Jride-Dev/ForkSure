from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .fork_auditor import audit_forks
from .github_client import GitHubAPIError, GitHubNotFoundError, GitHubRateLimitError, InvalidOwnerRepoError
from .reports import render_forks
from .security.audit import run_security_audit
from .security.dependencies import scan_dependencies
from .security.findings import SecurityFinding
from .security.sast import scan_sast
from .security.scoring import calculate_security_score
from .security.secrets import scan_secrets
from .security.scripts import scan_unsafe_scripts


app = typer.Typer(
    name="codebloodhound",
    help="Scan GitHub repository provenance, forks, imposters, license drift, and security risks.",
    no_args_is_help=True,
)
security_app = typer.Typer(help="Run local security scans.", no_args_is_help=True)
app.add_typer(security_app, name="security")
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


@security_app.command("scripts")
def security_scripts(
    path: Path = typer.Argument(
        ...,
        help="Local file or directory to scan.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
) -> None:
    """Scan local scripts and config files for risky execution patterns."""
    findings = scan_unsafe_scripts(path)
    _render_security_findings("Unsafe Script Findings", findings)


@security_app.command("secrets")
def security_secrets(
    path: Path = typer.Argument(
        ...,
        help="Local file or directory to scan.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
) -> None:
    """Scan local files for secrets using Gitleaks when available."""
    findings = scan_secrets(path)
    _render_security_findings("Secret Findings", findings)


@security_app.command("sast")
def security_sast(
    path: Path = typer.Argument(
        ...,
        help="Local file or directory to scan.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    rules: str | None = typer.Option(
        None,
        "--rules",
        help="Comma-separated Semgrep rules to run. Built-in aliases: sql,xss,csrf.",
    ),
) -> None:
    """Scan local files for SAST findings using Semgrep when available."""
    findings = scan_sast(path, rules=_parse_rule_option(rules))
    _render_security_findings("SAST Findings", findings)


@security_app.command("deps")
def security_deps(
    path: Path = typer.Argument(
        ...,
        help="Local file or directory to scan.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
) -> None:
    """Scan dependency manifests, lockfiles, and update automation config."""
    findings = scan_dependencies(path)
    _render_security_findings("Dependency Hygiene Findings", findings)


@security_app.command("audit")
def security_audit(
    path: Path = typer.Argument(
        ...,
        help="Local file or directory to scan.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
) -> None:
    """Run all local security scanners."""
    findings = run_security_audit(path)
    _render_security_findings("Security Audit Findings", findings)


def _parse_rule_option(value: str | None) -> list[str] | None:
    if value is None:
        return None
    rules = [rule.strip() for rule in value.split(",") if rule.strip()]
    return rules or None


def _render_security_findings(title: str, findings: list[SecurityFinding]) -> None:
    table = Table(title=title, show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("File", overflow="fold")
    table.add_column("Line", justify="right")
    table.add_column("Title")

    for finding in findings:
        table.add_row(
            finding.severity.upper(),
            finding.category,
            finding.file_path or "-",
            str(finding.line or "-"),
            finding.title,
        )

    console.print(table)
    score = calculate_security_score(findings)
    console.print(
        f"Security score: [bold]{score['score']}[/bold]/100 "
        f"Risk level: [bold]{score['risk_level']}[/bold] "
        f"Findings: {score['finding_count']}"
    )


if __name__ == "__main__":
    app()
