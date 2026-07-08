from __future__ import annotations

import webbrowser
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from .compare_scanner import compare_repositories
from .fork_auditor import audit_forks
from .github_client import GitHubAPIError, GitHubClient, GitHubNotFoundError, GitHubRateLimitError, InvalidOwnerRepoError
from .imposter_scanner import scan_imposters
from .license_scanner import compare_licenses
from .rare_string_scanner import merge_rare_string_matches, scan_rare_string_matches
from .readme_scanner import compare_readme_attribution
from .reports import COMPARE_DISCLAIMER, IMPOSTER_DISCLAIMER, render_forks, write_compare_html_report, write_imposter_html_report
from .security.audit import run_security_audit
from .security.dependencies import scan_dependencies
from .security.findings import SecurityFinding
from .security.osv import scan_osv
from .security.sast import scan_sast
from .security.scoring import calculate_security_score
from .security.secrets import scan_secrets
from .security.scripts import scan_unsafe_scripts
from .similarity_scanner import SimilarityScanError, scan_repository_similarity


app = typer.Typer(
    name="forksure",
    help="Scan GitHub repository provenance, forks, imposters, license drift, and security risks.",
    no_args_is_help=True,
)
security_app = typer.Typer(help="Run local security scans.", no_args_is_help=True)
app.add_typer(security_app, name="security")
console = Console(width=140)


@app.callback()
def main() -> None:
    """ForkSure command line interface."""


@app.command()
def forks(
    owner_repo: str = typer.Argument(..., help="Repository in owner/repo format."),
    audit_license: bool = typer.Option(
        False,
        "--audit-license",
        help="Compare the source repository license against each fork license.",
    ),
    audit_readme: bool = typer.Option(
        False,
        "--audit-readme",
        help="Check whether fork READMEs preserve obvious upstream attribution.",
    ),
) -> None:
    """List forks for a GitHub repository."""
    try:
        if audit_license or audit_readme:
            client = GitHubClient()
            fork_list = audit_forks(owner_repo, client=client)
            source_license = client.get_repo_license(owner_repo) if audit_license else None
            source_readme = client.get_repo_readme(owner_repo) if audit_readme else None
            license_results = {} if audit_license else None
            readme_results = {} if audit_readme else None
            for fork in fork_list:
                if audit_license and source_license is not None and license_results is not None:
                    fork_license = client.get_repo_license(fork.full_name)
                    license_results[fork.full_name] = {
                        "license": fork_license,
                        "comparison": compare_licenses(source_license, fork_license),
                    }
                if audit_readme and source_readme is not None and readme_results is not None:
                    fork_readme = client.get_repo_readme(fork.full_name)
                    readme_results[fork.full_name] = {
                        "readme": fork_readme,
                        "comparison": compare_readme_attribution(owner_repo, source_readme, fork_readme),
                    }
        else:
            fork_list = audit_forks(owner_repo)
            source_license = None
            license_results = None
            source_readme = None
            readme_results = None
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

    render_forks(
        fork_list,
        console=console,
        source_license=source_license,
        license_results=license_results,
        source_readme=source_readme,
        readme_results=readme_results,
    )


@app.command()
def compare(
    source_repo: str = typer.Argument(..., help="Source repository in owner/repo format."),
    candidate_repo: str = typer.Argument(..., help="Candidate repository in owner/repo format."),
    html: bool = typer.Option(False, "--html", help="Generate an HTML comparison report in the reports/ directory."),
    open_report: bool = typer.Option(False, "--open", help="Open the generated HTML report in the default browser."),
    out: Path | None = typer.Option(None, "--out", help="Custom HTML output path."),
    clone: bool = typer.Option(False, "--clone", help="Clone repositories before comparison."),
    similarity: bool = typer.Option(False, "--similarity", help="Compare cloned file paths and exact file hashes."),
) -> None:
    """Compare two GitHub repositories using metadata, license, and README signals."""
    try:
        result = compare_repositories(source_repo, candidate_repo, GitHubClient())
        if clone or similarity:
            result["similarity"] = scan_repository_similarity(source_repo, candidate_repo)
    except InvalidOwnerRepoError as exc:
        console.print(f"[red]Invalid repository:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except SimilarityScanError as exc:
        console.print(f"[red]Similarity scan failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except GitHubNotFoundError as exc:
        console.print(f"[red]Repository not found:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except GitHubRateLimitError as exc:
        console.print(f"[red]Rate limited:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except GitHubAPIError as exc:
        console.print(f"[red]GitHub error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _render_compare_result(result)
    if html or open_report or out is not None:
        report_path = write_compare_html_report(result, out or _default_compare_report_path(source_repo, candidate_repo))
        console.print(f"HTML report written to: {report_path}")
        if open_report:
            _open_html_report(report_path)


@app.command()
def imposters(
    owner_repo: str = typer.Argument(..., help="Repository in owner/repo format."),
    html: bool = typer.Option(False, "--html", help="Generate an HTML report in the reports/ directory."),
    open_report: bool = typer.Option(False, "--open", help="Open the generated HTML report in the default browser."),
    out: Path | None = typer.Option(None, "--out", help="Custom HTML output path."),
    rare_strings: bool = typer.Option(False, "--rare-strings", help="Search GitHub code for rare source README phrases."),
    max_rare_strings: int = typer.Option(5, "--max-rare-strings", min=1, help="Maximum rare strings to search."),
) -> None:
    """Search GitHub for possible name-squatting repository candidates."""
    try:
        client = GitHubClient()
        candidates = scan_imposters(owner_repo, client)
        if rare_strings:
            rare_matches = scan_rare_string_matches(owner_repo, client, max_strings=max_rare_strings)
            candidates = merge_rare_string_matches(candidates, rare_matches)
    except InvalidOwnerRepoError as exc:
        console.print(f"[red]Invalid repository:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except GitHubRateLimitError as exc:
        console.print(f"[red]Rate limited:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except GitHubAPIError as exc:
        console.print(f"[red]GitHub error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _render_imposter_candidates(candidates)
    if html or open_report or out is not None:
        report_path = write_imposter_html_report(owner_repo, candidates, out or _default_imposter_report_path(owner_repo))
        console.print(f"HTML report written to: {report_path}")
        if open_report:
            _open_html_report(report_path)


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


@security_app.command("osv")
def security_osv(
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
    """Scan dependencies for vulnerabilities using OSV Scanner when available."""
    findings = scan_osv(path)
    _render_security_findings("OSV Dependency Vulnerability Findings", findings)


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


def _render_imposter_candidates(candidates: list[dict]) -> None:
    if not candidates:
        console.print("[yellow]No imposter candidates found.[/yellow]")
        return

    console.print(f"[yellow]{IMPOSTER_DISCLAIMER}[/yellow]")
    table = Table(title="Imposter Repository Candidates", show_lines=False, box=box.SIMPLE, collapse_padding=True)
    table.add_column("Risk", style="bold", no_wrap=True, width=6)
    table.add_column("Score", justify="right", no_wrap=True, width=5)
    table.add_column("Classification", overflow="ellipsis", no_wrap=True, max_width=22)
    table.add_column("Fork", no_wrap=True, width=4)
    table.add_column("Stars", justify="right", no_wrap=True, width=5)
    table.add_column("Repository", overflow="ellipsis", no_wrap=True, max_width=28)
    table.add_column("Reason", overflow="ellipsis", no_wrap=True, max_width=36)

    for candidate in candidates:
        reasons = candidate.get("reasons")
        reason = "; ".join(str(item) for item in reasons) if isinstance(reasons, list) else "-"
        table.add_row(
            str(candidate.get("risk_level") or "INFO"),
            str(candidate.get("score") or 0),
            str(candidate.get("classification") or "unknown"),
            "yes" if candidate.get("fork") else "no",
            str(candidate.get("stargazers_count") or 0),
            str(candidate.get("full_name") or "-"),
            reason,
        )

    console.print(table)


def _render_compare_result(result: dict) -> None:
    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    candidate = result.get("candidate") if isinstance(result.get("candidate"), dict) else {}
    name_similarity = result.get("name_similarity") if isinstance(result.get("name_similarity"), dict) else {}
    license_comparison = result.get("license_comparison") if isinstance(result.get("license_comparison"), dict) else {}
    readme_comparison = result.get("readme_comparison") if isinstance(result.get("readme_comparison"), dict) else {}
    reasons = result.get("reasons")

    console.print(f"[yellow]{COMPARE_DISCLAIMER}[/yellow]")
    console.print(f"Source repo: [bold]{source.get('full_name', '-')}[/bold]")
    console.print(f"Candidate repo: [bold]{candidate.get('full_name', '-')}[/bold]")
    console.print(f"Overall risk: [bold]{result.get('overall_risk', 'INFO')}[/bold]")

    table = Table(title="Repository Compare", show_lines=False, box=box.SIMPLE)
    table.add_column("Signal", style="bold", overflow="fold")
    table.add_column("Status", overflow="fold")
    table.add_column("Details", overflow="fold")
    table.add_row(
        "Name similarity",
        f"{name_similarity.get('score', 0)} ({name_similarity.get('risk_level', 'INFO')})",
        _join_reasons(name_similarity.get("reasons")),
    )
    table.add_row(
        "License",
        f"{license_comparison.get('status', 'unknown')} ({str(license_comparison.get('severity', 'low')).upper()})",
        str(license_comparison.get("summary") or "-"),
    )
    table.add_row(
        "README attribution",
        f"{readme_comparison.get('status', 'unknown')} ({str(readme_comparison.get('severity', 'low')).upper()})",
        str(readme_comparison.get("summary") or "-"),
    )
    table.add_row(
        "Metadata",
        "candidate fork: yes" if candidate.get("fork") else "candidate fork: no",
        (
            f"Source stars: {source.get('stargazers_count', 0)}; "
            f"candidate stars: {candidate.get('stargazers_count', 0)}; "
            f"candidate branch: {candidate.get('default_branch', '-')}"
        ),
    )
    console.print(table)
    similarity = result.get("similarity")
    if isinstance(similarity, dict):
        _render_similarity_result(similarity)

    if isinstance(reasons, list) and reasons:
        console.print("Reasons:")
        for reason in reasons:
            console.print(f"- {reason}")


def _join_reasons(value: object) -> str:
    if not isinstance(value, list) or not value:
        return "-"
    return "; ".join(str(item) for item in value)


def _render_similarity_result(similarity: dict) -> None:
    table = Table(title="Similarity Evidence", show_lines=False, box=box.SIMPLE)
    table.add_column("Metric", style="bold", overflow="fold")
    table.add_column("Value", overflow="fold")
    table.add_row("Overall similarity score", f"{similarity.get('overall_similarity_score', 0)}")
    table.add_row("Exact hash matches", str(similarity.get("exact_hash_match_count", 0)))
    table.add_row("Shared paths", str(similarity.get("shared_path_count", 0)))
    table.add_row("Source file count", str(similarity.get("source_file_count", 0)))
    table.add_row("Candidate file count", str(similarity.get("candidate_file_count", 0)))
    console.print(table)

    top_matches = similarity.get("top_matches")
    if isinstance(top_matches, list) and top_matches:
        match_table = Table(title="Top Matching Files", show_lines=False, box=box.SIMPLE)
        match_table.add_column("Source path", overflow="fold")
        match_table.add_column("Candidate path", overflow="fold")
        match_table.add_column("Type", overflow="fold")
        for match in top_matches[:10]:
            if not isinstance(match, dict):
                continue
            match_table.add_row(
                str(match.get("source_path") or "-"),
                str(match.get("candidate_path") or "-"),
                str(match.get("match_type") or "-"),
            )
        console.print(match_table)


def _render_security_findings(title: str, findings: list[SecurityFinding]) -> None:
    table = Table(title=title, show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Category", overflow="fold")
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


def _default_imposter_report_path(owner_repo: str) -> Path:
    safe_name = "".join(char.lower() if char.isalnum() else "-" for char in owner_repo).strip("-")
    while "--" in safe_name:
        safe_name = safe_name.replace("--", "-")
    return Path("reports") / f"{safe_name or 'imposter-scan'}-imposters.html"


def _default_compare_report_path(source_repo: str, candidate_repo: str) -> Path:
    source_name = _safe_report_name(source_repo)
    candidate_name = _safe_report_name(candidate_repo)
    return Path("reports") / f"compare-{source_name}-vs-{candidate_name}.html"


def _safe_report_name(value: str) -> str:
    safe_name = "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")
    while "--" in safe_name:
        safe_name = safe_name.replace("--", "-")
    return safe_name or "repository"


def _open_html_report(report_path: Path) -> None:
    try:
        opened = webbrowser.open(report_path.resolve().as_uri())
    except Exception:
        opened = False
    if not opened:
        console.print("[yellow]Could not open HTML report automatically.[/yellow]")


if __name__ == "__main__":
    app()
