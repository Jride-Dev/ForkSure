from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Iterable, Mapping

from rich.console import Console
from rich.table import Table

from .github_client import GitHubRepo
from .license_scanner import format_license


IMPOSTER_DISCLAIMER = "These are similarity candidates for manual review, not accusations."


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


def write_imposter_html_report(owner_repo: str, candidates: list[dict], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    path.write_text(_imposter_report_html(owner_repo, candidates, timestamp), encoding="utf-8")
    return path


def _imposter_report_html(owner_repo: str, candidates: list[dict], timestamp: str) -> str:
    rows = "\n".join(_imposter_candidate_row(candidate) for candidate in candidates)
    candidate_content = (
        """
      <table>
        <thead>
          <tr>
            <th>Classification</th>
            <th>Risk</th>
            <th>Score</th>
            <th>Repository</th>
            <th>URL</th>
            <th>Created</th>
            <th>Pushed</th>
            <th>Fork</th>
            <th>Stars</th>
            <th>License</th>
            <th>Description</th>
            <th>README</th>
            <th>Reasons</th>
          </tr>
        </thead>
        <tbody>
"""
        + rows
        + """
        </tbody>
      </table>
"""
        if candidates
        else "      <p class=\"empty\">No imposter candidates found.</p>\n"
    )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CodeBloodHound Imposter Scan</title>
    <style>
      body {{
        background: #f7f8fa;
        color: #1f2937;
        font-family: Arial, Helvetica, sans-serif;
        line-height: 1.5;
        margin: 0;
        padding: 32px;
      }}
      main {{
        background: #ffffff;
        border: 1px solid #d8dee8;
        border-radius: 8px;
        margin: 0 auto;
        max-width: 1180px;
        padding: 28px;
      }}
      h1 {{
        font-size: 28px;
        margin: 0 0 8px;
      }}
      .meta, .disclaimer, .summary, .empty {{
        margin: 8px 0;
      }}
      .disclaimer {{
        background: #fff7df;
        border: 1px solid #ead28a;
        border-radius: 6px;
        padding: 10px 12px;
      }}
      table {{
        border-collapse: collapse;
        margin-top: 20px;
        width: 100%;
      }}
      th, td {{
        border-bottom: 1px solid #e5e7eb;
        padding: 10px 8px;
        text-align: left;
        vertical-align: top;
      }}
      th {{
        background: #eef2f7;
        font-size: 13px;
        text-transform: uppercase;
      }}
      code {{
        background: #eef2f7;
        border-radius: 4px;
        padding: 2px 4px;
      }}
      a {{
        color: #075985;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>CodeBloodHound Imposter Scan</h1>
      <p class="meta"><strong>Target repo:</strong> <code>{escape(owner_repo)}</code></p>
      <p class="meta"><strong>Scan timestamp:</strong> {escape(timestamp)}</p>
      <p class="disclaimer">{escape(IMPOSTER_DISCLAIMER)}</p>
      <p class="summary"><strong>Summary count:</strong> {len(candidates)}</p>
{candidate_content}    </main>
  </body>
</html>
"""


def _imposter_candidate_row(candidate: dict) -> str:
    reasons = candidate.get("reasons")
    reason_text = "; ".join(str(reason) for reason in reasons) if isinstance(reasons, list) else "-"
    url = str(candidate.get("html_url") or "")
    url_cell = f'<a href="{escape(url, quote=True)}">{escape(url)}</a>' if url else "-"
    readme_text = _format_candidate_readme(candidate)
    return f"""          <tr>
            <td>{escape(str(candidate.get("classification") or "unknown"))}</td>
            <td>{escape(str(candidate.get("risk_level") or "INFO"))}</td>
            <td>{escape(str(candidate.get("score") or 0))}</td>
            <td>{escape(str(candidate.get("full_name") or "-"))}</td>
            <td>{url_cell}</td>
            <td>{escape(_format_candidate_date(candidate.get("created_at")))}</td>
            <td>{escape(_format_candidate_date(candidate.get("pushed_at")))}</td>
            <td>{"yes" if candidate.get("fork") else "no"}</td>
            <td>{escape(str(candidate.get("stargazers_count") or 0))}</td>
            <td>{escape(_format_candidate_license(candidate))}</td>
            <td>{escape(str(candidate.get("description") or "-"))}</td>
            <td>{escape(readme_text)}</td>
            <td>{escape(reason_text)}</td>
          </tr>"""


def _format_candidate_date(value: object) -> str:
    if value is None:
        return "-"
    text = str(value)
    return text.split("T", 1)[0] if text else "-"


def _format_candidate_license(candidate: dict) -> str:
    key = candidate.get("license_key")
    name = candidate.get("license_name")
    if key and name:
        return f"{key} ({name})"
    if key:
        return str(key)
    if name:
        return str(name)
    return "-"


def _format_candidate_readme(candidate: dict) -> str:
    status = str(candidate.get("readme_status") or "unknown")
    excerpt = candidate.get("readme_text_excerpt")
    if excerpt:
        return f"{status}: {excerpt}"
    return status
