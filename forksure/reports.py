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
    cards = "\n".join(_imposter_candidate_card(candidate) for candidate in candidates)
    candidate_content = (
        "      <section class=\"candidates\" aria-label=\"Imposter candidates\">\n"
        + cards
        + "      </section>\n"
        if candidates
        else "      <p class=\"empty\">No imposter candidates found.</p>\n"
    )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ForkSure Imposter Scan</title>
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
        max-width: 1100px;
        padding: 28px;
      }}
      h1 {{
        font-size: 28px;
        margin: 0 0 8px;
      }}
      h2, h3 {{
        margin: 0;
      }}
      h3 {{
        font-size: 15px;
        margin-bottom: 8px;
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
      code {{
        background: #eef2f7;
        border-radius: 4px;
        padding: 2px 4px;
      }}
      a {{
        color: #075985;
        overflow-wrap: anywhere;
      }}
      .candidates {{
        display: grid;
        gap: 18px;
        margin-top: 22px;
      }}
      .candidate-card {{
        border: 1px solid #d8dee8;
        border-radius: 8px;
        padding: 18px;
      }}
      .candidate-header {{
        align-items: flex-start;
        display: flex;
        gap: 12px;
        justify-content: space-between;
      }}
      .repo-link {{
        font-size: 20px;
        font-weight: 700;
        overflow-wrap: anywhere;
      }}
      .badges {{
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        justify-content: flex-end;
      }}
      .badge {{
        background: #eef2f7;
        border: 1px solid #d8dee8;
        border-radius: 999px;
        color: #334155;
        font-size: 12px;
        font-weight: 700;
        padding: 3px 8px;
        white-space: nowrap;
      }}
      .risk-high {{
        background: #fee2e2;
        border-color: #fecaca;
        color: #991b1b;
      }}
      .risk-medium {{
        background: #ffedd5;
        border-color: #fed7aa;
        color: #9a3412;
      }}
      .risk-low, .risk-info {{
        background: #dcfce7;
        border-color: #bbf7d0;
        color: #166534;
      }}
      .metadata-grid {{
        display: grid;
        gap: 10px;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        margin-top: 14px;
      }}
      .metadata-item {{
        background: #f8fafc;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        padding: 8px 10px;
      }}
      .metadata-label {{
        color: #64748b;
        display: block;
        font-size: 12px;
        text-transform: uppercase;
      }}
      .metadata-value {{
        display: block;
        font-weight: 700;
        overflow-wrap: anywhere;
      }}
      .section {{
        margin-top: 16px;
      }}
      .description {{
        overflow-wrap: anywhere;
      }}
      .reason-list, .rare-list {{
        margin: 0;
        padding-left: 20px;
      }}
      .reason-list li, .rare-list li {{
        margin: 6px 0;
      }}
      .readme-block {{
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        background: #f8fafc;
        padding: 10px;
      }}
      .readme-block summary {{
        cursor: pointer;
        font-weight: 700;
      }}
      .readme-block pre {{
        font-family: Consolas, "Courier New", monospace;
        font-size: 13px;
        max-width: 100%;
        margin: 10px 0 0;
        overflow-wrap: anywhere;
        white-space: pre-wrap;
      }}
      .readme-note {{
        color: #475569;
        margin: 10px 0 0;
      }}
      .readme-link {{
        display: inline-block;
        margin-top: 8px;
      }}
      .matched-string {{
        background: #f8fafc;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        overflow-wrap: anywhere;
        padding: 10px;
        white-space: pre-wrap;
      }}
      .matched-string {{
        display: block;
        margin: 6px 0;
      }}
      .evidence-file, .evidence-note {{
        display: block;
        overflow-wrap: anywhere;
      }}
      .evidence-note {{
        color: #475569;
        margin-top: 4px;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>ForkSure Imposter Scan</h1>
      <p class="meta"><strong>Target repo:</strong> <code>{escape(owner_repo)}</code></p>
      <p class="meta"><strong>Scan timestamp:</strong> {escape(timestamp)}</p>
      <p class="disclaimer">{escape(IMPOSTER_DISCLAIMER)}</p>
      <p class="summary"><strong>Summary count:</strong> {len(candidates)}</p>
{candidate_content}    </main>
  </body>
</html>
"""


def _imposter_candidate_card(candidate: dict) -> str:
    full_name = str(candidate.get("full_name") or "-")
    url = str(candidate.get("html_url") or "")
    link = (
        f'<a class="repo-link" href="{escape(url, quote=True)}">{escape(full_name)}</a>'
        if url
        else f'<span class="repo-link">{escape(full_name)}</span>'
    )
    risk = str(candidate.get("risk_level") or "INFO")
    risk_class = "".join(character for character in risk.casefold() if character.isalnum() or character == "-")
    classification = str(candidate.get("classification") or "unknown")
    description = str(candidate.get("description") or "").strip()
    description_html = f"""
        <section class="section">
          <h3>Description</h3>
          <p class="description">{escape(description)}</p>
        </section>""" if description else ""
    readme_html = _readme_section(candidate)
    rare_html = _rare_string_section(candidate)
    reasons_html = _reason_list(candidate.get("reasons"))
    return f"""        <article class="candidate-card">
          <header class="candidate-header">
            {link}
            <div class="badges">
              <span class="badge risk-{escape(risk_class or "info")}">Risk: {escape(risk)}</span>
              <span class="badge">Classification: {escape(classification)}</span>
              <span class="badge">Score: {escape(str(candidate.get("score") or 0))}</span>
              <span class="badge">Fork: {"yes" if candidate.get("fork") else "no"}</span>
              <span class="badge">Stars: {escape(str(candidate.get("stargazers_count") or 0))}</span>
            </div>
          </header>
          <section class="metadata-grid" aria-label="Candidate metadata">
            {_metadata_item("Created", _format_candidate_date(candidate.get("created_at")))}
            {_metadata_item("Last pushed", _format_candidate_date(candidate.get("pushed_at")))}
            {_metadata_item("Default branch", str(candidate.get("default_branch") or "-"))}
            {_metadata_item("License", _format_candidate_license(candidate))}
            {_metadata_item("README", str(candidate.get("readme_status") or "unknown"))}
          </section>
{description_html}
          <section class="section">
            <h3>Reasons</h3>
            {reasons_html}
          </section>
{readme_html}
{rare_html}
        </article>"""


def _metadata_item(label: str, value: str) -> str:
    return f"""            <div class="metadata-item">
              <span class="metadata-label">{escape(label)}</span>
              <span class="metadata-value">{escape(value)}</span>
            </div>"""


def _reason_list(reasons: object) -> str:
    if not isinstance(reasons, list) or not reasons:
        return "<p>-</p>"
    items = "".join(f"<li>{escape(str(reason))}</li>" for reason in reasons)
    return f'<ul class="reason-list">{items}</ul>'


def _readme_section(candidate: dict) -> str:
    excerpt = candidate.get("readme_text_excerpt")
    readme_url = str(candidate.get("readme_html_url") or candidate.get("html_url") or "")
    readme_link = (
        f'<a class="readme-link" href="{escape(readme_url, quote=True)}">Open README or repository</a>'
        if readme_url
        else ""
    )
    if not excerpt:
        return f"""          <section class="section">
            <details class="readme-block" open>
              <summary>README excerpt</summary>
              <p class="readme-note">README unavailable or not fetched.</p>
              {readme_link}
            </details>
          </section>"""
    notice = (
        '<p class="readme-note">README excerpt truncated for report readability.</p>'
        if candidate.get("readme_excerpt_truncated")
        else ""
    )
    return f"""          <section class="section">
            <details class="readme-block" open>
              <summary>README excerpt</summary>
              <pre>{escape(str(excerpt))}</pre>
              {notice}
              {readme_link}
            </details>
          </section>"""


def _rare_string_section(candidate: dict) -> str:
    matches = candidate.get("rare_string_matches")
    if not isinstance(matches, list) or not matches:
        return ""

    items: list[str] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        matched_string = escape(str(match.get("matched_string") or ""))
        file_path = escape(str(match.get("file_path") or ""))
        file_url = str(match.get("file_html_url") or "")
        reason = str(match.get("reason") or "").strip()
        file_label = f'<a href="{escape(file_url, quote=True)}">{file_path}</a>' if file_url else file_path
        reason_html = f'<span class="evidence-note">Reason: {escape(reason)}</span>' if reason else ""
        items.append(
            f"""              <li>
                <span class="matched-string">{matched_string}</span>
                <span class="evidence-file">{file_label}</span>
                {reason_html}
              </li>"""
        )
    if not items:
        return ""
    return f"""          <section class="section">
            <h3>Rare String Evidence</h3>
            <ul class="rare-list">
{"".join(items)}
            </ul>
          </section>"""


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
