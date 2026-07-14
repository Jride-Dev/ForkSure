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
COMPARE_DISCLAIMER = "This metadata comparison is for manual review, not an accusation."


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


def write_compare_html_report(comparison: Mapping[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    path.write_text(_compare_report_html(comparison, timestamp), encoding="utf-8")
    return path


def write_evidence_html_report(packet: Mapping[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_evidence_report_html(packet), encoding="utf-8")
    return path


def _evidence_report_html(packet: Mapping[str, Any]) -> str:
    source_repo = str(packet.get("source_repo") or "-")
    candidate_repo = str(packet.get("candidate_repo") or "-")
    source_url = str(packet.get("source_url") or "")
    candidate_url = str(packet.get("candidate_url") or "")
    overall_risk = str(packet.get("overall_risk") or "INFO")
    generated_at = str(packet.get("generated_at") or "")
    risk_breakdown = _mapping_or_empty(packet.get("risk_breakdown"))

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ForkSure Evidence Packet</title>
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
        max-width: 1050px;
        padding: 28px;
      }}
      h1 {{
        font-size: 28px;
        margin: 0 0 8px;
      }}
      h2 {{
        font-size: 20px;
        margin: 0 0 10px;
      }}
      a {{
        color: #075985;
        overflow-wrap: anywhere;
      }}
      .meta, .summary, .disclaimer {{
        margin: 8px 0;
      }}
      .disclaimer {{
        background: #fff7df;
        border: 1px solid #ead28a;
        border-radius: 6px;
        padding: 10px 12px;
      }}
      .section {{
        margin-top: 22px;
      }}
      .repo-grid {{
        display: grid;
        gap: 16px;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        margin-top: 20px;
      }}
      .card {{
        border: 1px solid #d8dee8;
        border-radius: 8px;
        padding: 16px;
      }}
      .risk {{
        border-radius: 999px;
        display: inline-block;
        font-size: 12px;
        font-weight: 700;
        margin-left: 8px;
        padding: 3px 8px;
      }}
      .risk-critical {{
        background: #7f1d1d;
        color: #ffffff;
      }}
      .risk-high {{
        background: #fee2e2;
        color: #991b1b;
      }}
      .risk-medium {{
        background: #ffedd5;
        color: #9a3412;
      }}
      .risk-low {{
        background: #dcfce7;
        color: #166534;
      }}
      .risk-info {{
        background: #e0f2fe;
        color: #075985;
      }}
      .risk-notscanned {{
        background: #f1f5f9;
        color: #475569;
      }}
      ul {{
        margin: 8px 0 0;
        padding-left: 20px;
      }}
      li {{
        margin: 6px 0;
      }}
      table {{
        border-collapse: collapse;
        margin-top: 10px;
        width: 100%;
      }}
      th, td {{
        border-bottom: 1px solid #e5e7eb;
        padding: 8px;
        text-align: left;
        vertical-align: top;
        overflow-wrap: anywhere;
      }}
      th {{
        background: #eef2f7;
        color: #334155;
        font-size: 13px;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>ForkSure Evidence Packet</h1>
      <p class="meta"><strong>Timestamp:</strong> {escape(generated_at)}</p>
      <p class="summary">{escape(str(packet.get("summary") or "-"))}</p>
      <section class="repo-grid" aria-label="Repository links">
        <article class="card">
          <h2>Source repo</h2>
          <p>{_html_link(source_repo, source_url)}</p>
        </article>
        <article class="card">
          <h2>Candidate repo</h2>
          <p>{_html_link(candidate_repo, candidate_url)}</p>
        </article>
      </section>
      <section class="section">
        <h2>Overall Risk <span class="risk risk-{escape(_risk_class(overall_risk))}">{escape(overall_risk)}</span></h2>
      </section>
{_risk_breakdown_section(risk_breakdown)}
      <section class="section">
        <h2>Evidence Found</h2>
        {_html_list(packet.get("evidence_found"))}
      </section>
      <section class="section">
        <h2>Evidence Not Found</h2>
        {_html_list(packet.get("evidence_not_found"))}
      </section>
      <section class="section">
        <h2>Manual Review Recommendations</h2>
        {_html_list(packet.get("manual_review_recommendations"))}
      </section>
      <section class="section">
        <h2>Disclaimer</h2>
        <p class="disclaimer">{escape(str(packet.get("disclaimer") or ""))}</p>
      </section>
    </main>
  </body>
</html>
"""


def _html_link(label: str, url: str) -> str:
    if not url:
        return escape(label)
    return f'<a href="{escape(url, quote=True)}">{escape(label)}</a>'


def _compare_report_html(comparison: Mapping[str, Any], timestamp: str) -> str:
    source = _mapping_or_empty(comparison.get("source"))
    candidate = _mapping_or_empty(comparison.get("candidate"))
    name_similarity = _mapping_or_empty(comparison.get("name_similarity"))
    license_comparison = _mapping_or_empty(comparison.get("license_comparison"))
    readme_comparison = _mapping_or_empty(comparison.get("readme_comparison"))
    similarity = comparison.get("similarity")
    source_security = comparison.get("source_security")
    candidate_security = comparison.get("candidate_security")
    risk_breakdown = _mapping_or_empty(comparison.get("risk_breakdown"))
    overall_risk = str(comparison.get("overall_risk") or "INFO")
    reasons = comparison.get("reasons")

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ForkSure Repository Compare</title>
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
      h2 {{
        font-size: 20px;
      }}
      h3 {{
        font-size: 16px;
        margin-bottom: 8px;
      }}
      a {{
        color: #075985;
        overflow-wrap: anywhere;
      }}
      .meta, .disclaimer {{
        margin: 8px 0;
      }}
      .disclaimer {{
        background: #fff7df;
        border: 1px solid #ead28a;
        border-radius: 6px;
        padding: 10px 12px;
      }}
      .repo-grid, .summary-grid {{
        display: grid;
        gap: 16px;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        margin-top: 20px;
      }}
      .card {{
        border: 1px solid #d8dee8;
        border-radius: 8px;
        padding: 16px;
      }}
      .risk {{
        border-radius: 999px;
        display: inline-block;
        font-size: 12px;
        font-weight: 700;
        margin-left: 8px;
        padding: 3px 8px;
      }}
      .risk-high {{
        background: #fee2e2;
        color: #991b1b;
      }}
      .risk-critical {{
        background: #7f1d1d;
        color: #ffffff;
      }}
      .risk-medium {{
        background: #ffedd5;
        color: #9a3412;
      }}
      .risk-low {{
        background: #dcfce7;
        color: #166534;
      }}
      .risk-info {{
        background: #e0f2fe;
        color: #075985;
      }}
      .risk-notscanned {{
        background: #f1f5f9;
        color: #475569;
      }}
      dl {{
        display: grid;
        gap: 8px 14px;
        grid-template-columns: max-content 1fr;
        margin: 12px 0 0;
      }}
      dt {{
        color: #64748b;
        font-weight: 700;
      }}
      dd {{
        margin: 0;
        overflow-wrap: anywhere;
      }}
      ul {{
        margin: 8px 0 0;
        padding-left: 20px;
      }}
      li {{
        margin: 6px 0;
      }}
      .section {{
        margin-top: 22px;
      }}
      table {{
        border-collapse: collapse;
        margin-top: 10px;
        width: 100%;
      }}
      th, td {{
        border-bottom: 1px solid #e5e7eb;
        padding: 8px;
        text-align: left;
        vertical-align: top;
        overflow-wrap: anywhere;
      }}
      th {{
        background: #eef2f7;
        color: #334155;
        font-size: 13px;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>ForkSure Repository Compare</h1>
      <p class="meta"><strong>Scan timestamp:</strong> {escape(timestamp)}</p>
      <p class="disclaimer">{escape(COMPARE_DISCLAIMER)}</p>
      <section class="section">
        <h2>Overall Risk <span class="risk risk-{escape(_risk_class(overall_risk))}">{escape(overall_risk)}</span></h2>
        {_html_list(reasons)}
      </section>
{_risk_breakdown_section(risk_breakdown)}
      <section class="repo-grid" aria-label="Repository metadata">
{_compare_repo_card("Source repo", source)}
{_compare_repo_card("Candidate repo", candidate)}
      </section>
      <section class="summary-grid" aria-label="Comparison summary">
{_compare_status_card("Name similarity", [
        ("Score", str(name_similarity.get("score") or 0)),
        ("Risk", str(name_similarity.get("risk_level") or "INFO")),
        ("Reasons", "; ".join(str(reason) for reason in name_similarity.get("reasons", []) if reason) or "-"),
    ])}
{_compare_status_card("License comparison", [
        ("Status", str(license_comparison.get("status") or "unknown")),
        ("Risk", str(license_comparison.get("severity") or "low").upper()),
        ("Summary", str(license_comparison.get("summary") or "-")),
    ])}
{_compare_status_card("README attribution comparison", [
        ("Status", str(readme_comparison.get("status") or "unknown")),
        ("Risk", str(readme_comparison.get("severity") or "low").upper()),
        ("Summary", str(readme_comparison.get("summary") or "-")),
    ])}
      </section>
{_similarity_section(similarity)}
{_security_section(source_security, candidate_security)}
    </main>
  </body>
</html>
"""


def _compare_repo_card(title: str, repo: Mapping[str, Any]) -> str:
    full_name = str(repo.get("full_name") or "-")
    url = str(repo.get("html_url") or "")
    link = (
        f'<a href="{escape(url, quote=True)}">{escape(full_name)}</a>'
        if url
        else escape(full_name)
    )
    return f"""        <article class="card">
          <h3>{escape(title)}</h3>
          <dl>
            <dt>Repository</dt><dd>{link}</dd>
            <dt>Description</dt><dd>{escape(str(repo.get("description") or "-"))}</dd>
            <dt>Fork</dt><dd>{"yes" if repo.get("fork") else "no"}</dd>
            <dt>Created</dt><dd>{escape(str(repo.get("created_at") or "-"))}</dd>
            <dt>Pushed</dt><dd>{escape(str(repo.get("pushed_at") or "-"))}</dd>
            <dt>Stars</dt><dd>{escape(str(repo.get("stargazers_count") or 0))}</dd>
            <dt>Default branch</dt><dd>{escape(str(repo.get("default_branch") or "-"))}</dd>
            <dt>License</dt><dd>{escape(str(repo.get("license_label") or "unknown"))}</dd>
            <dt>README</dt><dd>{escape(str(repo.get("readme_status") or "unknown"))}</dd>
          </dl>
        </article>"""


def _compare_status_card(title: str, rows: list[tuple[str, str]]) -> str:
    entries = "\n".join(
        f"            <dt>{escape(label)}</dt><dd>{escape(value)}</dd>"
        for label, value in rows
    )
    return f"""        <article class="card">
          <h3>{escape(title)}</h3>
          <dl>
{entries}
          </dl>
        </article>"""


def _html_list(values: object) -> str:
    if not isinstance(values, list) or not values:
        return "<p>-</p>"
    items = "".join(f"<li>{escape(str(value))}</li>" for value in values)
    return f"<ul>{items}</ul>"


def _risk_breakdown_section(risk_breakdown: Mapping[str, Any]) -> str:
    labels = {
        "name": "Name / imposter",
        "readme": "README attribution",
        "license": "License",
        "similarity": "Code similarity",
        "security": "Security",
    }
    rows = []
    for key, label in labels.items():
        item = _mapping_or_empty(risk_breakdown.get(key))
        if not item:
            continue
        risk = str(item.get("risk_level") or "INFO")
        rows.append(
            f"""              <tr>
                <th scope="row">{escape(label)}</th>
                <td><span class="risk risk-{escape(_risk_class(risk))}">{escape(risk)}</span></td>
                <td>{escape(str(item.get("summary") or "-"))}</td>
              </tr>"""
        )
    if not rows:
        return ""
    return f"""      <section class="section risk-breakdown">
        <h2>Risk Breakdown</h2>
        <table>
          <thead>
            <tr><th>Signal</th><th>Risk</th><th>Summary</th></tr>
          </thead>
          <tbody>
{"".join(rows)}
          </tbody>
        </table>
      </section>"""


def _similarity_section(similarity: object) -> str:
    if not isinstance(similarity, Mapping):
        return ""
    top_matches = similarity.get("top_matches")
    rows = ""
    if isinstance(top_matches, list) and top_matches:
        rows = "\n".join(_similarity_match_row(match) for match in top_matches[:20] if isinstance(match, Mapping))
    matches_html = (
        f"""          <table>
            <thead>
              <tr><th>Source path</th><th>Candidate path</th><th>Type</th></tr>
            </thead>
            <tbody>
{rows}
            </tbody>
          </table>"""
        if rows
        else "          <p>No exact file matches found.</p>"
    )
    return f"""      <section class="section similarity-evidence">
        <h2>Similarity Evidence</h2>
        <p class="disclaimer">Clone-based similarity evidence is for manual review and is not an accusation.</p>
        <dl>
          <dt>Overall score</dt><dd>{escape(str(similarity.get("overall_similarity_score") or 0))}</dd>
          <dt>Exact file matches</dt><dd>{escape(str(similarity.get("exact_hash_match_count") or 0))}</dd>
          <dt>Shared paths</dt><dd>{escape(str(similarity.get("shared_path_count") or 0))}</dd>
          <dt>Source file count</dt><dd>{escape(str(similarity.get("source_file_count") or 0))}</dd>
          <dt>Candidate file count</dt><dd>{escape(str(similarity.get("candidate_file_count") or 0))}</dd>
        </dl>
        <h3>Top matching files</h3>
{matches_html}
      </section>"""


def _security_section(source_security: object, candidate_security: object) -> str:
    if not isinstance(source_security, Mapping) or not isinstance(candidate_security, Mapping):
        return ""

    candidate_findings = candidate_security.get("top_findings")
    source_findings = source_security.get("top_findings")
    return f"""      <section class="section security-evidence">
        <h2>Security Evidence</h2>
        <p class="disclaimer">Unavailable scanner entries are informational and do not increase risk.</p>
        <div class="summary-grid" aria-label="Security audit summaries">
{_security_summary_card("Source security", source_security)}
{_security_summary_card("Candidate security", candidate_security)}
        </div>
{_security_findings_table("Candidate top findings", candidate_findings)}
{_security_findings_table("Source top findings", source_findings)}
      </section>"""


def _security_summary_card(title: str, security: Mapping[str, Any]) -> str:
    return _compare_status_card(
        title,
        [
            ("Repository", str(security.get("repo") or "-")),
            ("Score", f"{security.get('score', 0)}/100"),
            ("Risk", str(security.get("risk_level") or "INFO")),
            ("Findings", str(security.get("finding_count") or 0)),
        ],
    )


def _security_findings_table(title: str, findings: object) -> str:
    if not isinstance(findings, list) or not findings:
        return f"""        <section class="section">
          <h3>{escape(title)}</h3>
          <p>No findings to show.</p>
        </section>"""

    rows = "\n".join(
        _security_finding_row(finding)
        for finding in findings[:10]
        if isinstance(finding, Mapping)
    )
    if not rows:
        return ""
    return f"""        <section class="section">
          <h3>{escape(title)}</h3>
          <table>
            <thead>
              <tr><th>Severity</th><th>Category</th><th>File</th><th>Line</th><th>Title</th></tr>
            </thead>
            <tbody>
{rows}
            </tbody>
          </table>
        </section>"""


def _security_finding_row(finding: Mapping[str, Any]) -> str:
    return f"""              <tr>
                <td>{escape(str(finding.get("severity") or "info").upper())}</td>
                <td>{escape(str(finding.get("category") or "-"))}</td>
                <td>{escape(str(finding.get("file_path") or "-"))}</td>
                <td>{escape(str(finding.get("line") or "-"))}</td>
                <td>{escape(str(finding.get("title") or "-"))}</td>
              </tr>"""


def _similarity_match_row(match: Mapping[str, Any]) -> str:
    return f"""              <tr>
                <td>{escape(str(match.get("source_path") or "-"))}</td>
                <td>{escape(str(match.get("candidate_path") or "-"))}</td>
                <td>{escape(str(match.get("match_type") or "-"))}</td>
              </tr>"""


def _risk_class(risk: str) -> str:
    value = "".join(character for character in risk.casefold() if character.isalnum() or character == "-")
    return value or "info"


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
        box-sizing: border-box;
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
