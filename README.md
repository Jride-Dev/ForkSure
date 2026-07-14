# ForkSure

ForkSure is a Python CLI for GitHub repository provenance, fork audits,
imposter repository checks, and license drift scanning.

## MVP

```powershell
$env:GITHUB_TOKEN = "ghp_..."
forksure forks owner/repo
```

The token is optional, but authenticated requests get higher GitHub API limits.

## Development Setup

Recommended setup:

```powershell
python -m pip install uv
uv sync
python -m pytest -q
```

`uv.lock` is committed so dependency scanners such as Aikido can inspect the
resolved dependency graph.

## Website

The static project website lives in [site/](site/). GitHub Pages can deploy it
with the workflow in [.github/workflows/pages.yml](.github/workflows/pages.yml).
A custom domain can be configured later in the repository Pages settings.

## License

ForkSure is licensed under the MIT License. See [LICENSE](LICENSE).
