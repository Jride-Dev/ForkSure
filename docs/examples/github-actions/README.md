# GitHub Actions Examples

These files are documentation-only examples for running ForkSure in GitHub
Actions. They are intentionally stored under `docs/examples/github-actions/`
instead of `.github/workflows/`, so this repository does not start scanning
itself automatically.

## Examples

- `forksure-evidence.yml` builds JSON and HTML evidence packets for a manually
  supplied source repository and candidate repository.
- `forksure-security-audit.yml` runs `python -m forksure.cli security audit .`
  against the checked-out repository and saves terminal output as an artifact.

## How To Use

Copy one example into your repository:

```text
.github/workflows/forksure-evidence.yml
```

Then open the Actions tab, choose the workflow, and run it manually with
`workflow_dispatch` inputs.

These examples assume ForkSure can be installed from the checked-out repository
with:

```bash
python -m pip install uv
uv sync
```

If you copy the workflow into another project before ForkSure is published as a
package, adjust the install step to install ForkSure from the source repository
or another trusted source.

## Permissions And Token

The examples request only:

```yaml
permissions:
  contents: read
```

They use `${{ github.token }}` as `GITHUB_TOKEN` so GitHub API requests have
normal Actions authentication and higher rate limits than anonymous requests.

## Artifacts

Each workflow uploads the `reports/` directory as a workflow artifact. After a
manual run completes, open the run page and download the artifact from the
Artifacts section.

## No Auto-Reporting

These workflows do not report repositories to GitHub, open issues, create pull
requests, or fail only because ForkSure reports elevated risk. Review the JSON,
HTML, or text artifacts manually before deciding what, if anything, to do next.

## Disclaimer

ForkSure produces evidence for manual review. It does not determine ownership,
intent, copyright infringement, or malicious behavior.
