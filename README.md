# ForkSure

[![Release](https://img.shields.io/github/v/release/Jride-Dev/ForkSure?label=release)](https://github.com/Jride-Dev/ForkSure/releases/latest)
[![License: MIT](https://img.shields.io/github/license/Jride-Dev/ForkSure)](LICENSE)

ForkSure is a Python CLI for repository provenance review, fork audits,
imposter/name-collision checks, license drift scanning, README attribution review,
code similarity evidence, local safety signals, and neutral evidence packets.

Website: <https://jride-dev.github.io/ForkSure/>

Hosted review app: <https://forksure.jri-techyes.top/>

## What ForkSure Does

- Lists GitHub repository forks and fork metadata.
- Compares fork licenses against the source repository license.
- Checks whether fork READMEs preserve obvious upstream attribution.
- Searches for same-name and similar-name repository candidates.
- Uses rare README strings to discover additional candidate repositories.
- Compares two repositories using metadata, license, README, optional exact file similarity, and optional local security audit signals.
- Generates static HTML reports and maintainer-facing evidence packets for manual review.
- Runs local safety checks through existing wrappers for unsafe scripts, secrets, SAST, dependency hygiene, and OSV vulnerability scanning.

## What ForkSure Does Not Do

- It does not determine ownership, intent, copyright infringement, or malicious behavior.
- It does not automatically report repositories to GitHub or any third party.
- It does not run background jobs, scheduled monitoring, or persistent indexing.
- It does not require external scanners to be installed for the CLI to run.
- It does not replace manual legal, security, or maintainer review.

## Installation From Source

ForkSure currently targets Python 3.11+.

```powershell
git clone https://github.com/Jride-Dev/ForkSure.git
cd ForkSure
python -m pip install uv
uv sync
```

You can run the CLI from the source tree:

```powershell
python -m forksure.cli --help
```

## Local Web UI

Launch the repository review interface:

```powershell
uv run forksure ui
```

ForkSure opens <http://127.0.0.1:8765> in the default browser. The interface
supports two-repository comparison and close-match searches using either a
repository name or `owner/repo`. Use `--no-open` to start the server without
opening a browser, or `--port` to choose another port.

The hosted app supports GitHub metadata comparison and close-match discovery.
Clone-based similarity and subprocess security scans remain local-only and are
disabled in the hosted interface. Hosted license and README signals are marked
unknown when GitHub's public API does not return enough evidence.

Set `GITHUB_TOKEN` for higher GitHub API limits when scanning public repositories:

```powershell
$env:GITHUB_TOKEN = "ghp_..."
```

The token is optional.

## Development Setup

Recommended setup:

```powershell
python -m pip install uv
uv sync
python -m pytest -q
```

`uv.lock` is committed so dependency scanners such as Aikido can inspect the
resolved dependency graph.

## Common Commands

The recommended end-to-end workflow is:

```powershell
python -m forksure.cli review OWNER/REPO OTHER_OWNER/OTHER_REPO --similarity --security --html
```

Targeted commands remain available when only one signal or report is needed:

```powershell
python -m forksure.cli forks OWNER/REPO --audit-license --audit-readme
```

```powershell
python -m forksure.cli imposters OWNER/REPO --rare-strings --html
```

```powershell
python -m forksure.cli compare OWNER/REPO OTHER_OWNER/OTHER_REPO --similarity --security --html
```

```powershell
python -m forksure.cli evidence OWNER/REPO OTHER_OWNER/OTHER_REPO --similarity --security --html
```

```powershell
python -m forksure.cli security audit .
```

```powershell
python -m forksure.cli security audit . --json --out reports/security-audit.json
```

## Example Workflows

- Fork review: run `forks OWNER/REPO --audit-license --audit-readme` to inspect fork metadata, license drift, and README attribution.
- Candidate review: run `imposters OWNER/REPO --rare-strings --html` to collect neutral name-collision and rare-string evidence in an HTML report.
- Two-repository comparison: run `compare SOURCE_REPO CANDIDATE_REPO --similarity --security --html` to compare metadata, license, attribution, exact file similarity, and local safety signals.
- Maintainer packet: run `evidence SOURCE_REPO CANDIDATE_REPO --similarity --security --html` to create a concise evidence packet for manual review or support escalation.
- Complete review: run `review SOURCE_REPO CANDIDATE_REPO --similarity --security --html` for the recommended end-to-end workflow.

## GitHub Actions Examples

ForkSure JSON output can be used in CI to save machine-readable evidence as an
artifact. Documentation-only example workflows live in
[docs/examples/github-actions/](docs/examples/github-actions/).

These examples are not active workflows for this repository. Copy one into your
own `.github/workflows/` directory if you want to run ForkSure manually in GitHub
Actions and upload JSON, HTML, or text reports as artifacts.

## External Scanners

ForkSure can integrate with these tools when they are available on `PATH`:

- Gitleaks for secrets
- Semgrep for SAST
- OSV Scanner for dependency vulnerabilities

If these tools are not installed, ForkSure reports informational findings instead
of failing. Informational unavailable-tool findings do not increase the security
risk score.

## Evidence And Reporting Disclaimer

ForkSure produces evidence for manual review. It does not determine ownership,
intent, copyright infringement, or malicious behavior.

Do not file abuse, copyright, or malware reports based only on a ForkSure score.
Confirm copied code, copied assets, malware, deceptive impersonation, or policy
violations through manual review before escalating.

## Current Status

ForkSure v0.2.0 makes `review` the primary end-to-end workflow for repository
metadata, provenance, attribution, optional exact-file similarity, optional
local security signals, and neutral HTML or JSON evidence output.

The project is intentionally small: no database, web UI framework, background
jobs, or scheduled monitoring.

## Website

The static project website lives in [site/](site/). GitHub Pages deploys it with
the workflow in [.github/workflows/pages.yml](.github/workflows/pages.yml). A
custom domain can be configured later in the repository Pages settings.

## License

ForkSure is licensed under the MIT License. See [LICENSE](LICENSE).
