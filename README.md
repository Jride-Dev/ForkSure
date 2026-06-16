# CodeBloodHound

CodeBloodHound is a Python CLI for GitHub repository provenance, fork audits,
imposter repository checks, and license drift scanning.

## MVP

```powershell
$env:GITHUB_TOKEN = "ghp_..."
codebloodhound forks owner/repo
```

The token is optional, but authenticated requests get higher GitHub API limits.
