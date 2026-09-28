# Changelog

## Unreleased

- Add a local browser UI for repository comparison and close-name discovery.
- Add `forksure ui` with safe local defaults and optional similarity/security checks.
- Deploy the hosted review UI at <https://forksure.jri-techyes.top/>.
- Add a protected Render backend for hosted clone-based similarity and security summaries.
- Proxy hosted API requests through Cloudflare without exposing backend credentials to the browser.
- Add a complete logo, social preview, favicon, and product screenshot set.
- Adopt the tagline "Trace the source. Compare the evidence."
- Support authenticated read-only cloning of private GitHub repositories without putting tokens in clone URLs.
- Clarify when a repository is missing or inaccessible to the configured GitHub credentials.

## v0.2.0 - 2026-09-21

- Add the unified `review` command for end-to-end repository evidence collection.
- Add JSON output for compare, evidence, and local security audit workflows.
- Add documentation-only GitHub Actions examples for JSON and HTML artifacts.
- Keep generated ForkSure cache data out of local security and dependency scans.
- Update the locked AnyIO dependency beyond the versions affected by three advisories.

## v0.1.1

- Polish the public documentation and static website.
- Improve generated report handling and local scan exclusions.

## v0.1.0

- Initial public release of fork, license, README attribution, imposter, comparison,
  similarity, security-wrapper, evidence packet, and HTML reporting features.
