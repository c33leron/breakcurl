# Changelog

## 0.3.1 — Smoother terminal workflow

- Accept browser Copy as cURL with ANSI-C quotes (`$'…'`), escaped apostrophes, and multiline text without changing JSON values. Input is still parsed as data, never executed.
- Submit pasted cURL with one Enter, including multiline commands; keep the separate confirmation before sending requests.
- Skip automatic mutations that would resend an unchanged value, preserving the request budget for meaningful checks.
- Open the HTML report in the browser after interactive runs; `--no-open` disables it, and CI/piped runs never open a browser. The demo opens one index with all four examples.
- Highlight and underline clickable local HTML report links in supported terminals, with visible file URLs as a fallback.
- Remember an explicitly selected language between interactive runs; environment and CI overrides remain temporary.

## 0.3.0 — Security checks and local HTML reports

- Standalone `report.html` with localized findings, baseline assessment, evidence, request counts, and explicit scope limits; no scripts or external resources.
- Consistent overall outcome and next action in CLI, HTML, Markdown, and JSON. Incomplete baseline-only runs also surface as JUnit errors and unsuccessful SARIF invocations.
- Dry-run shows the future request budget separately from its zero traffic. Cross-platform replay links and a complete IDOR setup guide improve the first run.
- Default auth observations in `quick`, plus safe GET request support without a request body.
- **Migration from 0.2:** strict `--expect-auth` checks now require an explicit, complete authentication contract. Pass `--auth-contract` in the CLI or `auth-contract` in the GitHub Action.
- Opt-in IDOR workflow with two identities and five bounded reads: both identity controls, both own-object controls, and one cross-account read. A failed control stops the remaining requests.
- Aggregate secret redaction across identities, report text, CI formats, and replays; inert HTML and Markdown output, with API response bodies excluded.
- Incomplete-response metadata and unavailable fingerprints for truncated bodies or transport failures, preventing complete-response claims from partial evidence.
- Preserve Node.js 20 support for the new CLI flows.
- Update Vitest to 4.1.11 to address [GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9) in the development toolchain.

## 0.2.0 — CI integration and onboarding

- `--junit [file]` writes a JUnit XML report: `FAIL` → failure, `ERROR` → error, `WARN` → skipped.
- `--sarif [file]` writes a SARIF 2.1.0 report for GitHub code scanning, with CWE-linked rules and stable case fingerprints.
- Official [GitHub Action](action/) to run BreakCurl in CI and publish findings to the Security tab.
- JSON Schema for `breakcurl.config.json` (`$schema` is now accepted) with editor autocompletion.
- README overhaul: 20-second demo first, real terminal and report samples, comparison with alternatives, FAQ, and a CI guide.

## 0.1.0 — preparing the first release

- Interactive Copy as cURL input with a sanitized preflight.
- English interface by default with complete Russian localization through `--lang ru`.
- `quick`, `negative`, `security`, and `full` profiles with a 200-check hard limit.
- Breadth-first mutation distribution across JSON paths.
- Boundary, structure, protocol, and constrained injection checks.
- Auth probes with missing and invalid credentials.
- Strict authentication contract through `--expect-auth`.
- Custom `--set`, `--remove`, `--only`, `--exclude`, and JSON config checks.
- `--dry-run` with a guaranteed zero HTTP requests.
- `PASS`, `INFO`, `WARN`, `FAIL`, and `ERROR` classifications with separate severity and confidence.
- Detection of stack traces, internal paths, database errors, credentials, and unsafe HTML reflection.
- Redacted reports and replay cURLs without response bodies.
- Rate-limit safety stop on the first `HTTP 429`.
- Live terminal progress with a compact run summary.
- CI for Node.js 20/22/24, Dependabot, and CodeQL security-extended.
