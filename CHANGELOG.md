# Changelog

## 0.4.0 — Attack mode: OWASP API coverage, JWT tampering, recon

- **JWT attacks (API2:2023)**: signed Bearer tokens are replayed with `alg=none`, a stripped signature, or modified claims/`exp`. Successful probes remain candidates unless a complete sole-Authorization contract and `--expect-auth` require HTTP rejection. Changing `exp` also invalidates the signature and does not test expiry enforcement. Unchanged variants and unsigned source tokens are skipped.
- **Mass-assignment probes (API3:2023)**: `isAdmin: true` and `role: "admin"` are injected into the payload; responses remain observations until field persistence or permission effects are independently verified.
- **Excessive-data scan (API3:2023)**: responses are scanned in memory for bcrypt/argon2/crypt password hashes and sensitive-named fields; values never reach reports (CWE-200).
- **Configuration audit (API8:2023)**: the baseline response is audited once for incompatible CORS wildcard with credentials (LOW configuration observation; browsers block credentialed reads), missing `Secure`/`HttpOnly` cookie flags (CWE-614), missing HSTS (CWE-319), and versioned `Server` headers.
- **Spec discovery (API9:2023)**: unauthenticated same-origin GETs to `/openapi.json`, `/swagger.json`, `/graphql`, `/api-docs`; structured specs and recognized documentation renderers are flagged for review. Input headers and credentials are not forwarded to these paths.
- **Method tampering (API5:2023)**: opt-in `--attack-methods` replays a non-GET working request with each other supported HTTP verb, including destructive ones. Off by default.
- **OWASP API Security Top 10 coverage matrix** in `report.md`, `report.html`, and `report.json` — statuses and descriptions reflect evaluated probes. Failed IDOR prerequisites do not claim a completed cross-account read or unrelated audits; out-of-scope items are stated explicitly.
- **OWASP tags on signals** in SARIF (`breakcurl/owasp` property) and HTML badges (`API2:2023`, …).
- Baseline findings and each individual security signal are exported to SARIF with their own rule and severity; server/transport failures retain their primary result.
- SARIF `security-severity` is now derived from the finding severity (HIGH `8.1` / MEDIUM `5.0` / LOW `2.5`) instead of a hardcoded CWE guess — HIGH IDOR findings no longer score `5.0`.
- Default profile is now `security` (attack-first). `quick`, `negative`, and `full` remain available; `--profile` overrides.
- Terminal labels for the new `AUTHZ` and `RECON` categories; confirmation prompt mentions broken-JWT and method-tampering side effects.
- **Migration from 0.3**: default runs send more requests than the old `quick` default (up to ~80 checks); use `--profile quick` or `--max-cases` to keep the old budget. SARIF rule severities may shift where findings are HIGH.

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
