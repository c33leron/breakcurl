# Changelog

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
