<h1 align="center">BreakCurl</h1>

<p align="center">
  <strong>Paste one working cURL and see how your API handles invalid data, broken authorization, and unsafe responses.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/breakcurl"><img src="https://img.shields.io/npm/v/breakcurl" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/breakcurl"><img src="https://img.shields.io/npm/dm/breakcurl" alt="npm downloads"></a>
  <a href="https://github.com/c33leron/BreakCurl/actions/workflows/ci.yml"><img src="https://github.com/c33leron/BreakCurl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/c33leron/BreakCurl/actions/workflows/codeql.yml"><img src="https://github.com/c33leron/BreakCurl/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://www.npmjs.com/package/breakcurl"><img src="https://img.shields.io/node/v/breakcurl" alt="Node.js version"></a>
  <a href="https://github.com/c33leron/BreakCurl/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/breakcurl" alt="License"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/c33leron/BreakCurl/main/docs/assets/breakcurl-cli.png" alt="BreakCurl running negative and security API checks in a terminal" width="100%">
</p>

BreakCurl parses a browser's `Copy as cURL` as data, verifies the original request, and mutates one JSON element at a time. It highlights crashes, weak validation, authorization gaps, and exposed internal details — and produces evidence-ready reports.

No OpenAPI specification, test code, account, cloud service, or global installation required.

## Try it in 20 seconds

```bash
npx breakcurl demo
```

BreakCurl starts a disposable local API, attacks it with the full check profile, and shows real findings — no target system needed, zero risk.

## How it works

1. **Paste** one working `POST`, `PUT`, `PATCH`, or `DELETE` request from `DevTools → Network → Copy as cURL (bash)`.
2. **Confirm** the plan: sanitized target, exact request budget, every check it will send. `--dry-run` sends nothing.
3. **Read the report**: sequential checks with a strict oracle, sanitized replay cURLs for every finding, plus `report.json`, JUnit, and SARIF for CI.

BreakCurl detects `5xx` crashes, invalid JSON contracts, unvalidated fields and boundaries, endpoints answering `2xx` without credentials (CWE-306), stack traces and database errors in responses (CWE-209), reflected secrets (CWE-200), and unescaped markup reflection (CWE-79).

## Quick start

Requires [Node.js 20+](https://nodejs.org/).

```bash
npx breakcurl
```

1. Open `DevTools → Network`, select a working request.
2. Choose `Copy → Copy as cURL (bash)`.
3. Paste into the terminal, press `Enter` on an empty line.
4. Review the target and request budget, confirm with `y`.

Use only an authorized DEV/local environment and disposable data.

## What a run looks like

Output of `npx breakcurl demo` (abridged):

```text
BASELINE
  201     15ms  POST http://127.0.0.1:62143/api/users?token=<REDACTED>

CHECKS
  [01/24] PASS   AUTH         401      2ms  all credentials removed
  [06/24] FAIL   STRUCTURE    500      1ms  $.age = null
  [08/24] WARN   STRUCTURE    200      2ms  $.age = "not-a-number"
  ...

RUN SUMMARY
  results     PASS 7   INFO 15   WARN 1   FAIL 1   ERROR 0
```

Every `FAIL/WARN` finding ships with a sanitized replay cURL you can run, share, or attach to a bug report.

## Profiles

| Profile | Default checks | Coverage |
| --- | ---: | --- |
| `quick` | 15 | Remove, `null`, wrong type, empty value, numeric boundary |
| `negative` | 60 | Quick + whitespace, long strings, Unicode, extended boundaries |
| `security` | 80 | Auth boundary, constrained injection probes, protocol checks |
| `full` | 120 | Negative + Security |

```bash
npx breakcurl --profile negative
npx breakcurl --security --expect-auth
```

`--expect-auth` makes the authentication oracle strict: `401/403` → `PASS`, `2xx` → `FAIL`, another `4xx` → `WARN`. Without it, a successful auth probe stays `WARN` — the endpoint may be intentionally public.

## Safety

- Use only an authorized DEV/local environment and disposable data.
- `--dry-run` always sends `0` requests; without confirmation or `--allow-mutation`, no requests are sent.
- Checks run sequentially with no retries; the first `HTTP 429` stops the run; one run is hard-limited to `200` checks.
- Auth probes repeat the valid body without valid credentials and may cause a side effect if the endpoint is vulnerable.
- BreakCurl never executes the pasted cURL through a shell and does not perform exploitation, SSRF, brute force, race/load testing, or data extraction.

Read the complete [security policy](SECURITY.md).

## Results

- `PASS` — a specific expectation was confirmed.
- `INFO` — an observation without a strict oracle.
- `WARN` — suspicious behavior without complete proof.
- `FAIL` — a `5xx`, invalid JSON contract, or proven violation of an explicit oracle.
- `ERROR` — the run or check could not be evaluated correctly.

`severity` describes potential impact. `confidence` describes the strength of the evidence.

## Reports

Each run creates `breakcurl-output/`:

```text
breakcurl-output/
├── report.md            human-readable, follows --lang
├── report.json          stable English machine-readable format
├── junit.xml            with --junit: for any CI server
├── sarif.json           with --sarif: SARIF 2.1.0 for GitHub code scanning
└── findings/
    └── fail-age-null.curl   sanitized replay commands for FAIL/WARN
```

```bash
npx breakcurl --junit --sarif
```

Credentials, cookies, API keys, auth query parameters, JWTs, and secret-like JSON fields are replaced with `<REDACTED>` before anything is written to disk. API response bodies are never saved. Replay cURLs may still contain non-secret values, so use synthetic data and review artifacts before sharing them.

## CI and GitHub code scanning

Exit codes: `0` no FAIL or ERROR · `1` at least one FAIL · `2` ERROR, invalid input, or failed baseline.

The official [GitHub Action](action/) runs BreakCurl from a committed cURL file, publishes findings to the repository Security tab via SARIF, and fails the job on `FAIL`:

```yaml
name: API checks
on:
  schedule:
    - cron: "0 4 * * 1"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  breakcurl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: c33leron/BreakCurl/action@main
        with:
          curl-file: tests/fixtures/create-user.curl
          profile: security
          expect-auth: "true"
```

Do not commit real credentials — see the [action README](action/README.md) for assembling the cURL from secrets at runtime.

## Files and custom checks

```bash
npx breakcurl request.curl
cat request.curl | npx breakcurl --profile quick --allow-mutation
npx breakcurl --only '$.email' --exclude '$.profile.internalNote' --set '$.age=-1' --remove '$.profile.middleName'
```

Use a [JSON config](breakcurl.config.example.json) for repeatable checks:

```bash
npx breakcurl --config breakcurl.config.json
```

Reference the [JSON Schema](breakcurl.config.schema.json) in your config for editor autocompletion:

```json
{ "$schema": "https://raw.githubusercontent.com/c33leron/BreakCurl/main/breakcurl.config.schema.json" }
```

Complete CLI reference:

```bash
npx breakcurl --help
```

## Language

English is the default; run everything in Russian with `npx breakcurl --lang ru` or `export BREAKCURL_LANG=ru`. `report.json`, `junit.xml`, and `sarif.json` always keep stable English machine-readable fields.

## Why BreakCurl

API negative testing usually asks you to bring your own spec, templates, or wordlists. BreakCurl starts from the one artifact every developer already has: a working request from the browser.

| | BreakCurl | Schemathesis | nuclei | ffuf | Burp Intruder |
| --- | --- | --- | --- | --- | --- |
| Input | one pasted cURL | OpenAPI spec | templates | wordlists | proxy + manual config |
| Setup effort | seconds | needs a spec | needs templates | needs wordlists | needs proxy setup |
| Built-in oracles | yes | spec-based | matchers | no | manual review |
| Safe sequential defaults, budget cap, 429 stop | yes | partial | no | no | manual |
| Install | `npx` | `pip` | binary | binary | licensed app |

BreakCurl complements API testing; it does not replace a pentest, DAST scanner, or complete QA strategy.

## FAQ

**Is it safe to run against our shared DEV environment?**
One baseline request plus up to `--max-cases` sequential mutations, stop on the first `HTTP 429`, nothing in parallel. Still: disposable data, review the plan before confirming, prefer `--dry-run` first.

**Do I need an OpenAPI spec?**
No. The working cURL is the spec — it contains the URL, headers, credentials, and a valid body to mutate.

**Does it support GET requests?**
Not yet; a read-only profile with an IDOR oracle is on the roadmap.

**Where do my secrets go?**
Nowhere. Local-only, zero telemetry, secrets redacted before writing, response bodies never saved.

**Can it replace a pentest?**
No — it is the fast, safe first pass every QA engineer can run before involving security specialists.

## Boundaries

BreakCurl supports one `POST`, `PUT`, `PATCH`, or `DELETE` request, one HTTP/HTTPS URL, and a root JSON object. Multipart bodies, file bodies, redirects, shell variables, pipes, substitutions, and client certificates are intentionally unsupported.

## Roadmap

- Read-only `GET` profile with an IDOR oracle
- Run-to-run comparison: what broke since the last report
- More CI report targets (GitLab Code Quality, JUnit variants)

## Development

```bash
git clone https://github.com/c33leron/BreakCurl.git
cd BreakCurl
npm ci
npm run verify
```
