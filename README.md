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

BreakCurl starts a disposable local API, attacks it with the full check profile, and shows real findings — no target system needed, zero risk. You get a genuine report with a crash (`FAIL`), a weak-validation signal (`WARN`), and correctly rejected checks (`PASS`).

## How it works

1. **Paste** one working `POST`, `PUT`, `PATCH`, or `DELETE` request from `DevTools → Network → Copy as cURL (bash)`.
2. **Confirm** the plan: BreakCurl shows the sanitized target, the exact request budget, and every check it will send. `--dry-run` shows the plan and sends nothing.
3. **Read the report**: sequential checks with a strict oracle, sanitized replay cURLs for every finding, and a machine-readable `report.json` (plus JUnit and SARIF for CI).

BreakCurl detects:

- `5xx` crashes and invalid JSON contracts on mutated input
- required fields, types, enums, and boundaries that are silently not validated
- endpoints that answer `2xx` without valid credentials (`CWE-306`)
- stack traces, internal paths, database and ORM errors in responses (`CWE-209`)
- credentials, JWTs, and private keys reflected in responses (`CWE-200`)
- unescaped markup reflection in HTML responses (`CWE-79`)

## Quick start

Requires [Node.js 20+](https://nodejs.org/).

```bash
npx breakcurl
```

1. Open `DevTools → Network` in your browser.
2. Select a working `POST`, `PUT`, `PATCH`, or `DELETE` request.
3. Choose `Copy → Copy as cURL (bash)`.
4. Paste the complete cURL into the terminal and press `Enter` on an empty line.
5. Review the target and request budget, then confirm with `y`.

`npx` downloads and runs BreakCurl for you. Nothing is installed globally.

Preview the complete plan without sending a single HTTP request:

```bash
npx breakcurl --dry-run
```

Use only an authorized DEV/local environment and disposable data.

## What a run looks like

Output of `npx breakcurl demo` (abridged):

```text
BREAKCURL  LOCAL DEMO

BASELINE
  201     15ms  POST http://127.0.0.1:62143/api/users?token=<REDACTED>

CHECKS
  [01/24] PASS   AUTH         401      2ms  all credentials removed
  [02/24] PASS   AUTH         401      1ms  credentials replaced with invalid values
  [03/24] PASS   STRUCTURE    422      1ms  field $.email removed
  [06/24] FAIL   STRUCTURE    500      1ms  $.age = null
  [08/24] WARN   STRUCTURE    200      2ms  $.age = "not-a-number"
  [09/24] INFO   BOUNDARY     422      1ms  $.email = ""
  ...

RUN SUMMARY
  executed    24
  results     PASS 7   INFO 15   WARN 1   FAIL 1   ERROR 0
```

And the matching Markdown report, findings section:

```markdown
## Findings

- **FAIL** $.age = null: The API returned HTTP 500. (risk HIGH, confidence HIGH)
  — [sanitized replay cURL](findings/fail-age-null.curl)
- **WARN** $.age = "not-a-number": The API accepted a value that was expected
  to be rejected with HTTP 200. (risk MEDIUM, confidence MEDIUM)
  — [sanitized replay cURL](findings/warn-age-wrong-type.curl)
```

Every `FAIL/WARN` finding ships with a sanitized replay cURL you can run, share, or attach to a bug report.

## Profiles

| Profile | Default checks | Coverage |
| --- | ---: | --- |
| `quick` | 15 | Remove, `null`, wrong type, empty value, and numeric boundary |
| `negative` | 60 | Quick + whitespace, long strings, Unicode, and extended boundaries |
| `security` | 80 | Auth boundary, constrained injection probes, and protocol checks |
| `full` | 120 | Negative + Security |

```bash
npx breakcurl --profile negative
npx breakcurl --security
npx breakcurl --security --expect-auth
npx breakcurl --profile full --max-cases 100
```

`--expect-auth` makes the authentication oracle strict:

- `401/403` → `PASS`
- `2xx` → `FAIL`
- another `4xx` → `WARN`

Without `--expect-auth`, a successful auth probe remains `WARN`: the endpoint may be intentionally public.

## Safety

- Use only an authorized DEV/local environment and disposable data.
- `--dry-run` always sends `0` requests.
- Without confirmation or `--allow-mutation`, no requests are sent.
- Auth probes repeat the valid body without valid credentials and may cause a side effect if the endpoint is vulnerable.
- Checks run sequentially with no retries. The first `HTTP 429` stops the run.
- One run is hard-limited to `200` checks.
- BreakCurl never executes the pasted cURL through a shell.
- BreakCurl does not perform exploitation, SSRF, brute force, race/load testing, or data extraction.

Read the complete [security policy](https://github.com/c33leron/BreakCurl/blob/main/SECURITY.md).

## Results

- `PASS` — a specific expectation was confirmed.
- `INFO` — an observation without a strict oracle.
- `WARN` — suspicious behavior or a security signal without complete proof.
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
npx breakcurl --junit           # writes breakcurl-output/junit.xml
npx breakcurl --sarif           # writes breakcurl-output/sarif.json
npx breakcurl --junit --sarif   # both, for CI runs
```

Credentials, cookies, API keys, auth query parameters, JWTs, and secret-like JSON fields are replaced with `<REDACTED>`. API response bodies are not written to disk. Replay cURLs may still contain non-secret values from the original JSON, so use synthetic data and review artifacts before sharing them.

## CI and GitHub code scanning

Exit codes gate your pipeline:

```text
0  no FAIL or ERROR
1  at least one FAIL
2  ERROR, invalid input, or failed baseline
```

The official [GitHub Action](action/) runs BreakCurl from a committed cURL file, publishes `FAIL`/`WARN` findings to the repository Security tab via SARIF, and fails the job on `FAIL`:

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

Do not commit real credentials: BreakCurl rejects shell variables in cURL, so assemble the file from a low-privilege test token at runtime (see the [action README](action/README.md)).

## Files and pipes

```bash
npx breakcurl request.curl
cat request.curl | npx breakcurl --profile quick --allow-mutation
```

## Target fields and custom checks

```bash
npx breakcurl \
  --only '$.email' \
  --exclude '$.profile.internalNote' \
  --set '$.age=-1' \
  --remove '$.profile.middleName'
```

Use a [JSON config](breakcurl.config.example.json) for repeatable checks:

```bash
npx breakcurl --config breakcurl.config.json
```

Reference the [JSON Schema](breakcurl.config.schema.json) from your config for editor autocompletion:

```json
{
  "$schema": "https://raw.githubusercontent.com/c33leron/BreakCurl/main/breakcurl.config.schema.json"
}
```

Complete CLI reference:

```bash
npx breakcurl --help
```

## Language

English is the default. Run the complete CLI, prompts, errors, and Markdown report in Russian with:

```bash
npx breakcurl --lang ru
# or for every run in the current shell:
export BREAKCURL_LANG=ru
```

`report.json`, `junit.xml`, and `sarif.json` always keep stable English machine-readable fields, regardless of the selected interface language.

## Why BreakCurl

API negative testing usually asks you to bring your own spec, templates, or wordlists. BreakCurl starts from the one artifact every developer already has: a working request from the browser.

| | BreakCurl | Schemathesis | nuclei | ffuf | Burp Intruder |
| --- | --- | --- | --- | --- | --- |
| Input | one pasted cURL | OpenAPI spec | templates | wordlists | proxy + manual config |
| Setup effort | seconds | needs a spec | needs templates | needs wordlists | needs proxy setup |
| Built-in oracles (auth, contract, validation) | yes | spec-based | matchers | no | manual review |
| Safe defaults: sequential, budget cap, 429 stop, confirmation | yes | partial | no | no | manual |
| Works without a spec or proxy | yes | no | yes | yes | no |
| Install | `npx` | `pip` | binary | binary | licensed app |

BreakCurl complements API testing; it does not replace a pentest, DAST scanner, or complete QA strategy.

## FAQ

**Is it safe to run against our shared DEV environment?**
BreakCurl sends one baseline request plus up to `--max-cases` sequential mutations, stops on the first `HTTP 429`, and never runs anything in parallel. Still: use disposable data, review the plan before confirming, and prefer `--dry-run` first. If an endpoint is vulnerable, an auth probe can execute the operation — see [Safety](#safety).

**Do I need an OpenAPI spec?**
No. The working cURL is the spec — it contains the URL, headers, credentials, and a valid body to mutate.

**Does it support GET requests?**
Not yet. BreakCurl currently mutates JSON bodies of `POST/PUT/PATCH/DELETE` requests. A read-only profile with an IDOR oracle is on the roadmap.

**Where do my secrets go?**
Nowhere. BreakCurl runs locally with zero telemetry and no cloud. Secrets are redacted before anything is written to disk, and API response bodies are never saved.

**What happens when it finds something?**
You get a `FAIL` or `WARN` entry in the report, a sanitized replay cURL to reproduce it, and — with `--sarif` — an alert in the GitHub Security tab. Attach the replay to your bug report; the evidence is already packaged.

**Can it replace a pentest?**
No, and it does not try. BreakCurl is the fast, safe first pass every QA engineer can run before involving security specialists.

## Boundaries

BreakCurl supports one `POST`, `PUT`, `PATCH`, or `DELETE` request, one HTTP/HTTPS URL, and a root JSON object.

Multipart bodies, file bodies, redirects, shell variables, pipes, substitutions, and client certificates are intentionally unsupported.

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

## License

[MIT](LICENSE) — © Bogdan Bobylev
