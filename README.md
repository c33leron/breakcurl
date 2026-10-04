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
  <img src="https://raw.githubusercontent.com/c33leron/BreakCurl/main/docs/assets/breakcurl-demo.gif" alt="Animated replay of real BreakCurl demo results in a macOS-style terminal; output shortened and timing adjusted" width="100%">
</p>

BreakCurl parses `Copy as cURL` as data, verifies the request, and changes one JSON element at a time. It checks input, authentication, and two-user access, with results in a local HTML report.

No OpenAPI specification, test code, account, cloud service, or global installation required.

## Try it in 20 seconds

```bash
npx breakcurl demo
```

BreakCurl starts a disposable local API with synthetic data and deliberate bugs, including auth and IDOR examples. Read the terminal summary or open `breakcurl-output/demo.html` in your browser.

## How it works

1. **Paste** one working `GET`, `POST`, `PUT`, `PATCH`, or `DELETE` request from `DevTools → Network → Copy as cURL (bash)`.
2. **Confirm** the plan: sanitized target, exact request budget, every check it will send. `--dry-run` sends nothing.
3. **Read the report**: overall result, evidence, next action, and sanitized replay cURLs. HTML, JSON, JUnit, and SARIF are available.

BreakCurl finds server failures, invalid JSON, weak input handling, and suspicious authentication or responses. Missing-auth successes, reflected markup, and SQL-looking errors need investigation before being called vulnerabilities.

## Quick start

Requires [Node.js 20+](https://nodejs.org/). No project setup or global installation.

```bash
npx breakcurl
```

1. Open `DevTools → Network`, select a working request.
2. Choose `Copy → Copy as cURL (bash)`.
3. Paste into the terminal, press `Enter` on an empty line.
4. Review the target and budget, confirm with `y`. Read results in the terminal and `breakcurl-output/`.

Confirm npm's first-run install prompt with `y`. Use only authorized DEV/local environments and disposable data.

## What a run looks like

Abridged output of `npx breakcurl demo`; separate auth/IDOR scenarios follow. Timings vary:

```text
  201      8ms  POST http://127.0.0.1:55980/api/users?token=%3CREDACTED%3E
  [01/24] PASS   AUTH         401      1ms  All declared auth sources removed: header:Authorization, query:token, json:/token
  ...
  [06/24] FAIL   STRUCTURE    500      2ms  $.age = null
  ...
  [08/24] WARN   STRUCTURE    200      3ms  $.age = "not-a-number"
  ...
  outcome      Failures found
  tries / plan 25 / 25
  results      PASS 7   INFO 15   WARN 1   FAIL 1   ERROR 0
```

`FAIL/WARN` findings include sanitized replay cURLs. Supply your authorized test credentials before running them; review before sharing.

## Profiles

| Profile | Default checks | Coverage |
| --- | ---: | --- |
| `quick` | 15 | Auth probes when supported credentials are present, plus short JSON checks |
| `negative` | 60 | JSON structure and boundaries, whitespace, long strings, Unicode |
| `security` | 80 | Auth boundary, constrained injection probes, protocol checks |
| `full` | 120 | Negative + Security |

```bash
npx breakcurl --profile negative
npx breakcurl --security
```

Counts are maximums, plus one original request. Strict auth checks require `--expect-auth` **and a complete contract**:

```bash
npx breakcurl request.curl --auth-contract breakcurl.auth.example.json --expect-auth
```

Declare every header/query/JSON credential in [the auth contract](breakcurl.auth.example.json). `401/403` confirms rejection; success becomes `FAIL` only with that complete declaration; other `4xx` responses are inconclusive. Without it, success is a candidate. You are responsible for completeness.

## Two-user access checks (IDOR)

<details>
<summary>Check whether user A can read user B's private test object</summary>

Prepare two disposable users, each owning one private object. Establish that A must not read B's object and that knowing its ID does not grant access. Give each object a different random private marker, independent of its ID: 16–256 printable ASCII characters without spaces. Return it in the object's GET response; keep it out of requests.

Save the users' GET requests as `a.curl` and `b.curl`, keeping only `Authorization: Bearer ...` and optionally identical `Accept: application/json` headers. Copy [the config example](breakcurl.idor.example.json) to `breakcurl.idor.json`. Adapt the identity endpoint, object path, string actor/object IDs, markers, and JSON Pointers to your responses; see the [schema](breakcurl.idor.schema.json).

```bash
npx breakcurl idor a.curl b.curl --config breakcurl.idor.json --dry-run
npx breakcurl idor a.curl b.curl --config breakcurl.idor.json
```

At most five reads: identify both users, verify both own-object reads, then try A → B once. A failed control stops the sequence. Disclosure requires B's object ID **and private marker** in the cross-account response, even with HTTP `403`. `403/404` without the marker confirms denial of this probe; generic `200` or incomplete evidence proves neither access nor protection.

Scope: Bearer-only GET, one origin, one object-ID path segment, no query strings, cookies, redirects, or extra headers beyond `Accept: application/json`. One pair, one direction, one read; no enumeration, write-IDOR, lists, or GraphQL.

</details>

## Safety

- Use only an authorized DEV/local environment and disposable data.
- `--dry-run` sends `0` requests. Checking your own API requires confirmation or `--allow-mutation`.
- Checks run sequentially, without retries or redirects, capped at `200`. The run stops on `HTTP 429` or transport failure. Response capture: 16 KiB; incomplete bodies cannot establish content-based findings.
- Auth probes repeat the valid body without valid credentials and may cause a side effect if the endpoint is vulnerable.
- BreakCurl never executes pasted cURL through a shell and does not perform SSRF, brute force, race/load testing, or bulk data extraction. IDOR checks read only the explicitly configured test objects.

BreakCurl is a first pass, not a replacement for a pentest. Read the [security policy](SECURITY.md).

## Results

- `PASS` — a specific expectation was confirmed.
- `INFO` — an observation without a defined pass/fail expectation.
- `WARN` — suspicious behavior without complete proof.
- `FAIL` — a `5xx`, invalid JSON contract, or proven violation of an explicit expectation.
- `ERROR` — the run or check could not be evaluated correctly.

`severity` describes potential impact; `confidence` describes evidence strength. Start with the overall result and next action. Incomplete means unfinished; baseline-only means no additional checks. A green result does not prove the entire API is secure.

## Reports

Reports are saved in `breakcurl-output/`:

```text
breakcurl-output/
├── report.html          local browser report; no server or scripts needed
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

[View the example HTML](https://github.com/c33leron/BreakCurl/blob/main/docs/examples/report.html) · [Download HTML](https://github.com/c33leron/BreakCurl/raw/refs/heads/main/docs/examples/report.html). Expand checks for evidence and next actions. Use `--output` to avoid overwriting earlier reports.

Requests go only to your chosen API; there is no BreakCurl cloud upload or telemetry. Known credentials, secret-like JSON fields, and private markers are redacted before writing. Response bodies are never saved. Unrecognized sensitive values may remain; use synthetic data and review artifacts before sharing.

## CI and GitHub code scanning

Exit codes: `0` no FAIL or ERROR · `1` completed with FAIL · `2` ERROR, invalid input, or failed baseline/control. Incomplete runs take precedence and exit `2`, and are marked unsuccessful in JUnit/SARIF. Warnings can still exit `0`.

The official [GitHub Action](https://github.com/c33leron/BreakCurl/tree/main/action) runs BreakCurl from a cURL file, publishes findings to the repository Security tab via SARIF, and fails the job on `FAIL`.

<details>
<summary>Example GitHub workflow</summary>

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
          breakcurl-version: "0.3.0"
```

</details>

Strict auth checks need `auth-contract` and `expect-auth`. Do not commit credentials; see the [action README](https://github.com/c33leron/BreakCurl/blob/main/action/README.md) for using secrets.

## Files and custom checks

```bash
npx breakcurl request.curl
npx breakcurl request.curl --dry-run
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

English is the default; use `npx breakcurl --lang ru` or `export BREAKCURL_LANG=ru`. HTML and Markdown follow the selected language. JSON, JUnit, and SARIF keep stable English machine-readable fields.

## FAQ

**What do I need to start?**
Node.js 20+ and one working cURL. Run `npx breakcurl`; no project setup, OpenAPI spec, or global installation needed. To try it without your own API, run `npx breakcurl demo`.

**Can it change data in my API?**
Yes. Write requests, including auth probes, can create or change data. Use an authorized DEV/local environment with disposable data. Preview the plan with `--dry-run`, which sends no requests.

**Does it support GET and IDOR?**
Yes. Use GET without a body for basic checks, or the [two-user IDOR workflow](#two-user-access-checks-idor) to test access to another user's private object.

**Where do my secrets go?**
Requests go to your chosen API, with no BreakCurl cloud upload or telemetry. Known secrets are hidden in local reports; response bodies are not saved. Review files before sharing: unrecognized sensitive values may remain.

**Does a green result mean my API is secure?**
No. It only confirms the expectations actually checked. BreakCurl helps find problems early; it does not replace a pentest.

## Boundaries

BreakCurl supports one HTTP(S) URL: `GET` without a body, or `POST`/`PUT`/`PATCH`/`DELETE` with a root JSON object. Multipart/file bodies, redirects, shell variables, pipes, substitutions, client certificates, and duplicate headers are unsupported. IDOR has the narrower limits described above.

## Development

For contributors only; users start with `npx breakcurl`.

```bash
git clone https://github.com/c33leron/BreakCurl.git
cd BreakCurl
npm ci
npm run verify
```

To run your local code, use `npm run demo` or replace `npx breakcurl` with `npm run check --`.
