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

BreakCurl reads `Copy as cURL` without executing it, verifies the request, and tests JSON input, authentication, and two-user access. Results stay in local reports.

## Try it in 20 seconds

```bash
npx breakcurl demo
```

The demo uses a disposable local API with deliberate bugs, including auth and IDOR. In an interactive terminal, it opens `breakcurl-output/demo.html`: one tab with all four examples.

## Quick start

Requires [Node.js 20+](https://nodejs.org/).

```bash
npx breakcurl
```

1. Open `DevTools → Network`, select a working request.
2. Choose `Copy → Copy as cURL (bash)`.
3. Paste into the terminal and press `Enter` once.
4. Review the target, checks, and request budget, then confirm with `y`. Read the terminal summary and HTML report.

Confirm npm's first-run install prompt with `y`. Use only authorized DEV/local environments and disposable data.

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
- Pasted cURL is never executed. No SSRF, brute force, race/load testing, or bulk extraction. IDOR reads only the configured test objects.

Read the [security policy](SECURITY.md).

## Results

- `PASS` — a specific expectation was confirmed.
- `INFO` — an observation without a defined pass/fail expectation.
- `WARN` — suspicious behavior without complete proof.
- `FAIL` — a `5xx`, invalid JSON contract, or proven violation of an explicit expectation.
- `ERROR` — the run or check could not be evaluated correctly.

`severity` describes potential impact; `confidence` describes evidence strength. Incomplete means unfinished; baseline-only means no additional checks. Reflected markup and SQL-looking errors are observations, not proof of exploitation.

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

Interactive runs open the HTML report in your browser. On Windows/Linux, your default HTML app is used. Use `--no-open` to disable this; CI and piped runs never open a browser. The terminal also prints a highlighted `file://` link. Opening it depends on your terminal; you can always paste it into your browser.

```bash
npx breakcurl --junit --sarif
```

[View example HTML](https://github.com/c33leron/BreakCurl/blob/main/docs/examples/report.html) · [Download HTML](https://github.com/c33leron/BreakCurl/raw/refs/heads/main/docs/examples/report.html). Use `--output` to keep earlier reports. Replay cURLs redact credentials; add your authorized test credentials before running them.

Requests go only to your API, with no cloud upload or telemetry. Reports redact known credentials, secret-like JSON fields, and private markers; response bodies are never saved. Unknown sensitive values may remain: use synthetic data and review before sharing.

## CI and GitHub code scanning

Exit codes: `0` no FAIL or ERROR · `1` completed with FAIL · `2` ERROR, invalid input, or failed baseline/control. Incomplete runs take precedence and exit `2`, and are marked unsuccessful in JUnit/SARIF. Warnings can still exit `0`.

The [GitHub Action](https://github.com/c33leron/BreakCurl/tree/main/action) runs a cURL file, publishes SARIF to the repository Security tab, and fails on `FAIL`. See its [workflow and secrets setup](https://github.com/c33leron/BreakCurl/blob/main/action/README.md). Strict auth checks need `auth-contract` and `expect-auth`; never commit credentials.

## Files and custom checks

```bash
npx breakcurl request.curl
npx breakcurl request.curl --dry-run
cat request.curl | npx breakcurl --profile quick --allow-mutation
npx breakcurl --only '$.email' --exclude '$.profile.internalNote' --set '$.age=-1' --remove '$.profile.middleName'
```

Use `--config breakcurl.config.json` for repeatable checks: [example](breakcurl.config.example.json) · [schema](breakcurl.config.schema.json). Run `npx breakcurl --help` for all options.

## Language

English is the default. Run `npx breakcurl --lang ru` in your terminal to save Russian; `--lang en` switches back. `--lang` and `BREAKCURL_LANG` override the saved choice. Piped and CI runs never save changes. HTML/Markdown follow the language; JSON/JUnit/SARIF keep stable English fields.

## FAQ

**What do I need to start?**
Node.js 20+ and a working cURL. Run `npx breakcurl`, or `npx breakcurl demo` for a local example. No setup, OpenAPI spec, account, or global installation.

**Can it change data in my API?**
Yes. Write requests, including auth probes, can create or change data. Use an authorized DEV/local environment with disposable data. Preview the plan with `--dry-run`, which sends no requests.

**Does it support GET and IDOR?**
Yes. Use GET without a body for basic checks, or the [two-user IDOR workflow](#two-user-access-checks-idor) to test access to another user's private object.

**Where do my secrets go?**
Requests go only to your API. Reports redact known secrets and never save response bodies. Unknown sensitive values may remain, so review files before sharing.

**Does a green result mean my API is secure?**
No. It only confirms the expectations actually checked. BreakCurl helps find problems early; it does not replace a pentest.

## Boundaries

BreakCurl supports one HTTP(S) URL: `GET` without a body, or `POST`/`PUT`/`PATCH`/`DELETE` with a root JSON object. Multipart/file bodies, redirects, shell variables, pipes, substitutions, client certificates, and duplicate headers are unsupported. IDOR has the narrower limits described above.

## Development

```bash
git clone https://github.com/c33leron/BreakCurl.git
cd BreakCurl
npm ci
npm run verify
```

To run your local code, use `npm run demo` or replace `npx breakcurl` with `npm run check --`.
