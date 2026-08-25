<h1 align="center">BreakCurl</h1>

<p align="center">
  <strong>Paste one working cURL and see how your API handles invalid data, broken authorization, and unsafe responses.</strong>
</p>

<p align="center">
  <code>Local-first</code> · <code>Zero cloud</code> · <code>Zero shell execution</code> · <code>Evidence-ready reports</code>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/c33leron/BreakCurl/main/docs/assets/breakcurl-cli.png" alt="BreakCurl running negative and security API checks in a terminal" width="100%">
</p>

BreakCurl parses a browser's `Copy as cURL` as data, verifies the original request, and mutates one JSON element at a time. It highlights crashes, weak validation, authorization gaps, and exposed internal details.

No OpenAPI specification, test code, account, cloud service, or global installation required.

## Run

Requires [Node.js 20+](https://nodejs.org/).

```bash
npx breakcurl
```

Then:

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

Try BreakCurl without your own API:

```bash
npx breakcurl demo
```

## Language

English is the default. Run the complete CLI, prompts, errors, and Markdown report in Russian with:

```bash
npx breakcurl --lang ru
```

You can also set the language for every run in the current shell:

```bash
export BREAKCURL_LANG=ru
npx breakcurl
```

`report.json` always keeps stable English machine-readable fields and messages, regardless of the selected interface language.

## What happens

The default `quick` profile sends one baseline request and prepares up to 15 checks. Before sending anything, BreakCurl shows the sanitized target, profile, exact request budget, coverage categories, and output directory.

No requests are sent without explicit confirmation. Checks run sequentially with no retries. The first `HTTP 429` stops the remaining run.

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
- Checks run sequentially with no retries.
- The first `HTTP 429` stops the run.
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
├── report.md
├── report.json
└── findings/
    └── fail-auth-auth-missing.curl
```

- `report.md` follows the selected interface language.
- `report.json` remains stable and English for CI consumers.
- `findings/*.curl` contains sanitized replay commands for `FAIL/WARN`.

Credentials, cookies, API keys, auth query parameters, JWTs, and secret-like JSON fields are replaced with `<REDACTED>`. API response bodies are not written to disk. Replay cURLs may still contain non-secret values from the original JSON, so use synthetic data and review artifacts before sharing them.

## Files and CI

```bash
npx breakcurl request.curl
cat request.curl | npx breakcurl --profile quick --allow-mutation
```

Exit codes:

```text
0  no FAIL or ERROR
1  at least one FAIL
2  ERROR, invalid input, or failed baseline
```

## Target fields and custom checks

```bash
npx breakcurl \
  --only '$.email' \
  --exclude '$.profile.internalNote' \
  --set '$.age=-1' \
  --remove '$.profile.middleName'
```

Use a [JSON config](https://github.com/c33leron/BreakCurl/blob/main/breakcurl.config.example.json) for repeatable checks:

```bash
npx breakcurl --config breakcurl.config.json
```

Complete CLI reference:

```bash
npx breakcurl --help
```

## Boundaries

BreakCurl supports one `POST`, `PUT`, `PATCH`, or `DELETE` request, one HTTP/HTTPS URL, and a root JSON object.

Multipart bodies, file bodies, redirects, shell variables, pipes, substitutions, and client certificates are intentionally unsupported. BreakCurl complements API testing but does not replace a pentest, DAST scanner, or complete QA strategy.

## Development

```bash
git clone https://github.com/c33leron/BreakCurl.git
cd BreakCurl
npm ci
npm run verify
```
