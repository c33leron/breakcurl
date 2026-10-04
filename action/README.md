# BreakCurl GitHub Action

Runs [BreakCurl](https://github.com/c33leron/BreakCurl) against one saved cURL request in CI, writes HTML, Markdown, JSON, JUnit, and SARIF reports, and optionally publishes findings to [GitHub code scanning](https://docs.github.com/en/code-security/code-scanning).

Use `breakcurl-version: "0.3.0"` for HTML reports, auth observations in `quick`, and complete auth contracts. The Action downloads the selected version from npm. JUnit and SARIF are also supported in `0.2.0`.

## Usage

Save a working `Copy as cURL` from your browser DevTools as a file in the repository (or assemble it from a secret at runtime). Point the action at it:

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

The job fails when BreakCurl exits non-zero: `1` means a completed run with at least one `FAIL`; `2` means an incomplete run, `ERROR`, invalid input, or a failed baseline. For advisory-only runs add `continue-on-error: true` to the job.

To publish findings to the Security tab, keep `permissions.security-events: write` and `upload-sarif: "true"` (the default).

## Handling credentials in the cURL file

BreakCurl does not expand shell variables in the pasted cURL, so do not commit real credentials. Assemble the file from a low-privilege synthetic test token at runtime:

```yaml
      - name: Assemble cURL from secrets
        env:
          BC_TEST_TOKEN: ${{ secrets.BC_TEST_TOKEN }}
        run: |
          node <<'NODE'
          const { writeFileSync } = require('node:fs');
          const { join } = require('node:path');
          const token = process.env.BC_TEST_TOKEN;
          if (!token) throw new Error('BC_TEST_TOKEN is required');
          // Build a literal cURL file. Neither Node nor the shell executes it.
          const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
          const args = [
            'curl', '--request', 'POST',
            '--url', quote('https://test-api.example.test/users'),
            '--header', quote('Content-Type: application/json'),
            '--header', quote('Authorization: Bearer ' + token),
            '--data-raw', quote(JSON.stringify({ displayName: 'CI synthetic user', age: 30 })),
          ];
          writeFileSync(join(process.env.RUNNER_TEMP, 'request.curl'), args.join(' ') + '\n', { mode: 0o600 });
          NODE
      - uses: c33leron/BreakCurl/action@main
        with:
          curl-file: ${{ runner.temp }}/request.curl
          breakcurl-version: "0.3.0"
```

Use a dedicated test account against a non-production environment. Reports redact credentials before writing, but replay cURLs may still contain non-secret values from the original JSON body.

Replace the synthetic endpoint with your authorized test endpoint. The token enters Node through the environment and is written as a quoted argument; quotes, dollar signs, and backticks in its value are never evaluated as shell code. Do not print or upload the original request file.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `curl-file` | — (required) | File containing the working cURL command |
| `profile` | `quick` | `quick`, `negative`, `security`, or `full` |
| `max-cases` | profile default | Maximum checks, 1–200 |
| `expect-auth` | `false` | Require strict auth rejection. In 0.3.0+, also supply a complete `auth-contract`; `quick` already includes non-strict auth observations. |
| `auth-contract` | empty | Path to a complete auth contract JSON file; requires 0.3.0+ |
| `timeout` | `10000` | Per-request timeout in milliseconds |
| `lang` | `en` | Human-readable report language (`en` or `ru`); JSON remains English |
| `output-directory` | `breakcurl-output` | Where reports are written |
| `breakcurl-version` | `latest` | npm package version of breakcurl to run |
| `upload-sarif` | `true` | Upload `sarif.json` to GitHub code scanning |

A complete auth contract lists every credential source and confirms that the list is complete. Naming just one Bearer header is insufficient if a cookie, query parameter, or body field also authenticates the request. See the [contract example](../breakcurl.auth.example.json). Strict checks need both the contract and `expect-auth: "true"`; without a complete contract, successful probes remain candidates.

## Outputs

| Output | Description |
| --- | --- |
| `report-path` | Markdown report |
| `junit-path` | JUnit XML report |
| `sarif-path` | SARIF 2.1.0 report |

## Safety

BreakCurl sends one baseline request and up to `max-cases` sequential mutation requests against the target in the cURL. Only point it at environments you are authorized to test, with disposable synthetic data. See the [security policy](../SECURITY.md).
