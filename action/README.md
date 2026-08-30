# BreakCurl GitHub Action

Runs [BreakCurl](https://github.com/c33leron/BreakCurl) against one saved cURL request in CI, writes `report.md`, `report.json`, `junit.xml`, and `sarif.json`, and optionally publishes findings to [GitHub code scanning](https://docs.github.com/en/code-security/code-scanning).

JUnit and SARIF reports require `breakcurl` 0.2.0 or newer (`breakcurl-version` input).

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
          expect-auth: "true"
```

The job fails when BreakCurl exits non-zero: `1` means at least one `FAIL`, `2` means `ERROR`, invalid input, or a failed baseline. For advisory-only runs add `continue-on-error: true` to the job.

To publish findings to the Security tab, keep `permissions.security-events: write` and `upload-sarif: "true"` (the default).

## Handling credentials in the cURL file

BreakCurl does not expand shell variables in the pasted cURL, so do not commit real credentials. Assemble the file from a low-privilege synthetic test token at runtime:

```yaml
      - name: Assemble cURL from secrets
        run: |
          sed "s/\$TEST_TOKEN/${{ secrets.BC_TEST_TOKEN }}/" tests/fixtures/create-user.curl.template > /tmp/request.curl
      - uses: c33leron/BreakCurl/action@main
        with:
          curl-file: /tmp/request.curl
```

Use a dedicated test account against a non-production environment. Reports redact credentials before writing, but replay cURLs may still contain non-secret values from the original JSON body.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `curl-file` | — (required) | File containing the working cURL command |
| `profile` | `quick` | `quick`, `negative`, `security`, or `full` |
| `max-cases` | profile default | Maximum checks, 1–200 |
| `expect-auth` | `false` | Auth probes must return 401/403 (profile `security`/`full`) |
| `timeout` | `10000` | Per-request timeout in milliseconds |
| `lang` | `en` | Interface language for `report.md` (`en` or `ru`) |
| `output-directory` | `breakcurl-output` | Where reports are written |
| `breakcurl-version` | `latest` | npm package version of breakcurl to run |
| `upload-sarif` | `true` | Upload `sarif.json` to GitHub code scanning |

## Outputs

| Output | Description |
| --- | --- |
| `report-path` | Markdown report |
| `junit-path` | JUnit XML report |
| `sarif-path` | SARIF 2.1.0 report |

## Safety

BreakCurl sends one baseline request and up to `max-cases` sequential mutation requests against the target in the cURL. Only point it at environments you are authorized to test, with disposable synthetic data. See the [security policy](../SECURITY.md).
