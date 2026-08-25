# Security policy

## Safe usage

BreakCurl sends one baseline request and may then send up to 200 sequential `POST`, `PUT`, `PATCH`, or `DELETE` checks. Default profiles are limited to 15–120 cases. Use the tool only against systems you are authorized to test and only with disposable data that can be safely modified or restored.

If the target API returns `HTTP 429`, BreakCurl immediately stops the remaining checks, returns `ERROR`, and records the number of skipped cases. This limits additional traffic after a rate limit is reached, but it does not replace an agreed request budget or an authorized test environment.

Before execution, BreakCurl displays the sanitized target, profile, exact request budget, and coverage categories. Interactive runs require confirmation. Non-interactive runs require `--allow-mutation`. A `--dry-run` always sends zero HTTP requests.

The `security` and `full` profiles may send the original valid body without credentials or with invalid credentials. If an endpoint is vulnerable, an auth probe may execute the business operation. Use a non-production environment, a dedicated test entity, and a restoration plan. With `--expect-auth`, only `401/403` proves an authentication rejection.

Security payloads use constrained, non-executable markers. BreakCurl does not perform brute force, SSRF, race/load testing, data extraction, persistence, or automated exploitation.

BreakCurl parses the input cURL as data and never executes it through a shell. Unsupported shell syntax and unsupported cURL features are rejected before any request is sent.

Sensitive headers, query parameters, JSON fields, known credential values, JWTs, and private-key patterns are redacted from generated files. API response bodies are not written to disk: reports contain only status, metadata, and a structural fingerprint. Redaction does not replace short-lived test credentials and least privilege.

BreakCurl runs locally and has no accounts, telemetry, or cloud upload.

## Supported releases

Security fixes are provided for the latest published release.

## Reporting a vulnerability

Do not include active credentials, personal data, production payloads, or private URLs in public Issues. Send the maintainer a minimal sanitized reproduction through a private GitHub Security Advisory. Include the affected release, impact, reproduction steps, and expected protection.
