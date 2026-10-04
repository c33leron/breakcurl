# Security policy

## Authorized, bounded testing

Use BreakCurl only against systems you are authorized to test, with disposable test data. The ordinary CLI sends one working baseline and at most 200 sequential checks (15 by default). POST/PUT/PATCH/DELETE probes can execute real business operations, including when an authentication control is broken. Restoration of application data is the operator's responsibility; there is no hidden cleanup traffic.

Before traffic, the CLI shows the sanitized target, profile, request budget, and checks. Interactive runs require confirmation; noninteractive runs require `--allow-mutation`. The self-contained `demo` command authorizes only its temporary loopback fixtures. `--dry-run` always sends zero requests and does not start a demo server.

There are no retries, redirect following, concurrent probes, ID enumeration, brute force, SSRF, load/race testing, persistence, or automated destructive exploitation. The first HTTP 429 stops all subsequent requests. Ordinary checks also stop on transport failure. Response capture is bounded at 16 KiB; a truncated body is marked incomplete rather than called invalid JSON.

## Authentication evidence

Default quick runs include probes for recognized credentials. Removing a header does not prove the request is anonymous. Successful heuristic probes remain candidates. A strict `--expect-auth` check requires a complete auth contract declaring every credential source. The tool validates and mutates declared header/query/JSON locations together; the fixture author attests that there are no additional credential channels. The result is bounded by that declaration and the expected HTTP rejection, not a claim that a business operation occurred.

Undeclared body credentials can block auth probes. Secret-like body fields are not automatically treated as session credentials: they may be registration or login data. `--auth-body-path` supports explicit exploratory body locations; it does not attest complete authentication coverage.

## IDOR evidence

The IDOR mode uses two controlled identities, two seeded private objects, and an explicit isolation contract. It performs at most five sequential GET requests: two identity checks, two allowed object reads, one cross-account read. It stops on failed prerequisites or 429. It never enumerates objects.

Only same-origin Bearer-only GET is supported. Query strings, cookies, userinfo, fragments, extra headers, ambiguous inputs, and private canaries present in prepared requests are rejected before traffic. The fixture declares that object IDs do not themselves grant access and that the private canaries come from the stored private objects. The tool cannot prove the truth of those application-level declarations.

Disclosure requires both the known object ID and its private canary in the cross-account response. An error status cannot hide disclosed data. Incomplete/ambiguous responses and failed identities are not evidence of protection. Results apply to the exact pair, direction, and read operation; write-IDOR and arbitrary role/tenant policies remain outside the mode.

## Input and artifacts

cURL is parsed as data, never executed by a shell. Unsupported shell syntax, duplicate headers, and unsupported cURL options are rejected. Transport headers that could conflict with the HTTP client are removed.

BreakCurl has no account system, telemetry, or cloud upload. It reads credentials into process memory; response bodies are analyzed in memory and never written to reports. Recognized secrets, explicitly declared credentials, and private IDOR canaries are redacted from reports and replay templates. Synthetic non-secret request values may remain; inspect artifacts before sharing.

The HTML report is a passive local file without scripts, forms, external assets, or network calls, and includes a restrictive CSP. Dynamic HTML and Markdown text is context-escaped; XML and JSON use their own encoding. Only program-generated relative replay links are active. Reports do not execute the replay templates.

## Reporting a vulnerability

Do not put live credentials, personal data, production payloads, or private URLs in public issues. Send a minimal sanitized reproduction using a private GitHub Security Advisory for this repository. Include the affected version, impact, steps, and expected control. Security fixes are provided for the latest published release.
