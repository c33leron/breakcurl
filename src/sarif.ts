import { englishText } from "./i18n.js";
import { redactText, redactUrl } from "./redact.js";
import { hasWorkingBaseline, summarizeRun } from "./run-summary.js";
import type {
  CaseResult,
  Classification,
  FindingSeverity,
  RunResult,
  SecuritySignal,
} from "./types.js";
import { VERSION } from "./version.js";

const REPOSITORY_URI = "https://github.com/c33leron/BreakCurl";
const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

interface RuleMetadata {
  short: string;
  cwe?: string;
}

/**
 * Stable rule identities for findings that have no dedicated SecuritySignal.
 * Signal-driven findings reuse the signal id (for example
 * "authentication-not-enforced").
 */
const RULES: Record<string, RuleMetadata> = {
  "idor-private-object-disclosure": {
    short:
      "A controlled identity received another private object's ID and canary contrary to the declared isolation contract.",
    cwe: "CWE-639",
  },
  "authentication-not-enforced": {
    short:
      "A declared authentication rejection contract was not observed; resource access requires separate evidence.",
    cwe: "CWE-306",
  },
  "internal-details": {
    short: "The response exposes stack traces or internal paths.",
    cwe: "CWE-209",
  },
  "database-error": {
    short: "The response exposes database or ORM error details.",
    cwe: "CWE-209",
  },
  "secret-exposure": {
    short: "The response may contain credentials or private keys.",
    cwe: "CWE-200",
  },
  "html-reflection": {
    short: "Markup probes are reflected unescaped in HTML responses.",
    cwe: "CWE-79",
  },
  "technology-header": {
    short: "The response exposes implementation technology headers.",
    cwe: "CWE-200",
  },
  "jwt-signature-not-enforced": {
    short:
      "The endpoint accepted a JWT with a broken signature (alg=none, stripped, or tampered claims).",
    cwe: "CWE-347",
  },
  "jwt-auth-rejection-missing": {
    short:
      "A tampered JWT did not receive an authentication rejection; signature bypass requires separate evidence.",
    cwe: "CWE-347",
  },
  "jwt-expiry-not-enforced": {
    short: "The endpoint accepted an expired JWT.",
    cwe: "CWE-613",
  },
  "mass-assignment-accepted": {
    short:
      "An injected privileged field was accepted into the payload (mass assignment).",
    cwe: "CWE-915",
  },
  "unexpected-method-accepted": {
    short:
      "The endpoint processed the request under an unexpected HTTP method.",
    cwe: "CWE-284",
  },
  "api-spec-exposure": {
    short: "An API specification is exposed without authentication.",
    cwe: "CWE-200",
  },
  "cors-wildcard-credentials": {
    short:
      "The CORS wildcard and credentials combination is invalid for credentialed browser access.",
    cwe: "CWE-942",
  },
  "cookie-flags-missing": {
    short: "Set-Cookie lacks the Secure or HttpOnly protection.",
    cwe: "CWE-614",
  },
  "hsts-missing": {
    short: "The HTTPS response does not enforce HSTS.",
    cwe: "CWE-319",
  },
  "server-version-header": {
    short: "The Server header reveals an implementation version.",
    cwe: "CWE-200",
  },
  "password-hash-exposure": {
    short: "The response exposes a password or secret hash.",
    cwe: "CWE-200",
  },
  "sensitive-field-response": {
    short: "The response returns a value for a sensitive-named field.",
    cwe: "CWE-200",
  },
  "structure-finding": {
    short: "A mutated JSON structure was not handled as expected.",
  },
  "boundary-finding": {
    short: "A boundary value produced unexpected or unsafe behavior.",
  },
  "protocol-finding": {
    short: "An HTTP protocol-level check behaved unexpectedly.",
  },
  "injection-finding": {
    short: "A constrained injection probe produced a suspicious response.",
  },
  "authentication-finding": {
    short: "An authentication check behaved unexpectedly.",
  },
  "custom-finding": {
    short: "A user-defined check produced a finding.",
  },
  "baseline-finding": {
    short: "The original request did not pass its response control.",
  },
};

const CONTRACT_FAILURE_SIGNALS = new Set([
  "idor-private-object-disclosure",
  "authentication-not-enforced",
  "jwt-auth-rejection-missing",
  "jwt-signature-not-enforced",
  "jwt-expiry-not-enforced",
]);

interface SarifFinding {
  item: CaseResult;
  ruleId: string;
  classification: Classification;
  severity?: FindingSeverity;
  signal?: SecuritySignal;
  baseline: boolean;
}

/**
 * Renders baseline and case findings as SARIF 2.1.0 for GitHub code scanning.
 * Each security signal retains its own rule and severity; PASS and INFO are
 * omitted so the Security tab stays clean.
 */
export function formatSarif(
  result: RunResult,
  knownSecrets: string[] = [],
): string {
  const baselineAssessment = result.baseline.assessment;
  const findings = [
    ...(baselineAssessment
      ? findingsFor(
          {
            mutation: {
              id: "baseline",
              path: "$",
              description: "Baseline response",
              kind: "custom-set",
              category: "protocol",
              body: result.baseline.request.body,
            },
            response: result.baseline.response,
            ...baselineAssessment,
          },
          true,
        )
      : []),
    ...result.cases.flatMap((item) => findingsFor(item, false)),
  ];
  const ruleIds = [...new Set(findings.map((finding) => finding.ruleId))];
  // GitHub code scanning expects one security-severity per rule; use the
  // strongest severity observed for it instead of a hardcoded CWE guess.
  const severityByRule = new Map<string, string>();
  for (const finding of findings) {
    if (!finding.severity) continue;
    const severity = securitySeverity(finding.severity);
    if (Number(severity) > Number(severityByRule.get(finding.ruleId) ?? 0)) {
      severityByRule.set(finding.ruleId, severity);
    }
  }
  const baselineUrl = result.baseline.request.url;
  const outcome = summarizeRun(result);
  const runErrorDetail = hasWorkingBaseline(result)
    ? `Requests attempted / planned: ${outcome.requestsAttempted} / ${outcome.requestsPlanned ?? "unknown"}.`
    : `Baseline HTTP ${result.baseline.response.status}.`;

  return `${JSON.stringify(
    {
      $schema: SARIF_SCHEMA,
      version: "2.1.0",
      runs: [
        {
          invocations: [
            {
              executionSuccessful: outcome.exitCode !== 2,
              ...(outcome.exitCode === 2
                ? {
                    toolExecutionNotifications: [
                      {
                        level: "error",
                        message: {
                          text: `${englishText(outcome.explanation)} ${runErrorDetail}`,
                        },
                      },
                    ],
                  }
                : {}),
            },
          ],
          tool: {
            driver: {
              name: "BreakCurl",
              version: VERSION,
              informationUri: REPOSITORY_URI,
              rules: ruleIds.map((id) =>
                formatRule(
                  id,
                  knownSecrets,
                  severityByRule.get(id),
                  findings.find((finding) => finding.ruleId === id)?.signal,
                ),
              ),
            },
          },
          results: findings.map((finding) =>
            formatResult(finding, baselineUrl, knownSecrets),
          ),
        },
      ],
    },
    null,
    2,
  )}\n`;
}

function findingsFor(item: CaseResult, baseline: boolean): SarifFinding[] {
  if (!["FAIL", "WARN", "ERROR"].includes(item.classification)) return [];
  const signals = (item.securitySignals ?? []).filter(
    (signal) => signal.id !== "technology-header",
  );
  // Response observations must not inherit a server/transport failure's
  // classification or aggregate severity. Keep that primary outcome separate.
  const operationalFailure =
    item.classification === "ERROR" ||
    (item.classification === "FAIL" &&
      (item.response.status >= 500 ||
        !signals.some((signal) => CONTRACT_FAILURE_SIGNALS.has(signal.id))));
  const findings: SarifFinding[] = [];
  if (signals.length === 0 || operationalFailure) {
    findings.push({
      item,
      ruleId: baseline
        ? "baseline-finding"
        : `${item.mutation.category ?? "structure"}-finding`,
      classification: item.classification,
      ...(item.severity ? { severity: item.severity } : {}),
      baseline,
    });
  }
  for (const signal of signals) {
    findings.push({
      item,
      ruleId: signal.id,
      classification:
        item.classification === "FAIL" &&
        !operationalFailure &&
        CONTRACT_FAILURE_SIGNALS.has(signal.id)
          ? "FAIL"
          : "WARN",
      severity: signal.severity,
      signal,
      baseline,
    });
  }
  return findings;
}

function formatRule(
  id: string,
  knownSecrets: string[],
  securitySeverityOverride?: string,
  signal?: SecuritySignal,
): Record<string, unknown> {
  const builtInRule = Object.hasOwn(RULES, id) ? RULES[id] : undefined;
  const rule = builtInRule ?? {
    short: signal
      ? redactText(englishText(signal.title), knownSecrets)
      : "BreakCurl check produced a finding.",
    ...(signal?.cwe ? { cwe: redactText(signal.cwe, knownSecrets) } : {}),
  };
  return {
    id: sanitizedRuleId(id, knownSecrets),
    shortDescription: { text: rule.short },
    ...(rule.cwe ? { helpUri: cweUri(rule.cwe) } : {}),
    properties: {
      ...(rule.cwe
        ? { "security-severity": securitySeverityOverride ?? "5.0" }
        : {}),
    },
  };
}

function cweUri(cwe: string): string {
  const number = cwe.replace(/^CWE-/, "");
  return `https://cwe.mitre.org/data/definitions/${encodeURIComponent(number)}.html`;
}

function securitySeverity(severity: "LOW" | "MEDIUM" | "HIGH"): string {
  if (severity === "HIGH") return "8.1";
  if (severity === "MEDIUM") return "5.0";
  return "2.5";
}

function formatResult(
  finding: SarifFinding,
  baselineUrl: string,
  knownSecrets: string[],
): Record<string, unknown> {
  const { item, signal } = finding;
  const description = redactText(
    englishText(item.mutation.description),
    knownSecrets,
  );
  const reason = redactText(
    englishText(
      signal && !CONTRACT_FAILURE_SIGNALS.has(signal.id)
        ? signal.title
        : item.reason,
    ),
    knownSecrets,
  );
  const url = redactArtifactUrl(item.mutation.url ?? baselineUrl, knownSecrets);
  return {
    ruleId: sanitizedRuleId(finding.ruleId, knownSecrets),
    level: levelFor(finding.classification),
    message: { text: `${description}: ${reason}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: url },
        },
      },
    ],
    partialFingerprints: {
      "breakcurlCaseId/v1": redactText(item.mutation.id, knownSecrets),
      "breakcurlFindingId/v1": `${redactText(item.mutation.id, knownSecrets)}:${sanitizedRuleId(finding.ruleId, knownSecrets)}`,
    },
    properties: {
      "breakcurl/classification": finding.classification,
      "breakcurl/category": item.mutation.category ?? "structure",
      "breakcurl/source": finding.baseline ? "baseline" : "case",
      "breakcurl/http-status": item.response.status,
      ...(finding.severity ? { "breakcurl/severity": finding.severity } : {}),
      ...(item.confidence ? { "breakcurl/confidence": item.confidence } : {}),
      ...(signal?.cwe
        ? { "breakcurl/cwe": redactText(signal.cwe, knownSecrets) }
        : {}),
      ...(signal?.owasp
        ? { "breakcurl/owasp": redactText(signal.owasp, knownSecrets) }
        : {}),
    },
  };
}

function levelFor(classification: string): "error" | "warning" | "note" {
  if (classification === "FAIL" || classification === "ERROR") return "error";
  if (classification === "WARN") return "warning";
  return "note";
}

function sanitizedRuleId(id: string, knownSecrets: string[]): string {
  return Object.hasOwn(RULES, id) ? id : redactText(id, knownSecrets);
}

function redactArtifactUrl(url: string, knownSecrets: string[]): string {
  const redacted = redactUrl(url, knownSecrets);
  const protocol = url.match(/^[a-z][a-z0-9+.-]*:/i)?.[0];
  if (!protocol) return redacted;
  // The URL scheme is syntax, even when a credential happens to be "https".
  const redactedProtocol = redactText(protocol, knownSecrets);
  return redacted.startsWith(redactedProtocol)
    ? protocol + redacted.slice(redactedProtocol.length)
    : redacted;
}
