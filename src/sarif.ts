import { englishText } from "./i18n.js";
import { redactText, redactUrl } from "./redact.js";
import type { CaseResult, RunResult } from "./types.js";
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
  "authentication-not-enforced": {
    short: "The endpoint responds successfully without valid credentials.",
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
};

/**
 * Renders FAIL, WARN, and ERROR cases as SARIF 2.1.0 for GitHub code
 * scanning. PASS and INFO are omitted so the Security tab stays clean.
 */
export function formatSarif(
  result: RunResult,
  knownSecrets: string[] = [],
): string {
  const findings = result.cases.filter((item) =>
    ["FAIL", "WARN", "ERROR"].includes(item.classification),
  );
  const ruleIds = [...new Set(findings.map((item) => ruleIdFor(item)))];
  const baselineUrl = result.baseline.request.url;

  return `${JSON.stringify(
    {
      $schema: SARIF_SCHEMA,
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "BreakCurl",
              version: VERSION,
              informationUri: REPOSITORY_URI,
              rules: ruleIds.map((id) => formatRule(id)),
            },
          },
          results: findings.map((item) =>
            formatResult(item, baselineUrl, knownSecrets),
          ),
        },
      ],
    },
    null,
    2,
  )}\n`;
}

function ruleIdFor(item: CaseResult): string {
  const signal = item.securitySignals?.[0]?.id;
  if (signal) return signal;
  return `${item.mutation.category ?? "structure"}-finding`;
}

function formatRule(id: string): Record<string, unknown> {
  const rule = RULES[id] ?? { short: "BreakCurl check produced a finding." };
  return {
    id,
    shortDescription: { text: rule.short },
    ...(rule.cwe ? { helpUri: cweUri(rule.cwe) } : {}),
    properties: {
      ...(rule.cwe ? { "security-severity": securitySeverity(id) } : {}),
    },
  };
}

function cweUri(cwe: string): string {
  const number = cwe.replace(/^CWE-/, "");
  return `https://cwe.mitre.org/data/definitions/${number}.html`;
}

function securitySeverity(id: string): string {
  return RULES[id]?.cwe === "CWE-306" ? "8.1" : "5.0";
}

function formatResult(
  item: CaseResult,
  baselineUrl: string,
  knownSecrets: string[],
): Record<string, unknown> {
  const description = redactText(
    englishText(item.mutation.description),
    knownSecrets,
  );
  const reason = redactText(englishText(item.reason), knownSecrets);
  const url = redactUrl(item.mutation.url ?? baselineUrl, knownSecrets);
  const signal = item.securitySignals?.[0];
  return {
    ruleId: ruleIdFor(item),
    level: levelFor(item.classification),
    message: { text: `${description}: ${reason}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: url },
        },
      },
    ],
    partialFingerprints: { "breakcurlCaseId/v1": item.mutation.id },
    properties: {
      "breakcurl/classification": item.classification,
      "breakcurl/category": item.mutation.category ?? "structure",
      "breakcurl/http-status": item.response.status,
      ...(item.severity ? { "breakcurl/severity": item.severity } : {}),
      ...(item.confidence ? { "breakcurl/confidence": item.confidence } : {}),
      ...(signal?.cwe ? { "breakcurl/cwe": signal.cwe } : {}),
    },
  };
}

function levelFor(classification: string): "error" | "warning" | "note" {
  if (classification === "FAIL") return "error";
  if (classification === "WARN") return "warning";
  return "note";
}
