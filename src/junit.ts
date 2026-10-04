import { englishText } from "./i18n.js";
import { redactText, redactUrl } from "./redact.js";
import { hasWorkingBaseline, summarizeRun } from "./run-summary.js";
import type { CaseResult, RunResult } from "./types.js";

/**
 * Renders the run as a JUnit XML document so CI servers can show per-check
 * results without extra tooling. FAIL becomes <failure>, ERROR becomes
 * <error>, and WARN becomes <skipped> because JUnit has no warning state.
 */
export function formatJunitXml(
  result: RunResult,
  knownSecrets: string[] = [],
): string {
  const cases = result.cases;
  const failures = count(cases, "FAIL");
  const outcome = summarizeRun(result);
  const addRunError = outcome.exitCode === 2 && count(cases, "ERROR") === 0;
  const runErrorDetail = hasWorkingBaseline(result)
    ? `Requests attempted / planned: ${outcome.requestsAttempted} / ${outcome.requestsPlanned ?? "unknown"}.`
    : `Baseline HTTP ${result.baseline.response.status}.`;
  const errors = count(cases, "ERROR") + Number(addRunError);
  const total = cases.length + Number(addRunError);
  const skipped = count(cases, "WARN");
  const time = (
    cases.reduce((total, item) => total + item.response.latencyMs, 0) / 1000
  ).toFixed(3);
  const request = result.baseline.request;
  const classname = redactText(
    `${request.method} ${redactUrl(request.url, knownSecrets)}`,
    knownSecrets,
  );
  const testcases = [
    ...cases.map((item) => formatTestcase(item, classname, knownSecrets)),
    ...(addRunError
      ? [
          `    <testcase name="[run] Run prerequisites and completion" classname="${escapeXml(classname)}" time="0"><error type="run-incomplete" message="${escapeXml(englishText(outcome.title))}">${escapeXml(englishText(outcome.explanation))} ${escapeXml(runErrorDetail)} This is a run control, not an additional HTTP request.</error></testcase>`,
        ]
      : []),
  ].join("\n");

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="breakcurl" tests="${total}" failures="${failures}" errors="${errors}" skipped="${skipped}" time="${time}">`,
    `  <testsuite name="breakcurl ${escapeXml(result.profile ?? "quick")}" tests="${total}" failures="${failures}" errors="${errors}" skipped="${skipped}" time="${time}">`,
    testcases,
    "  </testsuite>",
    "</testsuites>",
    "",
  ]
    .filter((line) => line !== "")
    .join("\n");
}

function formatTestcase(
  item: CaseResult,
  classname: string,
  knownSecrets: string[],
): string {
  const name = `[${item.mutation.category ?? "structure"}] ${redactText(
    englishText(item.mutation.description),
    knownSecrets,
  )}`;
  const time = (item.response.latencyMs / 1000).toFixed(3);
  const head = `    <testcase name="${escapeXml(name)}" classname="${escapeXml(classname)}" time="${time}"`;
  const reason = redactText(englishText(item.reason), knownSecrets);

  if (item.classification === "FAIL") {
    return `${head}>\n      <failure message="${escapeXml(reason)}" type="assertion">${escapeXml(failureDetails(item))}\n      </failure>\n    </testcase>`;
  }
  if (item.classification === "ERROR") {
    return `${head}>\n      <error message="${escapeXml(reason)}" type="error">${escapeXml(failureDetails(item))}\n      </error>\n    </testcase>`;
  }
  if (item.classification === "WARN") {
    return `${head}>\n      <skipped message="${escapeXml(`WARN: ${reason}`)}"/>\n    </testcase>`;
  }
  return `${head}/>`;
}

function failureDetails(item: CaseResult): string {
  const attributes = [
    `classification: ${item.classification}`,
    item.severity ? `severity: ${item.severity}` : undefined,
    item.confidence ? `confidence: ${item.confidence}` : undefined,
    ...(item.securitySignals ?? []).map(
      (signal) => `signal: ${signal.id}${signal.cwe ? ` (${signal.cwe})` : ""}`,
    ),
  ].filter((value): value is string => Boolean(value));
  return attributes.join("\n");
}

function count(cases: CaseResult[], classification: string): number {
  return cases.filter((item) => item.classification === classification).length;
}

export function escapeXml(value: string): string {
  // XML 1.0 forbids these control characters even inside escaped text.
  const printable = value.replace(
    // biome-ignore lint/suspicious/noControlCharactersInRegex: strip characters that are invalid in XML documents
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,
    "",
  );
  return printable
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}
