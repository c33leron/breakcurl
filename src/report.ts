import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { quote } from "shell-quote";
import { responseSchemaFingerprint } from "./classify.js";
import { formatHtmlReport } from "./html-report.js";
import { englishText, message, renderText } from "./i18n.js";
import { formatJunitXml } from "./junit.js";
import { requestForCase } from "./mutations.js";
import {
  collectSensitiveValues,
  redactText,
  sanitizeRequest,
} from "./redact.js";
import { summarizeRun } from "./run-summary.js";
import { isUnsafeTransportHeader } from "./runner.js";
import { formatSarif } from "./sarif.js";
import type {
  CaseResult,
  Classification,
  Language,
  ParsedCurl,
  RunResult,
} from "./types.js";

export interface ReportFiles {
  reportPath: string;
  htmlReportPath: string;
  jsonReportPath: string;
  findingPaths: string[];
  junitPath?: string | undefined;
  sarifPath?: string | undefined;
}

export interface ReportExtras {
  junitPath?: string | undefined;
  sarifPath?: string | undefined;
  /** In-memory values from additional controls; never serialized. */
  knownSecrets?: string[];
}

/** Writes sanitized human and machine-readable reports plus replay cURLs. */
export async function writeReport(
  result: RunResult,
  outputDirectory: string,
  extras: ReportExtras = {},
): Promise<ReportFiles> {
  const findingsDirectory = join(outputDirectory, "findings");
  await mkdir(findingsDirectory, { recursive: true });

  const knownSecrets = [
    ...new Set([
      ...(extras.knownSecrets ?? []),
      ...collectSensitiveValues(result.baseline.request),
      ...result.cases.flatMap((item) =>
        collectSensitiveValues(
          requestForCase(result.baseline.request, item.mutation),
        ),
      ),
    ]),
  ];
  const baselineRequest = sanitizeRequest(
    result.baseline.request,
    knownSecrets,
  );
  const findingPaths: string[] = [];
  const replayByCase = new Map<CaseResult, string>();
  const usedNames = new Set<string>();

  for (const caseResult of result.cases) {
    if (
      caseResult.classification !== "FAIL" &&
      caseResult.classification !== "WARN"
    ) {
      continue;
    }

    const filename = findingFileName(caseResult, usedNames, knownSecrets);
    const filePath = join(findingsDirectory, filename);
    const mutatedRequest = sanitizeRequest(
      requestForCase(result.baseline.request, caseResult.mutation),
      knownSecrets,
    );
    await writeFile(filePath, `${formatCurl(mutatedRequest)}\n`, "utf8");
    findingPaths.push(filePath);
    replayByCase.set(caseResult, `findings/${filename}`);
  }

  const reportPath = join(outputDirectory, "report.md");
  await writeFile(
    reportPath,
    formatReport(result, baselineRequest, replayByCase, knownSecrets),
    "utf8",
  );
  const htmlReportPath = join(outputDirectory, "report.html");
  await writeFile(
    htmlReportPath,
    formatHtmlReport(result, { knownSecrets, replayByCase }),
    "utf8",
  );
  const jsonReportPath = join(outputDirectory, "report.json");
  await writeFile(
    jsonReportPath,
    `${JSON.stringify(formatJsonReport(result, baselineRequest, replayByCase, knownSecrets), (_key, value: unknown) => (typeof value === "string" ? redactText(value, knownSecrets) : value), 2)}\n`,
    "utf8",
  );
  if (extras.junitPath) {
    await writeFile(
      extras.junitPath,
      formatJunitXml(result, knownSecrets),
      "utf8",
    );
  }
  if (extras.sarifPath) {
    await writeFile(
      extras.sarifPath,
      formatSarif(result, knownSecrets),
      "utf8",
    );
  }
  return {
    reportPath,
    htmlReportPath,
    jsonReportPath,
    findingPaths,
    junitPath: extras.junitPath,
    sarifPath: extras.sarifPath,
  };
}

function formatReport(
  result: RunResult,
  baselineRequest: ParsedCurl,
  replayByCase: Map<CaseResult, string>,
  knownSecrets: string[],
): string {
  const baseline = result.baseline.response;
  const findings = result.cases.filter(
    (caseResult) =>
      caseResult.classification === "FAIL" ||
      caseResult.classification === "WARN" ||
      caseResult.classification === "ERROR",
  );
  const summary = countByClassification(result.cases);
  const language = result.language ?? "en";
  const outcome = summarizeRun(result);
  const outcomeText = (value: string) =>
    escapeCell(redactText(value, knownSecrets));

  const allCases =
    result.cases.length === 0
      ? message(
          language,
          "_No checks were executed._",
          "_Проверки не выполнялись._",
        )
      : [
          message(
            language,
            "| Result | Risk | Category | Check | Expectation | HTTP | Reason | Replay |",
            "| Результат | Риск | Категория | Проверка | Ожидание | HTTP | Причина | Повтор |",
          ),
          "| --- | --- | --- | --- | --- | ---: | --- | --- |",
          ...result.cases.map((caseResult) =>
            formatCaseRow(
              caseResult,
              replayByCase.get(caseResult),
              knownSecrets,
              language,
            ),
          ),
        ].join("\n");

  const findingsSection =
    findings.length === 0
      ? message(
          language,
          "_No FAIL, WARN, or ERROR results._",
          "_Результаты FAIL, WARN и ERROR отсутствуют._",
        )
      : findings
          .map((caseResult) =>
            formatFinding(
              caseResult,
              replayByCase.get(caseResult),
              knownSecrets,
              language,
            ),
          )
          .join("\n");

  const notes =
    result.notes && result.notes.length > 0
      ? [
          "",
          message(language, "## Run limitations", "## Ограничения запуска"),
          "",
          ...result.notes.map(
            (note) =>
              `- ${escapeCell(redactText(renderText(note, language), knownSecrets))}`,
          ),
        ]
      : [];

  return [
    message(language, "# BreakCurl report", "# Отчёт BreakCurl"),
    "",
    `## ${outcomeText(renderText(outcome.title, language))}`,
    "",
    outcomeText(renderText(outcome.explanation, language)),
    "",
    `${message(language, "Next action", "Следующее действие")}: ${outcomeText(renderText(outcome.nextAction, language))}`,
    "",
    message(language, "## Target", "## Цель"),
    "",
    message(
      language,
      `- Method: ${escapeCell(redactText(baselineRequest.method, knownSecrets))}`,
      `- Метод: ${escapeCell(redactText(baselineRequest.method, knownSecrets))}`,
    ),
    `- URL: ${escapeCell(redactText(baselineRequest.url, knownSecrets))}`,
    message(
      language,
      `- Profile: ${escapeCell(redactText(result.profile ?? "quick", knownSecrets))}`,
      `- Профиль: ${escapeCell(redactText(result.profile ?? "quick", knownSecrets))}`,
    ),
    message(
      language,
      `- Mode: ${escapeCell(redactText(result.mode ?? "checks", knownSecrets))}`,
      `- Режим: ${escapeCell(redactText(result.mode ?? "checks", knownSecrets))}`,
    ),
    ...(result.completedRequests !== undefined ||
    result.plannedRequests !== undefined
      ? [
          message(
            language,
            `- Requests attempted / planned: ${outcome.requestsAttempted} / ${outcome.requestsPlanned ?? "—"}`,
            `- Запросов начато / запланировано: ${outcome.requestsAttempted} / ${outcome.requestsPlanned ?? "—"}`,
          ),
        ]
      : []),
    "",
    message(language, "## Baseline request", "## Исходный запрос"),
    "",
    message(
      language,
      `- HTTP ${baseline.status} in ${baseline.latencyMs} ms`,
      `- HTTP ${baseline.status} за ${baseline.latencyMs} мс`,
    ),
    message(
      language,
      `- Contract fingerprint: ${responseSchemaFingerprint(baseline) ?? (baseline.bodyOmitted ? "omitted for privacy" : "unavailable (incomplete response)")}`,
      `- Fingerprint контракта: ${responseSchemaFingerprint(baseline) ?? (baseline.bodyOmitted ? "не сохраняется для защиты приватных данных" : "недоступен (неполный ответ)")}`,
    ),
    ...(result.baseline.assessment
      ? [
          "",
          message(
            language,
            "### Baseline assessment",
            "### Оценка исходного запроса",
          ),
          "",
          `- **${escapeCell(redactText(result.baseline.assessment.classification, knownSecrets))}** ${escapeCell(redactText(renderText(result.baseline.assessment.reason, language), knownSecrets))}`,
          ...(result.baseline.assessment.securitySignals ?? []).map(
            (signal) =>
              `- ${escapeCell(redactText(renderText(signal.title, language), knownSecrets))}${signal.cwe ? ` (${escapeCell(redactText(signal.cwe, knownSecrets))})` : ""}`,
          ),
          "",
          message(
            language,
            "Uses the existing baseline response; no additional request was sent.",
            "Используется уже полученный исходный ответ; дополнительный запрос не отправлялся.",
          ),
        ]
      : []),
    "",
    message(language, "## All checks", "## Все проверки"),
    "",
    allCases,
    "",
    message(language, "## Findings", "## Находки"),
    "",
    findingsSection,
    ...notes,
    "",
    message(language, "## Summary", "## Итог"),
    "",
    message(
      language,
      `Checks: ${result.cases.length}; FAIL: ${summary.FAIL}; WARN: ${summary.WARN}; INFO: ${summary.INFO}; PASS: ${summary.PASS}; ERROR: ${summary.ERROR}.`,
      `Проверок: ${result.cases.length}; FAIL: ${summary.FAIL}; WARN: ${summary.WARN}; INFO: ${summary.INFO}; PASS: ${summary.PASS}; ERROR: ${summary.ERROR}.`,
    ),
    "",
    message(
      language,
      "API response bodies and secrets were not written to the report. The fingerprint uses only the status and response structure.",
      "Ответы API и секреты не записывались в отчёт. Fingerprint построен только по статусу и структуре ответа.",
    ),
    message(
      language,
      "Results apply only to the executed requests and do not establish that the entire API is secure. Fingerprints are unavailable for incomplete responses; equal fingerprints do not prove equal objects or authorized access.",
      "Результаты относятся только к выполненным запросам и не доказывают безопасность всего API. Fingerprint недоступен для неполных ответов; совпадение fingerprint не доказывает совпадение объектов или разрешенный доступ.",
    ),
    "",
  ].join("\n");
}

function formatCaseRow(
  caseResult: CaseResult,
  replayPath: string | undefined,
  knownSecrets: string[],
  language: Language,
): string {
  const response = caseResult.response;
  const http = response.status === 0 ? "—" : String(response.status);
  const replay = replayPath
    ? `[${message(language, "replay", "повтор")}](${toMarkdownPath(replayPath)})`
    : "—";
  return [
    escapeCell(redactText(caseResult.classification, knownSecrets)),
    escapeCell(redactText(caseResult.severity ?? "—", knownSecrets)),
    escapeCell(
      redactText(caseResult.mutation.category ?? "negative", knownSecrets),
    ),
    escapeCell(
      redactText(
        renderText(caseResult.mutation.description, language),
        knownSecrets,
      ),
    ),
    escapeCell(
      redactText(caseResult.mutation.expectation ?? "legacy", knownSecrets),
    ),
    http,
    escapeCell(
      redactText(renderText(caseResult.reason, language), knownSecrets),
    ),
    replay,
  ]
    .join(" | ")
    .replace(/^/, "| ")
    .replace(/$/, " |");
}

function formatFinding(
  caseResult: CaseResult,
  replayPath: string | undefined,
  knownSecrets: string[],
  language: Language,
): string {
  const replayText = replayPath
    ? message(
        language,
        ` — [sanitized replay cURL](${toMarkdownPath(replayPath)})`,
        ` — [безопасный cURL для повтора](${toMarkdownPath(replayPath)})`,
      )
    : "";
  const attributes = [
    caseResult.severity
      ? message(
          language,
          `risk ${caseResult.severity}`,
          `риск ${caseResult.severity}`,
        )
      : undefined,
    caseResult.confidence
      ? message(
          language,
          `confidence ${caseResult.confidence}`,
          `уверенность ${caseResult.confidence}`,
        )
      : undefined,
    ...(caseResult.securitySignals ?? []).map((signal) => signal.cwe),
  ].filter((item): item is string => Boolean(item));
  const suffix =
    attributes.length > 0
      ? ` (${escapeCell(redactText(attributes.join(", "), knownSecrets))})`
      : "";
  return `- **${escapeCell(redactText(caseResult.classification, knownSecrets))}** ${escapeCell(redactText(renderText(caseResult.mutation.description, language), knownSecrets))}: ${escapeCell(redactText(renderText(caseResult.reason, language), knownSecrets))}${suffix}${replayText}`;
}

function formatJsonReport(
  result: RunResult,
  baselineRequest: ParsedCurl,
  replayByCase: Map<CaseResult, string>,
  knownSecrets: string[],
): Record<string, unknown> {
  const outcome = summarizeRun(result);
  return {
    schemaVersion: 1,
    language: "en",
    profile: result.profile ?? "quick",
    mode: result.mode ?? "checks",
    outcome: {
      ...outcome,
      title: englishText(outcome.title),
      explanation: englishText(outcome.explanation),
      nextAction: englishText(outcome.nextAction),
    },
    plannedRequests: result.plannedRequests ?? null,
    completedRequests: result.completedRequests ?? null,
    target: {
      method: baselineRequest.method,
      url: baselineRequest.url,
    },
    baseline: {
      status: result.baseline.response.status,
      latencyMs: result.baseline.response.latencyMs,
      schemaFingerprint: responseSchemaFingerprint(result.baseline.response),
      bodyTruncated: result.baseline.response.bodyTruncated ?? null,
      bodyOmitted: result.baseline.response.bodyOmitted ?? false,
      timedOut: result.baseline.response.timedOut,
      transportError: Boolean(result.baseline.response.connectionError),
      assessment: result.baseline.assessment
        ? {
            classification: result.baseline.assessment.classification,
            reason: redactText(
              englishText(result.baseline.assessment.reason),
              knownSecrets,
            ),
            severity: result.baseline.assessment.severity ?? null,
            confidence: result.baseline.assessment.confidence ?? null,
            securitySignals: (
              result.baseline.assessment.securitySignals ?? []
            ).map((signal) => ({
              id: redactText(signal.id, knownSecrets),
              title: redactText(englishText(signal.title), knownSecrets),
              severity: signal.severity,
              cwe: signal.cwe ? redactText(signal.cwe, knownSecrets) : null,
            })),
          }
        : null,
    },
    summary: countByClassification(result.cases),
    notes: (result.notes ?? []).map((note) =>
      redactText(englishText(note), knownSecrets),
    ),
    cases: result.cases.map((caseResult) => ({
      id: redactText(caseResult.mutation.id, knownSecrets),
      category: caseResult.mutation.category ?? "negative",
      expectation: caseResult.mutation.expectation ?? "legacy",
      classification: caseResult.classification,
      severity: caseResult.severity ?? null,
      confidence: caseResult.confidence ?? null,
      description: redactText(
        englishText(caseResult.mutation.description),
        knownSecrets,
      ),
      status: caseResult.response.status,
      latencyMs: caseResult.response.latencyMs,
      reason: redactText(englishText(caseResult.reason), knownSecrets),
      schemaFingerprint: responseSchemaFingerprint(caseResult.response),
      bodyTruncated: caseResult.response.bodyTruncated ?? null,
      bodyOmitted: caseResult.response.bodyOmitted ?? false,
      timedOut: caseResult.response.timedOut,
      transportError: Boolean(caseResult.response.connectionError),
      securitySignals: (caseResult.securitySignals ?? []).map((signal) => ({
        id: redactText(signal.id, knownSecrets),
        title: redactText(englishText(signal.title), knownSecrets),
        severity: signal.severity,
        cwe: signal.cwe ? redactText(signal.cwe, knownSecrets) : null,
      })),
      replay: replayByCase.get(caseResult) ?? null,
    })),
  };
}

function formatCurl(request: ParsedCurl): string {
  const lines = [`curl -X ${request.method} ${shellQuote(request.url)}`];
  const replayHeaders = Object.entries(request.headers)
    .filter(([name]) => !isUnsafeTransportHeader(name))
    .sort(([left], [right]) => left.localeCompare(right));
  for (const [name, value] of replayHeaders) {
    lines.push(`  -H ${shellQuote(`${name}: ${value}`)}`);
  }
  if (request.method !== "GET") {
    lines.push(`  --data-raw ${shellQuote(JSON.stringify(request.body))}`);
  }
  return lines.join(" \\\n");
}

function shellQuote(value: string): string {
  return quote([value]);
}

function findingFileName(
  caseResult: CaseResult,
  usedNames: Set<string>,
  knownSecrets: string[],
): string {
  const status = caseResult.classification.toLowerCase();
  const path =
    redactText(caseResult.mutation.path, knownSecrets)
      .replace(/^\$(?:\.|\[)/, "")
      .replace(/[^A-Za-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .toLowerCase() || "field";
  const kind = caseResult.mutation.kind
    .replace(/[^a-z0-9]+/gi, "-")
    .toLowerCase();
  const base = `${status}-${path}-${kind}`;
  let candidate = `${base}.curl`;
  let suffix = 2;
  while (usedNames.has(candidate)) {
    candidate = `${base}-${suffix}.curl`;
    suffix += 1;
  }
  usedNames.add(candidate);
  return candidate;
}

function countByClassification(
  cases: CaseResult[],
): Record<Classification, number> {
  const counts: Record<Classification, number> = {
    PASS: 0,
    INFO: 0,
    WARN: 0,
    FAIL: 0,
    ERROR: 0,
  };
  for (const caseResult of cases) counts[caseResult.classification] += 1;
  return counts;
}

function escapeCell(value: string): string {
  // Encode Markdown metacharacters as entities so untrusted labels cannot
  // introduce links, images, raw HTML, code spans, or new table rows.
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replace(
      /[\\`[\]!*_{}()#~|:@]/g,
      (character) => `&#${character.charCodeAt(0)};`,
    )
    .replace(/\bwww\./gi, (prefix) => `${prefix.slice(0, -1)}&#46;`)
    .replace(/[\r\n\u2028\u2029]/g, " ");
}

function toMarkdownPath(value: string): string {
  return value
    .split("\\")
    .join("/")
    .split("/")
    .map(encodeURIComponent)
    .join("/");
}
