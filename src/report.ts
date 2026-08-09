import { mkdir, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { quote } from "shell-quote";
import { responseSchemaFingerprint } from "./classify.js";
import { requestForCase } from "./mutations.js";
import {
  collectSensitiveValues,
  redactText,
  sanitizeRequest,
} from "./redact.js";
import { isUnsafeTransportHeader } from "./runner.js";
import type {
  CaseResult,
  Classification,
  ParsedCurl,
  RunResult,
} from "./types.js";

export interface ReportFiles {
  reportPath: string;
  jsonReportPath: string;
  findingPaths: string[];
}

/** Writes sanitized human and machine-readable reports plus replay cURLs. */
export async function writeReport(
  result: RunResult,
  outputDirectory: string,
): Promise<ReportFiles> {
  const findingsDirectory = join(outputDirectory, "findings");
  await mkdir(findingsDirectory, { recursive: true });

  const knownSecrets = collectSensitiveValues(result.baseline.request);
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

    const filename = findingFileName(caseResult, usedNames);
    const filePath = join(findingsDirectory, filename);
    const mutatedRequest = sanitizeRequest(
      requestForCase(result.baseline.request, caseResult.mutation),
      knownSecrets,
    );
    await writeFile(filePath, `${formatCurl(mutatedRequest)}\n`, "utf8");
    findingPaths.push(filePath);
    replayByCase.set(caseResult, relative(outputDirectory, filePath));
  }

  const reportPath = join(outputDirectory, "report.md");
  await writeFile(
    reportPath,
    formatReport(result, baselineRequest, replayByCase, knownSecrets),
    "utf8",
  );
  const jsonReportPath = join(outputDirectory, "report.json");
  await writeFile(
    jsonReportPath,
    `${JSON.stringify(formatJsonReport(result, baselineRequest, replayByCase, knownSecrets), null, 2)}\n`,
    "utf8",
  );
  return { reportPath, jsonReportPath, findingPaths };
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
      caseResult.classification === "WARN",
  );
  const summary = countByClassification(result.cases);

  const allCases =
    result.cases.length === 0
      ? "_Проверки не выполнялись._"
      : [
          "| Результат | Риск | Категория | Проверка | Ожидание | HTTP | Причина | Fingerprint | Повтор |",
          "| --- | --- | --- | --- | --- | ---: | --- | --- | --- |",
          ...result.cases.map((caseResult) =>
            formatCaseRow(
              caseResult,
              replayByCase.get(caseResult),
              knownSecrets,
            ),
          ),
        ].join("\n");

  const findingsSection =
    findings.length === 0
      ? "_Находки FAIL и WARN отсутствуют._"
      : findings
          .map((caseResult) =>
            formatFinding(
              caseResult,
              replayByCase.get(caseResult),
              knownSecrets,
            ),
          )
          .join("\n");

  const notes =
    result.notes && result.notes.length > 0
      ? [
          "",
          "## Ограничения запуска",
          "",
          ...result.notes.map(
            (note) => `- ${escapeCell(redactText(note, knownSecrets))}`,
          ),
        ]
      : [];

  return [
    "# Отчёт BreakCurl",
    "",
    "## Цель",
    "",
    `- Метод: \`${baselineRequest.method}\``,
    `- URL: \`${baselineRequest.url}\``,
    `- Профиль: \`${result.profile ?? "quick"}\``,
    "",
    "## Исходный запрос",
    "",
    `- HTTP ${baseline.status} за ${baseline.latencyMs} мс`,
    `- Fingerprint контракта: \`${responseSchemaFingerprint(baseline)}\``,
    "",
    "## Все проверки",
    "",
    allCases,
    "",
    "## Находки",
    "",
    findingsSection,
    ...notes,
    "",
    "## Итог",
    "",
    `Проверок: ${result.cases.length}; FAIL: ${summary.FAIL}; WARN: ${summary.WARN}; INFO: ${summary.INFO}; PASS: ${summary.PASS}; ERROR: ${summary.ERROR}.`,
    "",
    "Ответы API и секреты не записывались в отчёт. Fingerprint построен только по статусу и структуре ответа.",
    "",
  ].join("\n");
}

function formatCaseRow(
  caseResult: CaseResult,
  replayPath: string | undefined,
  knownSecrets: string[],
): string {
  const response = caseResult.response;
  const http = response.status === 0 ? "—" : String(response.status);
  const replay = replayPath ? `[повтор](${toMarkdownPath(replayPath)})` : "—";
  return [
    caseResult.classification,
    caseResult.severity ?? "—",
    caseResult.mutation.category ?? "negative",
    escapeCell(redactText(caseResult.mutation.description, knownSecrets)),
    caseResult.mutation.expectation ?? "legacy",
    http,
    escapeCell(redactText(caseResult.reason, knownSecrets)),
    responseSchemaFingerprint(response),
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
): string {
  const replayText = replayPath
    ? ` — [безопасный cURL для повтора](${toMarkdownPath(replayPath)})`
    : "";
  const attributes = [
    caseResult.severity ? `риск ${caseResult.severity}` : undefined,
    caseResult.confidence ? `уверенность ${caseResult.confidence}` : undefined,
    ...(caseResult.securitySignals ?? []).map((signal) => signal.cwe),
  ].filter((item): item is string => Boolean(item));
  const suffix = attributes.length > 0 ? ` (${attributes.join(", ")})` : "";
  return `- **${caseResult.classification}** ${escapeCell(redactText(caseResult.mutation.description, knownSecrets))}: ${escapeCell(redactText(caseResult.reason, knownSecrets))}${suffix}${replayText}`;
}

function formatJsonReport(
  result: RunResult,
  baselineRequest: ParsedCurl,
  replayByCase: Map<CaseResult, string>,
  knownSecrets: string[],
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    profile: result.profile ?? "quick",
    target: {
      method: baselineRequest.method,
      url: baselineRequest.url,
    },
    baseline: {
      status: result.baseline.response.status,
      latencyMs: result.baseline.response.latencyMs,
      schemaFingerprint: responseSchemaFingerprint(result.baseline.response),
    },
    summary: countByClassification(result.cases),
    notes: (result.notes ?? []).map((note) => redactText(note, knownSecrets)),
    cases: result.cases.map((caseResult) => ({
      id: caseResult.mutation.id,
      category: caseResult.mutation.category ?? "negative",
      expectation: caseResult.mutation.expectation ?? "legacy",
      classification: caseResult.classification,
      severity: caseResult.severity ?? null,
      confidence: caseResult.confidence ?? null,
      description: redactText(caseResult.mutation.description, knownSecrets),
      status: caseResult.response.status,
      latencyMs: caseResult.response.latencyMs,
      reason: redactText(caseResult.reason, knownSecrets),
      schemaFingerprint: responseSchemaFingerprint(caseResult.response),
      securitySignals: (caseResult.securitySignals ?? []).map((signal) => ({
        id: signal.id,
        title: signal.title,
        severity: signal.severity,
        cwe: signal.cwe ?? null,
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
  lines.push(`  --data-raw ${shellQuote(JSON.stringify(request.body))}`);
  return lines.join(" \\\n");
}

function shellQuote(value: string): string {
  return quote([value]);
}

function findingFileName(
  caseResult: CaseResult,
  usedNames: Set<string>,
): string {
  const status = caseResult.classification.toLowerCase();
  const path =
    caseResult.mutation.path
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
  return value.replaceAll("|", "\\|").replaceAll("\n", " ");
}

function toMarkdownPath(value: string): string {
  return value.split("\\").join("/");
}
