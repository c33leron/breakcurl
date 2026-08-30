import { mkdir, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { quote } from "shell-quote";
import { responseSchemaFingerprint } from "./classify.js";
import { englishText, message, renderText } from "./i18n.js";
import { formatJunitXml } from "./junit.js";
import { requestForCase } from "./mutations.js";
import {
  collectSensitiveValues,
  redactText,
  sanitizeRequest,
} from "./redact.js";
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
  jsonReportPath: string;
  findingPaths: string[];
  junitPath?: string | undefined;
  sarifPath?: string | undefined;
}

export interface ReportExtras {
  junitPath?: string | undefined;
  sarifPath?: string | undefined;
}

/** Writes sanitized human and machine-readable reports plus replay cURLs. */
export async function writeReport(
  result: RunResult,
  outputDirectory: string,
  extras: ReportExtras = {},
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
      caseResult.classification === "WARN",
  );
  const summary = countByClassification(result.cases);
  const language = result.language ?? "en";

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
            "| Result | Risk | Category | Check | Expectation | HTTP | Reason | Fingerprint | Replay |",
            "| Результат | Риск | Категория | Проверка | Ожидание | HTTP | Причина | Fingerprint | Повтор |",
          ),
          "| --- | --- | --- | --- | --- | ---: | --- | --- | --- |",
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
          "_No FAIL or WARN findings._",
          "_Находки FAIL и WARN отсутствуют._",
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
    message(language, "## Target", "## Цель"),
    "",
    message(
      language,
      `- Method: \`${baselineRequest.method}\``,
      `- Метод: \`${baselineRequest.method}\``,
    ),
    `- URL: \`${baselineRequest.url}\``,
    message(
      language,
      `- Profile: \`${result.profile ?? "quick"}\``,
      `- Профиль: \`${result.profile ?? "quick"}\``,
    ),
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
      `- Contract fingerprint: \`${responseSchemaFingerprint(baseline)}\``,
      `- Fingerprint контракта: \`${responseSchemaFingerprint(baseline)}\``,
    ),
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
    caseResult.classification,
    caseResult.severity ?? "—",
    caseResult.mutation.category ?? "negative",
    escapeCell(
      redactText(
        renderText(caseResult.mutation.description, language),
        knownSecrets,
      ),
    ),
    caseResult.mutation.expectation ?? "legacy",
    http,
    escapeCell(
      redactText(renderText(caseResult.reason, language), knownSecrets),
    ),
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
  const suffix = attributes.length > 0 ? ` (${attributes.join(", ")})` : "";
  return `- **${caseResult.classification}** ${escapeCell(redactText(renderText(caseResult.mutation.description, language), knownSecrets))}: ${escapeCell(redactText(renderText(caseResult.reason, language), knownSecrets))}${suffix}${replayText}`;
}

function formatJsonReport(
  result: RunResult,
  baselineRequest: ParsedCurl,
  replayByCase: Map<CaseResult, string>,
  knownSecrets: string[],
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    language: "en",
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
    notes: (result.notes ?? []).map((note) =>
      redactText(englishText(note), knownSecrets),
    ),
    cases: result.cases.map((caseResult) => ({
      id: caseResult.mutation.id,
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
      securitySignals: (caseResult.securitySignals ?? []).map((signal) => ({
        id: signal.id,
        title: englishText(signal.title),
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
