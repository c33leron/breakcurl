import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { stripVTControlCharacters } from "node:util";
import { createColors } from "picocolors";
import { message, renderText } from "./i18n.js";
import { redactText } from "./redact.js";
import { summarizeRun } from "./run-summary.js";
import type {
  CaseResult,
  Classification,
  Language,
  RunResult,
} from "./types.js";

export function printBanner(mode: string, colorEnabled: boolean): void {
  const colors = createColors(colorEnabled);
  console.log(`${colors.bold(colors.cyan("BREAKCURL"))}  ${colors.dim(mode)}`);
}

export function printSection(title: string, colorEnabled: boolean): void {
  const colors = createColors(colorEnabled);
  console.log(`\n${colors.bold(colors.cyan(title))}`);
}

export function printKeyValue(
  key: string,
  value: string,
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  console.log(`  ${colors.dim(key.padEnd(12))} ${safeTerminalText(value)}`);
}

export function printFileLink(
  key: string,
  filePath: string,
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  const url = safeTerminalText(pathToFileURL(resolve(filePath)).href);
  const interactive =
    process.stdout.isTTY === true &&
    colorEnabled &&
    process.env.TERM !== "dumb";
  // Only our generated file URL may add terminal hyperlink control sequences.
  const link = interactive
    ? `\u001b]8;;${url}\u001b\\${url}\u001b]8;;\u001b\\`
    : url;
  console.log(`  ${colors.dim(safeTerminalText(key).padEnd(12))} ${link}`);
}

export function printBaseline(
  method: string,
  url: string,
  status: number,
  latencyMs: number,
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  const statusLabel = colorStatus(String(status), status, colors);
  console.log(
    `  ${statusLabel.padEnd(colorEnabled ? String(status).length : 3)}  ${String(latencyMs).padStart(5)}ms  ${colors.bold(method)} ${safeTerminalText(url)}`,
  );
}

export function printCaseLine(
  item: CaseResult,
  index: number,
  total: number,
  colorEnabled: boolean,
  language: Language,
  knownSecrets: string[] = [],
): void {
  const colors = createColors(colorEnabled);
  const width = String(total).length;
  const counter = `${String(index + 1).padStart(width, "0")}/${total}`;
  const rawVerdict = item.classification.padEnd(5);
  const verdict = colorVerdict(rawVerdict, item.classification, colors);
  const category = categoryLabel(item.mutation.category).padEnd(11);
  const status = displayStatus(item.response.status).padStart(3);
  const latency = `${item.response.latencyMs}ms`.padStart(7);
  console.log(
    `  [${counter}] ${verdict}  ${colors.dim(category)}  ${status}  ${latency}  ${safeTerminalText(redactText(renderText(item.mutation.description, language), knownSecrets))}`,
  );
}

export function printResultSummary(
  cases: CaseResult[],
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  const counts = countClassifications(cases);
  const parts: string[] = [];
  for (const classification of [
    "PASS",
    "INFO",
    "WARN",
    "FAIL",
    "ERROR",
  ] as const) {
    const value = `${classification} ${counts[classification]}`;
    parts.push(colorVerdict(value, classification, colors));
  }
  printKeyValue("executed", String(cases.length), colorEnabled);
  printKeyValue("results", parts.join("   "), colorEnabled);
}

export function printRunOutcome(
  result: RunResult,
  colorEnabled: boolean,
  language: Language,
): void {
  const summary = summarizeRun(result);
  printKeyValue(
    message(language, "outcome", "результат"),
    renderText(summary.title, language),
    colorEnabled,
  );
  printKeyValue(
    message(language, "meaning", "пояснение"),
    renderText(summary.explanation, language),
    colorEnabled,
  );
  printKeyValue(
    message(language, "next", "дальше"),
    renderText(summary.nextAction, language),
    colorEnabled,
  );
  printKeyValue(
    message(language, "tries / plan", "запросы/план"),
    `${summary.requestsAttempted} / ${summary.requestsPlanned ?? message(language, "unknown", "неизвестно")}`,
    colorEnabled,
  );
}

export function printNotice(
  label: string,
  message: string,
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  console.log(
    `  ${colors.yellow(colors.bold(label))}  ${safeTerminalText(message)}`,
  );
}

export function safeTerminalText(value: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: untrusted text must not control the terminal
  return stripVTControlCharacters(value).replace(/[\u0000-\u001f\u007f]/g, " ");
}

export function displayStatus(status: number): string {
  return status === 0 ? "---" : String(status);
}

function categoryLabel(category: CaseResult["mutation"]["category"]): string {
  switch (category) {
    case "authentication":
      return "AUTH";
    case "injection":
      return "INJECTION";
    case "boundary":
      return "BOUNDARY";
    case "protocol":
      return "PROTOCOL";
    case "custom":
      return "CUSTOM";
    default:
      return "STRUCTURE";
  }
}

function countClassifications(
  cases: CaseResult[],
): Record<Classification, number> {
  const counts: Record<Classification, number> = {
    PASS: 0,
    INFO: 0,
    WARN: 0,
    FAIL: 0,
    ERROR: 0,
  };
  for (const item of cases) counts[item.classification] += 1;
  return counts;
}

function colorVerdict(
  value: string,
  classification: Classification,
  colors: ReturnType<typeof createColors>,
): string {
  switch (classification) {
    case "PASS":
      return colors.green(value);
    case "INFO":
      return colors.cyan(value);
    case "WARN":
      return colors.yellow(value);
    case "FAIL":
      return colors.red(value);
    case "ERROR":
      return colors.magenta(value);
  }
}

function colorStatus(
  value: string,
  status: number,
  colors: ReturnType<typeof createColors>,
): string {
  if (status >= 200 && status < 300) return colors.green(value);
  if (status >= 400 && status < 500) return colors.yellow(value);
  if (status >= 500) return colors.red(value);
  return colors.magenta(value);
}
