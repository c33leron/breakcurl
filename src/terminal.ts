import { createColors } from "picocolors";
import { renderText } from "./i18n.js";
import type { CaseResult, Classification, Language } from "./types.js";

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
  console.log(`  ${colors.dim(key.padEnd(12))}${value}`);
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
    `  ${statusLabel.padEnd(colorEnabled ? String(status).length : 3)}  ${String(latencyMs).padStart(5)}ms  ${colors.bold(method)} ${url}`,
  );
}

export function printCaseLine(
  item: CaseResult,
  index: number,
  total: number,
  colorEnabled: boolean,
  language: Language,
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
    `  [${counter}] ${verdict}  ${colors.dim(category)}  ${status}  ${latency}  ${renderText(item.mutation.description, language)}`,
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

export function printNotice(
  label: string,
  message: string,
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  console.log(`  ${colors.yellow(colors.bold(label))}  ${message}`);
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
