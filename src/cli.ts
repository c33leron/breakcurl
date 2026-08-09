import { createReadStream, openSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { stdin as input, stdout as output } from "node:process";
import { createInterface } from "node:readline/promises";
import { Command } from "commander";
import { createColors } from "picocolors";
import { classifyCase } from "./classify.js";
import { loadConfig } from "./config.js";
import { parseCurl } from "./curl.js";
import { runDemo } from "./demo.js";
import {
  generateChecks,
  parseInlineCustomCase,
  requestForCase,
} from "./mutations.js";
import { redactUrl } from "./redact.js";
import { writeReport } from "./report.js";
import { sendRequest } from "./runner.js";
import type {
  CaseResult,
  CheckCategory,
  CheckProfile,
  CustomCaseDefinition,
  MutationCase,
  RunResult,
} from "./types.js";

interface CliOptions {
  profile?: string;
  maxCases?: string;
  timeout: string;
  allowMutation?: boolean;
  output: string;
  color: boolean;
  security?: boolean;
  expectAuth?: boolean;
  dryRun?: boolean;
  config?: string;
  only: string[];
  exclude: string[];
  set: string[];
  remove: string[];
}

const PROFILE_DEFAULT_CASES: Record<CheckProfile, number> = {
  quick: 15,
  negative: 60,
  security: 80,
  full: 120,
};
const MAX_CASES = 200;
const collectValue = (value: string, previous: string[]): string[] => [
  ...previous,
  value,
];

const program = new Command()
  .name("breakcurl")
  .version("0.1.0", "-V, --version", "показать версию")
  .helpOption("-h, --help", "показать справку")
  .configureHelp({
    optionDescription: (option) => {
      if (
        Array.isArray(option.defaultValue) &&
        option.defaultValue.length === 0
      ) {
        return option.description;
      }
      const shouldShowDefault =
        option.defaultValue !== undefined &&
        (option.required || option.optional || option.isBoolean());
      if (!shouldShowDefault) return option.description;
      const value =
        option.defaultValueDescription ?? JSON.stringify(option.defaultValue);
      return `${option.description} (по умолчанию: ${value})`;
    },
    styleTitle: (title) =>
      ({
        "Usage:": "Использование:",
        "Arguments:": "Аргументы:",
        "Options:": "Параметры:",
        "Commands:": "Команды:",
        "Global Options:": "Глобальные параметры:",
      })[title] ?? title,
  })
  .description(
    "Изменяет по одному полю JSON и показывает, где ломается ваш API.",
  )
  .argument(
    "[file]",
    "файл с рабочим cURL; без файла можно вставить cURL вручную",
  )
  .option(
    "--profile <name>",
    "профиль: quick, negative, security или full; по умолчанию negative",
  )
  .option("--security", "короткий alias для --profile security")
  .option(
    "--max-cases <number>",
    `максимум проверок (1–${MAX_CASES}); зависит от профиля`,
  )
  .option("--timeout <ms>", "тайм-аут запроса в миллисекундах", "10000")
  .option(
    "--allow-mutation",
    "разрешить запросы без интерактивного подтверждения",
  )
  .option(
    "--expect-auth",
    "считать 401/403 обязательным результатом auth-probes",
  )
  .option("--dry-run", "показать план и не отправлять HTTP-запросы")
  .option("--config <file>", "JSON-конфиг пользовательских проверок")
  .option(
    "--only <json-path>",
    "проверять только указанный JSON path; можно повторять",
    collectValue,
    [],
  )
  .option(
    "--exclude <json-path>",
    "исключить JSON path; можно повторять",
    collectValue,
    [],
  )
  .option(
    "--set <path=json>",
    "добавить пользовательскую замену; можно повторять",
    collectValue,
    [],
  )
  .option(
    "--remove <json-path>",
    "добавить пользовательское удаление; можно повторять",
    collectValue,
    [],
  )
  .option("--output <directory>", "каталог для результатов", "breakcurl-output")
  .option("--no-color", "отключить цветной вывод")
  .action(async (file: string | undefined, options: CliOptions) => {
    const config = options.config ? await loadConfig(options.config) : {};
    const profile = resolveProfile(options, config.profile);
    const configuredMax = options.maxCases
      ? positiveInteger(options.maxCases, "--max-cases")
      : config.maxCases;
    const maxCases = configuredMax ?? PROFILE_DEFAULT_CASES[profile];
    if (maxCases > MAX_CASES) {
      throw new Error(`--max-cases не может превышать ${MAX_CASES}.`);
    }
    const timeoutMs = positiveInteger(options.timeout, "--timeout");
    const curlInput = file
      ? await readFile(file, "utf8")
      : await readCurlInput();
    const request = parseCurl(curlInput);
    const expectAuth = options.expectAuth ?? config.expectAuth ?? false;
    if (expectAuth && profile !== "security" && profile !== "full") {
      throw new Error("--expect-auth требует профиль security или full.");
    }
    const customCases = buildCustomCases(
      config.customCases ?? [],
      options.set,
      options.remove,
    );
    const generatedChecks = generateChecks(request, {
      profile,
      maxCases,
      onlyPaths: [...(config.onlyPaths ?? []), ...options.only],
      excludePaths: [...(config.excludePaths ?? []), ...options.exclude],
      customCases,
      expectAuth,
    });
    const mutations = generatedChecks.cases;
    if (mutations.length === 0) {
      throw new Error(
        "Не сгенерировано ни одной проверки. Проверьте profile, paths и customCases.",
      );
    }

    printPreflight(
      request.method,
      request.url,
      profile,
      mutations,
      options.output,
      generatedChecks.notes,
      options.dryRun ?? false,
    );
    if (options.dryRun) {
      printDryRunPlan(mutations);
      process.exitCode = 0;
      return;
    }
    if (
      !options.allowMutation &&
      !(await confirmRequests(mutations.length, hasAuthProbes(mutations)))
    ) {
      throw new Error("Запросы не были разрешены. Ничего не отправлено.");
    }

    console.log("\nИсходный запрос");
    const baselineResponse = await sendRequest(request, timeoutMs);
    console.log(
      `  ${request.method} ${redactUrl(request.url)} → ${displayStatus(baselineResponse.status)} (${baselineResponse.latencyMs} ms)`,
    );
    if (baselineResponse.timedOut || baselineResponse.connectionError) {
      throw new Error(
        "Исходный запрос не завершился. BreakCurl нужен один рабочий запрос. Мутации не отправлялись.",
      );
    }
    if (baselineResponse.status < 200 || baselineResponse.status >= 300) {
      throw new Error(
        `Исходный запрос вернул ${baselineResponse.status}. BreakCurl нужен один рабочий запрос. Мутации не отправлялись.`,
      );
    }

    const cases: CaseResult[] = [];
    for (const mutation of mutations) {
      const response = await sendRequest(
        requestForCase(request, mutation),
        timeoutMs,
      );
      const outcome = classifyCase(mutation, response, {
        baseline: baselineResponse,
        expectAuth,
      });
      cases.push({ mutation, response, ...outcome });
    }

    const result: RunResult = {
      baseline: { request, response: baselineResponse },
      cases,
      profile,
      notes: generatedChecks.notes,
    };
    const generated = await writeReport(result, options.output);
    printResults(
      result,
      generated.reportPath,
      generated.jsonReportPath,
      generated.findingPaths,
      options.color,
    );
    process.exitCode = cases.some((item) => item.classification === "ERROR")
      ? 2
      : cases.some((item) => item.classification === "FAIL")
        ? 1
        : 0;
  });

program
  .command("demo")
  .description("запустить встроенную демонстрацию")
  .action(async () => {
    const options = program.opts<CliOptions>();
    const timeoutMs = positiveInteger(options.timeout, "--timeout");
    const success = await runDemo({
      timeoutMs,
      outputDirectory: options.output,
      color: options.color,
    });
    process.exitCode = success ? 0 : 2;
  });

program.parseAsync().catch((error: unknown) => {
  console.error(
    `ERROR  ${error instanceof Error ? error.message : "BreakCurl завершился с ошибкой."}`,
  );
  process.exitCode = 2;
});

function positiveInteger(value: string, option: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${option} должен быть положительным целым числом.`);
  }
  return parsed;
}

async function readCurlInput(): Promise<string> {
  if (input.isTTY) return readPastedCurl();

  const chunks: Buffer[] = [];
  for await (const chunk of input)
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  const value = Buffer.concat(chunks).toString("utf8");
  if (!value.trim()) throw new Error("Стандартный ввод не содержит cURL.");
  return value;
}

async function readPastedCurl(): Promise<string> {
  console.log(
    "Вставьте скопированный cURL целиком. После вставки нажмите Enter ещё раз на пустой строке:\n",
  );
  const reader = createInterface({ input, output });
  const lines: string[] = [];
  try {
    for await (const line of reader) {
      if (line.trim() === "" && lines.length > 0) break;
      if (line.trim() !== "" || lines.length > 0) lines.push(line);
    }
  } finally {
    reader.close();
  }
  const value = lines.join("\n").trim();
  if (!value) throw new Error("cURL не был введён.");
  return value;
}

async function confirmRequests(
  caseCount: number,
  includesAuthProbes: boolean,
): Promise<boolean> {
  if (
    !output.isTTY ||
    (input.isTTY === false && process.platform === "win32")
  ) {
    throw new Error("Для неинтерактивного запуска требуется --allow-mutation.");
  }
  let terminalInput: NodeJS.ReadableStream = input;
  let ttyInput: ReturnType<typeof createReadStream> | undefined;
  if (!input.isTTY) {
    try {
      ttyInput = createReadStream("/dev/tty", {
        fd: openSync("/dev/tty", "r"),
        autoClose: true,
      });
      terminalInput = ttyInput;
    } catch {
      throw new Error(
        "Для неинтерактивного запуска требуется --allow-mutation.",
      );
    }
  }
  const prompt = createInterface({ input: terminalInput, output });
  try {
    const answer = await prompt.question(
      `BreakCurl отправит 1 исходный запрос и ${caseCount} проверочных запросов.\nЭто может изменить данные в целевой системе.${includesAuthProbes ? "\nAuth-probes могут выполнить операцию без авторизации, если endpoint уязвим." : ""}\nПродолжить? (y/N) `,
    );
    return answer.trim().toLowerCase() === "y";
  } finally {
    prompt.close();
    ttyInput?.destroy();
  }
}

function printPreflight(
  method: string,
  url: string,
  profile: CheckProfile,
  cases: MutationCase[],
  outputDirectory: string,
  notes: string[],
  dryRun: boolean,
): void {
  const categories = countCategories(cases);
  console.log("BreakCurl v0.1.0\n\nПеред запуском");
  console.log(`  Цель: ${method} ${redactUrl(url)}`);
  console.log(`  Профиль: ${profile}`);
  console.log(
    `  Запросы: ${dryRun ? "0 (dry-run)" : `1 исходный + ${cases.length} проверочных`}`,
  );
  console.log(
    `  Категории: ${Object.entries(categories)
      .map(([category, count]) => `${category}=${count}`)
      .join(", ")}`,
  );
  console.log(`  Результаты: ${outputDirectory}`);
  if (hasAuthProbes(cases)) {
    console.log(
      "  ВНИМАНИЕ: auth-probes повторяют валидное тело без корректных credentials и при уязвимости могут вызвать side effect.",
    );
  }
  for (const note of notes) console.log(`  NOTE: ${note}`);
}

function printResults(
  result: RunResult,
  reportPath: string,
  jsonReportPath: string,
  findingPaths: string[],
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  console.log("\nНегативные проверки");
  for (const item of result.cases) {
    const label =
      item.classification === "FAIL"
        ? colors.red(item.classification)
        : item.classification === "WARN"
          ? colors.yellow(item.classification)
          : item.classification === "PASS"
            ? colors.green(item.classification)
            : item.classification === "INFO"
              ? colors.cyan(item.classification)
              : colors.magenta(item.classification);
    console.log(
      `  ${label.padEnd(5)} ${item.mutation.description} → ${displayStatus(item.response.status)}`,
    );
  }

  const failed = result.cases.filter(
    (item) => item.classification === "FAIL",
  ).length;
  const warned = result.cases.filter(
    (item) => item.classification === "WARN",
  ).length;
  const passed = result.cases.filter(
    (item) => item.classification === "PASS",
  ).length;
  const informed = result.cases.filter(
    (item) => item.classification === "INFO",
  ).length;
  const errored = result.cases.filter(
    (item) => item.classification === "ERROR",
  ).length;
  console.log("\nИтог");
  console.log(
    `  Проверок: ${result.cases.length}; FAIL: ${failed}; WARN: ${warned}; INFO: ${informed}; PASS: ${passed}; ERROR: ${errored}`,
  );
  console.log("\nСоздано");
  console.log(`  ${reportPath}`);
  console.log(`  ${jsonReportPath}`);
  for (const path of findingPaths) console.log(`  ${path}`);
  console.log("\nСекреты были скрыты до записи файлов.");
}

function displayStatus(status: number): string {
  return status === 0 ? "NO RESPONSE" : String(status);
}

function resolveProfile(
  options: CliOptions,
  configProfile: CheckProfile | undefined,
): CheckProfile {
  if (options.security && options.profile && options.profile !== "security") {
    throw new Error("Не используйте --security вместе с другим --profile.");
  }
  const value = options.security
    ? "security"
    : (options.profile ?? configProfile ?? "negative");
  if (!["quick", "negative", "security", "full"].includes(value)) {
    throw new Error(
      "--profile должен быть quick, negative, security или full.",
    );
  }
  return value as CheckProfile;
}

function buildCustomCases(
  configured: CustomCaseDefinition[],
  setCases: string[],
  removeCases: string[],
): CustomCaseDefinition[] {
  return [
    ...configured,
    ...setCases.map(parseInlineCustomCase),
    ...removeCases.map((path) => ({
      name: `Пользовательское удаление ${path}`,
      path,
      operation: "remove" as const,
      expect: "reject" as const,
    })),
  ];
}

function countCategories(
  cases: MutationCase[],
): Partial<Record<CheckCategory, number>> {
  const counts: Partial<Record<CheckCategory, number>> = {};
  for (const item of cases) {
    const category = item.category ?? "structure";
    counts[category] = (counts[category] ?? 0) + 1;
  }
  return counts;
}

function hasAuthProbes(cases: MutationCase[]): boolean {
  return cases.some((item) => item.category === "authentication");
}

function printDryRunPlan(cases: MutationCase[]): void {
  console.log("\nПлан проверок — HTTP-запросы не отправлены");
  for (const [index, item] of cases.entries()) {
    console.log(
      `  ${String(index + 1).padStart(3)}. [${item.category ?? "negative"}] ${item.description} — expect ${item.expectation ?? "legacy"}`,
    );
  }
}
