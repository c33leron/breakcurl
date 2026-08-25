import { createReadStream, openSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { stdin as input, stdout as output } from "node:process";
import { createInterface } from "node:readline/promises";
import { Command, InvalidArgumentError } from "commander";
import { classifyCase } from "./classify.js";
import { loadConfig } from "./config.js";
import { parseCurl } from "./curl.js";
import { runDemo } from "./demo.js";
import {
  detectInitialLanguage,
  isLanguage,
  localized,
  message,
  renderText,
} from "./i18n.js";
import {
  generateChecks,
  parseInlineCustomCase,
  requestForCase,
} from "./mutations.js";
import { redactUrl } from "./redact.js";
import { writeReport } from "./report.js";
import { sendRequest } from "./runner.js";
import {
  printBanner,
  printBaseline,
  printCaseLine,
  printKeyValue,
  printNotice,
  printResultSummary,
  printSection,
} from "./terminal.js";
import type {
  CaseResult,
  CheckCategory,
  CheckProfile,
  CustomCaseDefinition,
  Language,
  MutationCase,
  RunResult,
  TranslatableText,
} from "./types.js";

interface CliOptions {
  lang: Language;
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
const initialLanguage = detectInitialLanguage(
  process.argv.slice(2),
  process.env.BREAKCURL_LANG,
);
const m = (en: string, ru: string): string => message(initialLanguage, en, ru);
const collectValue = (value: string, previous: string[]): string[] => [
  ...previous,
  value,
];

const program = new Command()
  .name("breakcurl")
  .version("0.1.0", "-V, --version", m("show version", "показать версию"))
  .helpOption("-h, --help", m("show help", "показать справку"))
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
      return `${option.description} ${m(
        `(default: ${value})`,
        `(по умолчанию: ${value})`,
      )}`;
    },
    styleTitle: (title) =>
      initialLanguage === "ru"
        ? ({
            "Usage:": "Использование:",
            "Arguments:": "Аргументы:",
            "Options:": "Параметры:",
            "Commands:": "Команды:",
            "Global Options:": "Глобальные параметры:",
          }[title] ?? title)
        : title,
  })
  .description(
    m(
      "Mutates one JSON field at a time and shows where your API breaks.",
      "Изменяет по одному полю JSON и показывает, где ломается ваш API.",
    ),
  )
  .argument(
    "[file]",
    m(
      "file containing a working cURL; omit it to paste cURL interactively",
      "файл с рабочим cURL; без файла можно вставить cURL вручную",
    ),
  )
  .option(
    "--lang <language>",
    m("interface language: en or ru", "язык интерфейса: en или ru"),
    parseLanguage,
    initialLanguage,
  )
  .option(
    "--profile <name>",
    m(
      "profile: quick, negative, security, or full; defaults to quick",
      "профиль: quick, negative, security или full; по умолчанию quick",
    ),
  )
  .option(
    "--security",
    m(
      "short alias for --profile security",
      "короткий alias для --profile security",
    ),
  )
  .option(
    "--max-cases <number>",
    m(
      `maximum checks (1–${MAX_CASES}); depends on the profile`,
      `максимум проверок (1–${MAX_CASES}); зависит от профиля`,
    ),
  )
  .option(
    "--timeout <ms>",
    m("request timeout in milliseconds", "тайм-аут запроса в миллисекундах"),
    "10000",
  )
  .option(
    "--allow-mutation",
    m(
      "allow requests without interactive confirmation",
      "разрешить запросы без интерактивного подтверждения",
    ),
  )
  .option(
    "--expect-auth",
    m(
      "require auth probes to return 401/403",
      "считать 401/403 обязательным результатом auth-probes",
    ),
  )
  .option(
    "--dry-run",
    m(
      "show the plan without sending HTTP requests",
      "показать план и не отправлять HTTP-запросы",
    ),
  )
  .option(
    "--config <file>",
    m(
      "JSON config with custom checks",
      "JSON-конфиг пользовательских проверок",
    ),
  )
  .option(
    "--only <json-path>",
    m(
      "check only this JSON path; repeatable",
      "проверять только указанный JSON path; можно повторять",
    ),
    collectValue,
    [],
  )
  .option(
    "--exclude <json-path>",
    m(
      "exclude this JSON path; repeatable",
      "исключить JSON path; можно повторять",
    ),
    collectValue,
    [],
  )
  .option(
    "--set <path=json>",
    m(
      "add a custom replacement; repeatable",
      "добавить пользовательскую замену; можно повторять",
    ),
    collectValue,
    [],
  )
  .option(
    "--remove <json-path>",
    m(
      "add a custom removal; repeatable",
      "добавить пользовательское удаление; можно повторять",
    ),
    collectValue,
    [],
  )
  .option(
    "--output <directory>",
    m("output directory", "каталог для результатов"),
    "breakcurl-output",
  )
  .option("--no-color", m("disable colored output", "отключить цветной вывод"))
  .action(async (file: string | undefined, options: CliOptions) => {
    const language = options.lang;
    const config = options.config
      ? await loadConfig(options.config, language)
      : {};
    const profile = resolveProfile(options, config.profile, language);
    const configuredMax = options.maxCases
      ? positiveInteger(options.maxCases, "--max-cases", language)
      : config.maxCases;
    const maxCases = configuredMax ?? PROFILE_DEFAULT_CASES[profile];
    if (maxCases > MAX_CASES) {
      throw new Error(
        message(
          language,
          `--max-cases cannot exceed ${MAX_CASES}.`,
          `--max-cases не может превышать ${MAX_CASES}.`,
        ),
      );
    }
    const timeoutMs = positiveInteger(options.timeout, "--timeout", language);
    const curlInput = file
      ? await readFile(file, "utf8")
      : await readCurlInput(language);
    const request = parseCurl(curlInput, language);
    const expectAuth = options.expectAuth ?? config.expectAuth ?? false;
    if (expectAuth && profile !== "security" && profile !== "full") {
      throw new Error(
        message(
          language,
          "--expect-auth requires the security or full profile.",
          "--expect-auth требует профиль security или full.",
        ),
      );
    }
    const customCases = buildCustomCases(
      config.customCases ?? [],
      options.set,
      options.remove,
      language,
    );
    const generatedChecks = generateChecks(request, {
      profile,
      maxCases,
      onlyPaths: [...(config.onlyPaths ?? []), ...options.only],
      excludePaths: [...(config.excludePaths ?? []), ...options.exclude],
      customCases,
      expectAuth,
      language,
    });
    const mutations = generatedChecks.cases;
    if (mutations.length === 0) {
      throw new Error(
        message(
          language,
          "No checks were generated. Review the profile, paths, and customCases.",
          "Не сгенерировано ни одной проверки. Проверьте profile, paths и customCases.",
        ),
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
      options.color,
      language,
    );
    if (options.dryRun) {
      printDryRunPlan(mutations, language);
      process.exitCode = 0;
      return;
    }
    if (
      !options.allowMutation &&
      !(await confirmRequests(
        mutations.length,
        hasAuthProbes(mutations),
        language,
      ))
    ) {
      throw new Error(
        message(
          language,
          "Requests were not authorized. Nothing was sent.",
          "Запросы не были разрешены. Ничего не отправлено.",
        ),
      );
    }

    printSection(
      message(language, "BASELINE", "ИСХОДНЫЙ ЗАПРОС"),
      options.color,
    );
    const baselineResponse = await sendRequest(request, timeoutMs);
    printBaseline(
      request.method,
      redactUrl(request.url),
      baselineResponse.status,
      baselineResponse.latencyMs,
      options.color,
    );
    if (baselineResponse.timedOut || baselineResponse.connectionError) {
      throw new Error(
        message(
          language,
          "The baseline request did not complete. BreakCurl needs one working request. No mutations were sent.",
          "Исходный запрос не завершился. BreakCurl нужен один рабочий запрос. Мутации не отправлялись.",
        ),
      );
    }
    if (baselineResponse.status < 200 || baselineResponse.status >= 300) {
      throw new Error(
        message(
          language,
          `The baseline request returned ${baselineResponse.status}. BreakCurl needs one working request. No mutations were sent.`,
          `Исходный запрос вернул ${baselineResponse.status}. BreakCurl нужен один рабочий запрос. Мутации не отправлялись.`,
        ),
      );
    }

    const cases: CaseResult[] = [];
    const runNotes = [...generatedChecks.notes];
    printSection(message(language, "CHECKS", "ПРОВЕРКИ"), options.color);
    for (const [index, mutation] of mutations.entries()) {
      const response = await sendRequest(
        requestForCase(request, mutation),
        timeoutMs,
      );
      const outcome = classifyCase(mutation, response, {
        baseline: baselineResponse,
        expectAuth,
      });
      const caseResult = { mutation, response, ...outcome };
      cases.push(caseResult);
      printCaseLine(
        caseResult,
        index,
        mutations.length,
        options.color,
        language,
      );

      if (response.status === 429) {
        const skipped = mutations.length - cases.length;
        const retryAfter = response.headers["retry-after"];
        const note = localized(
          `Safety stop: received HTTP 429${retryAfter ? ` (Retry-After: ${retryAfter})` : ""}; skipped checks: ${skipped}.`,
          `Safety stop: получен HTTP 429${retryAfter ? ` (Retry-After: ${retryAfter})` : ""}; пропущено проверок: ${skipped}.`,
        );
        runNotes.push(note);
        console.log();
        printNotice(
          message(language, "SAFETY STOP", "ЗАЩИТНАЯ ОСТАНОВКА"),
          renderText(note, language),
          options.color,
        );
        break;
      }
    }

    const result: RunResult = {
      baseline: { request, response: baselineResponse },
      cases,
      profile,
      notes: runNotes,
      language,
    };
    const generated = await writeReport(result, options.output);
    printResults(
      result,
      generated.reportPath,
      generated.jsonReportPath,
      generated.findingPaths,
      options.color,
      language,
    );
    process.exitCode = cases.some((item) => item.classification === "ERROR")
      ? 2
      : cases.some((item) => item.classification === "FAIL")
        ? 1
        : 0;
  });

program
  .command("demo")
  .description(m("run the built-in demo", "запустить встроенную демонстрацию"))
  .action(async () => {
    const options = program.opts<CliOptions>();
    const language = options.lang;
    const timeoutMs = positiveInteger(options.timeout, "--timeout", language);
    const success = await runDemo({
      timeoutMs,
      outputDirectory: options.output,
      color: options.color,
      language,
    });
    process.exitCode = success ? 0 : 2;
  });

program.parseAsync().catch((error: unknown) => {
  const language = program.opts<CliOptions>().lang ?? initialLanguage;
  console.error(
    `ERROR  ${error instanceof Error ? error.message : message(language, "BreakCurl exited with an error.", "BreakCurl завершился с ошибкой.")}`,
  );
  process.exitCode = 2;
});

function positiveInteger(
  value: string,
  option: string,
  language: Language,
): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(
      message(
        language,
        `${option} must be a positive integer.`,
        `${option} должен быть положительным целым числом.`,
      ),
    );
  }
  return parsed;
}

async function readCurlInput(language: Language): Promise<string> {
  if (input.isTTY) return readPastedCurl(language);

  const chunks: Buffer[] = [];
  for await (const chunk of input)
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  const value = Buffer.concat(chunks).toString("utf8");
  if (!value.trim()) {
    throw new Error(
      message(
        language,
        "Standard input does not contain cURL.",
        "Стандартный ввод не содержит cURL.",
      ),
    );
  }
  return value;
}

async function readPastedCurl(language: Language): Promise<string> {
  console.log(
    message(
      language,
      "Paste the complete Copy as cURL command, then press Enter on an empty line:\n",
      "Вставьте Copy as cURL целиком, затем нажмите Enter на пустой строке:\n",
    ),
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
  if (!value) {
    throw new Error(
      message(language, "No cURL was provided.", "cURL не был введён."),
    );
  }
  return value;
}

async function confirmRequests(
  caseCount: number,
  includesAuthProbes: boolean,
  language: Language,
): Promise<boolean> {
  if (
    !output.isTTY ||
    (input.isTTY === false && process.platform === "win32")
  ) {
    throw new Error(
      message(
        language,
        "Non-interactive runs require --allow-mutation.",
        "Для неинтерактивного запуска требуется --allow-mutation.",
      ),
    );
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
        message(
          language,
          "Non-interactive runs require --allow-mutation.",
          "Для неинтерактивного запуска требуется --allow-mutation.",
        ),
      );
    }
  }
  const prompt = createInterface({ input: terminalInput, output });
  try {
    const answer = await prompt.question(
      message(
        language,
        `BreakCurl will send 1 baseline request and ${caseCount} check requests.\nThis may modify data in the target system.${includesAuthProbes ? "\nAuth probes may execute the operation without authorization if the endpoint is vulnerable." : ""}\nContinue? (y/N) `,
        `BreakCurl отправит 1 исходный запрос и ${caseCount} проверочных запросов.\nЭто может изменить данные в целевой системе.${includesAuthProbes ? "\nAuth-probes могут выполнить операцию без авторизации, если endpoint уязвим." : ""}\nПродолжить? (y/N) `,
      ),
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
  notes: TranslatableText[],
  dryRun: boolean,
  colorEnabled: boolean,
  language: Language,
): void {
  const categories = countCategories(cases);
  printBanner(
    dryRun
      ? message(language, "DRY RUN · ZERO REQUESTS", "ПЛАН · НОЛЬ ЗАПРОСОВ")
      : message(
          language,
          "CONTROLLED API MUTATION",
          "КОНТРОЛИРУЕМЫЕ API-МУТАЦИИ",
        ),
    colorEnabled,
  );
  printSection(message(language, "RUN PLAN", "ПЛАН ЗАПУСКА"), colorEnabled);
  printKeyValue(
    message(language, "target", "цель"),
    `${method} ${redactUrl(url)}`,
    colorEnabled,
  );
  printKeyValue(
    message(language, "profile", "профиль"),
    profile.toUpperCase(),
    colorEnabled,
  );
  printKeyValue(
    message(language, "budget", "запросы"),
    dryRun
      ? message(language, "0 requests", "0 запросов")
      : message(
          language,
          `1 baseline + ${cases.length} checks`,
          `1 исходный + ${cases.length} проверок`,
        ),
    colorEnabled,
  );
  printKeyValue(
    message(language, "coverage", "покрытие"),
    Object.entries(categories)
      .map(([category, count]) => `${category}=${count}`)
      .join(" · "),
    colorEnabled,
  );
  printKeyValue(
    message(language, "artifacts", "артефакты"),
    outputDirectory,
    colorEnabled,
  );
  if (hasAuthProbes(cases)) {
    printNotice(
      message(language, "CAUTION", "ВНИМАНИЕ"),
      message(
        language,
        "Auth probes repeat the valid body without credentials and may cause a side effect.",
        "Auth-probes повторяют валидное тело без credentials и могут вызвать side effect.",
      ),
      colorEnabled,
    );
  }
  for (const note of notes) {
    printNotice(
      message(language, "NOTE", "ПРИМЕЧАНИЕ"),
      renderText(note, language),
      colorEnabled,
    );
  }
}

function printResults(
  result: RunResult,
  reportPath: string,
  jsonReportPath: string,
  findingPaths: string[],
  colorEnabled: boolean,
  language: Language,
): void {
  printSection(message(language, "RUN SUMMARY", "ИТОГ"), colorEnabled);
  printResultSummary(result.cases, colorEnabled);
  printSection(message(language, "ARTIFACTS", "АРТЕФАКТЫ"), colorEnabled);
  printKeyValue(message(language, "report", "отчёт"), reportPath, colorEnabled);
  printKeyValue("json", jsonReportPath, colorEnabled);
  for (const path of findingPaths) {
    printKeyValue(message(language, "finding", "находка"), path, colorEnabled);
  }
  printKeyValue(
    message(language, "privacy", "приватность"),
    message(
      language,
      "Secrets redacted before writing",
      "Секреты скрыты до записи",
    ),
    colorEnabled,
  );
}

function resolveProfile(
  options: CliOptions,
  configProfile: CheckProfile | undefined,
  language: Language,
): CheckProfile {
  if (options.security && options.profile && options.profile !== "security") {
    throw new Error(
      message(
        language,
        "Do not combine --security with another --profile.",
        "Не используйте --security вместе с другим --profile.",
      ),
    );
  }
  const value = options.security
    ? "security"
    : (options.profile ?? configProfile ?? "quick");
  if (!["quick", "negative", "security", "full"].includes(value)) {
    throw new Error(
      message(
        language,
        "--profile must be quick, negative, security, or full.",
        "--profile должен быть quick, negative, security или full.",
      ),
    );
  }
  return value as CheckProfile;
}

function buildCustomCases(
  configured: CustomCaseDefinition[],
  setCases: string[],
  removeCases: string[],
  language: Language,
): CustomCaseDefinition[] {
  return [
    ...configured,
    ...setCases.map((value, index) =>
      parseInlineCustomCase(value, index, language),
    ),
    ...removeCases.map((path) => ({
      name: localized(
        `Custom removal of ${path}`,
        `Пользовательское удаление ${path}`,
      ),
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

function printDryRunPlan(cases: MutationCase[], language: Language): void {
  console.log(
    message(
      language,
      "\nDRY-RUN CHECKS · no HTTP requests were sent",
      "\nПРОВЕРКИ DRY-RUN · HTTP-запросы не отправлены",
    ),
  );
  for (const [index, item] of cases.entries()) {
    console.log(
      `  ${String(index + 1).padStart(3)}. [${item.category ?? "negative"}] ${renderText(item.description, language)} — expect ${item.expectation ?? "legacy"}`,
    );
  }
}

function parseLanguage(value: string): Language {
  if (!isLanguage(value)) {
    throw new InvalidArgumentError(
      `language must be en or ru; received ${JSON.stringify(value)}`,
    );
  }
  return value;
}
