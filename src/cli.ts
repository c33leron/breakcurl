import { createReadStream, openSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { stdin as input, stdout as output } from "node:process";
import { createInterface } from "node:readline/promises";
import { Command, InvalidArgumentError } from "commander";
import {
  collectAuthContractSecrets,
  parseAuthContract,
} from "./auth-contract.js";
import { loadConfig } from "./config.js";
import { parseCurl } from "./curl.js";
import { runDemo } from "./demo.js";
import {
  executeChecks,
  exitCodeForRun,
  hasWorkingBaseline,
} from "./execute.js";
import {
  detectInitialLanguage,
  isLanguage,
  localized,
  message,
  renderText,
} from "./i18n.js";
import { executeIdorPlan, parseIdorConfig, prepareIdorPlan } from "./idor.js";
import {
  generateChecks,
  parseInlineCustomCase,
  requestForCase,
} from "./mutations.js";
import { readPastedCurl } from "./paste.js";
import {
  loadLanguagePreference,
  saveLanguagePreference,
  shouldPersistLanguagePreference,
} from "./preferences.js";
import { collectSensitiveValues, redactText, redactUrl } from "./redact.js";
import { writeReport } from "./report.js";
import {
  printBanner,
  printBaseline,
  printCaseLine,
  printFileLink,
  printKeyValue,
  printNotice,
  printResultSummary,
  printRunOutcome,
  printSection,
  safeTerminalText,
} from "./terminal.js";
import type {
  CheckCategory,
  CheckProfile,
  CustomCaseDefinition,
  Language,
  MutationCase,
  RunResult,
  TranslatableText,
} from "./types.js";
import { VERSION } from "./version.js";

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
  authBodyPath: string[];
  authContract?: string;
  dryRun?: boolean;
  config?: string;
  junit?: string | true;
  sarif?: string | true;
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
let outputSecrets: string[] = [];
const initialLanguage = detectInitialLanguage(
  process.argv.slice(2),
  process.env.BREAKCURL_LANG,
  await loadLanguagePreference(),
);
const m = (en: string, ru: string): string => message(initialLanguage, en, ru);
const collectValue = (value: string, previous: string[]): string[] => [
  ...previous,
  value,
];

const program = new Command()
  .name("breakcurl")
  .version(VERSION, "-V, --version", m("show version", "показать версию"))
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
      "Run controlled API and authentication checks from cURL, then open an HTML report.",
      "Проверяет API и авторизацию по cURL и создает понятный HTML-отчет.",
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
    m(
      "interface language: en or ru; remembered in interactive runs",
      "язык интерфейса: en или ru; запоминается при интерактивном запуске",
    ),
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
      "expect 401/403; strict failures require a complete --auth-contract",
      "ожидать 401/403; строгий вывод требует полного --auth-contract",
    ),
  )
  .option(
    "--auth-body-path <path>",
    m(
      "declare a JSON credential path to remove/invalidate with header credentials (repeatable)",
      "указать JSON-путь credentials для удаления/замены вместе с заголовками (можно повторять)",
    ),
    collectValue,
    [],
  )
  .option(
    "--auth-contract <file>",
    m(
      "complete header/query/JSON credential declaration for strict auth checks",
      "полное описание credentials в header/query/JSON для строгой проверки авторизации",
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
    "--junit [file]",
    m(
      "also write a JUnit XML report for CI (default: breakcurl-output/junit.xml)",
      "дополнительно сохранить отчёт JUnit XML для CI (по умолчанию: breakcurl-output/junit.xml)",
    ),
  )
  .option(
    "--sarif [file]",
    m(
      "also write a SARIF 2.1.0 report for GitHub code scanning (default: breakcurl-output/sarif.json)",
      "дополнительно сохранить отчёт SARIF 2.1.0 для GitHub code scanning (по умолчанию: breakcurl-output/sarif.json)",
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
    outputSecrets = collectSensitiveValues(request);
    const expectAuth = options.expectAuth ?? config.expectAuth ?? false;
    const authContract = options.authContract
      ? parseAuthContract(
          await readJsonFile(options.authContract, language),
          language,
        )
      : config.authContract;
    if (authContract)
      outputSecrets.push(
        ...collectAuthContractSecrets(request, authContract, language),
      );
    if (expectAuth && profile === "negative") {
      throw new Error(
        message(
          language,
          "--expect-auth requires the quick, security, or full profile.",
          "--expect-auth требует профиль quick, security или full.",
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
      authBodyPaths: [...(config.authBodyPaths ?? []), ...options.authBodyPath],
      ...(authContract ? { authContract } : {}),
      language,
    });
    const mutations = generatedChecks.cases;
    outputSecrets = [
      ...new Set([
        ...outputSecrets,
        ...mutations.flatMap((mutation) =>
          collectSensitiveValues(requestForCase(request, mutation)),
        ),
      ]),
    ];
    if (mutations.length === 0 && request.method !== "GET") {
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
    const result = await executeChecks(request, mutations, {
      timeoutMs,
      profile,
      language,
      notes: generatedChecks.notes,
      onBaseline: ({ response }) => {
        printBaseline(
          request.method,
          redactUrl(request.url, outputSecrets),
          response.status,
          response.latencyMs,
          options.color,
        );
        printSection(message(language, "CHECKS", "ПРОВЕРКИ"), options.color);
      },
      onCase: (item, index) =>
        printCaseLine(
          item,
          index,
          mutations.length,
          options.color,
          language,
          outputSecrets,
        ),
      onStop: (note) =>
        printNotice(
          message(language, "SAFETY STOP", "ЗАЩИТНАЯ ОСТАНОВКА"),
          redactText(renderText(note, language), outputSecrets),
          options.color,
        ),
    });
    const generated = await writeReport(result, options.output, {
      knownSecrets: outputSecrets,
      junitPath: resolveReportOption(
        options.junit,
        "junit.xml",
        options.output,
      ),
      sarifPath: resolveReportOption(
        options.sarif,
        "sarif.json",
        options.output,
      ),
    });
    printResults(
      result,
      generated.reportPath,
      generated.jsonReportPath,
      generated.findingPaths,
      generated.junitPath,
      generated.sarifPath,
      options.color,
      language,
      generated.htmlReportPath,
    );
    process.exitCode = exitCodeForRun(result);
    if (!hasWorkingBaseline(result)) {
      const note = result.notes?.at(-1);
      if (note)
        console.error(
          safeTerminalText(
            redactText(renderText(note, language), outputSecrets),
          ),
        );
    }
  });

program
  .command("idor <a> <b>")
  .description(
    m(
      "verify read access isolation between two controlled bearer identities",
      "проверить изоляцию чтения между двумя тестовыми пользователями с bearer-токенами",
    ),
  )
  .action(async (a: string, b: string) => {
    const options = program.opts<CliOptions>();
    const language = options.lang;
    rejectUnrelatedOptions(options, "idor");
    if (!options.config)
      throw new Error(
        m(
          "IDOR requires --config breakcurl.idor.json; start from breakcurl.idor.example.json.",
          "Для IDOR нужен --config breakcurl.idor.json; образец: breakcurl.idor.example.json.",
        ),
      );
    const timeoutMs = positiveInteger(options.timeout, "--timeout", language);
    const config = parseIdorConfig(
      await readJsonFile(options.config, language),
      language,
    );
    const requestA = parseCurl(await readFile(a, "utf8"), language);
    const requestB = parseCurl(await readFile(b, "utf8"), language);
    outputSecrets = [
      ...collectSensitiveValues(requestA),
      ...collectSensitiveValues(requestB),
    ];
    const plan = prepareIdorPlan(requestA, requestB, config, language);
    outputSecrets.push(...plan.knownSecrets);
    printBanner(
      message(
        language,
        "CONTROLLED IDOR CHECK",
        "КОНТРОЛИРУЕМАЯ IDOR-ПРОВЕРКА",
      ),
      options.color,
    );
    printKeyValue(
      message(language, "target", "цель"),
      redactUrl(plan.origin, outputSecrets),
      options.color,
    );
    printKeyValue(
      message(language, "planned", "план"),
      message(language, "at most 5 GET requests", "не более 5 GET-запросов"),
      options.color,
    );
    if (options.dryRun)
      printKeyValue(
        message(language, "sent", "отправлено"),
        message(language, "0 requests (dry-run)", "0 запросов (только план)"),
        options.color,
      );
    for (const item of plan.requests)
      console.log(
        `  ${safeTerminalText(redactText(renderText(item.description, language), outputSecrets))}`,
      );
    if (options.dryRun) {
      console.log(
        message(
          language,
          "DRY RUN: no HTTP requests were sent.",
          "ПЛАН: HTTP-запросы не отправлены.",
        ),
      );
      return;
    }
    if (
      !options.allowMutation &&
      !(await confirmRequests(4, false, language, true))
    ) {
      throw new Error(
        message(
          language,
          "Requests were not authorized. Nothing was sent.",
          "Запросы не были разрешены. Ничего не отправлено.",
        ),
      );
    }
    const result = await executeIdorPlan(plan, {
      timeoutMs,
      language,
      onResult: (item, index) =>
        printCaseLine(item, index, 5, options.color, language, outputSecrets),
    });
    const files = await writeReport(result, options.output, {
      knownSecrets: outputSecrets,
      junitPath: resolveReportOption(
        options.junit,
        "junit.xml",
        options.output,
      ),
      sarifPath: resolveReportOption(
        options.sarif,
        "sarif.json",
        options.output,
      ),
    });
    printResults(
      result,
      files.reportPath,
      files.jsonReportPath,
      files.findingPaths,
      files.junitPath,
      files.sarifPath,
      options.color,
      language,
      files.htmlReportPath,
    );
    process.exitCode = exitCodeForRun(result);
  });

program
  .command("demo")
  .description(m("run the built-in demo", "запустить встроенную демонстрацию"))
  .action(async () => {
    const options = program.opts<CliOptions>();
    const language = options.lang;
    rejectUnrelatedOptions(options, "demo");
    const timeoutMs = positiveInteger(options.timeout, "--timeout", language);
    if (options.dryRun) {
      console.log(
        message(
          language,
          "Demo dry-run: 0 requests. No server was started. Run demo without --dry-run to use the disposable local fixtures.",
          "План демо: 0 запросов. Сервер не запускался. Уберите --dry-run, чтобы проверить одноразовый локальный стенд.",
        ),
      );
      return;
    }
    const success = await runDemo({
      timeoutMs,
      outputDirectory: options.output,
      color: options.color,
      language,
      junitPath: resolveReportOption(
        options.junit,
        "junit.xml",
        options.output,
      ),
      sarifPath: resolveReportOption(
        options.sarif,
        "sarif.json",
        options.output,
      ),
    });
    process.exitCode = success ? 0 : 2;
  });

program.hook("preAction", async () => {
  const language = program.opts<CliOptions>().lang;
  if (
    shouldPersistLanguagePreference({
      explicitLanguage:
        program.getOptionValueSource("lang") === "cli" ? language : undefined,
      stdinIsTTY: input.isTTY,
      stdoutIsTTY: output.isTTY,
      ci: process.env.CI,
    })
  ) {
    const warning = await saveLanguagePreference(language);
    if (warning) {
      console.error(`${message(language, "WARNING", "ВНИМАНИЕ")}  ${warning}`);
    }
  }
});

program.parseAsync().catch((error: unknown) => {
  const language = program.opts<CliOptions>().lang ?? initialLanguage;
  console.error(
    `ERROR  ${safeTerminalText(redactText(error instanceof Error ? error.message : message(language, "BreakCurl exited with an error.", "BreakCurl завершился с ошибкой."), outputSecrets))}`,
  );
  process.exitCode = 2;
});

function rejectUnrelatedOptions(
  options: CliOptions,
  command: "idor" | "demo",
): void {
  const unsupported =
    options.profile ||
    options.security ||
    options.maxCases ||
    options.expectAuth ||
    options.authContract ||
    options.authBodyPath.length ||
    options.only.length ||
    options.exclude.length ||
    options.set.length ||
    options.remove.length ||
    (command === "demo" && options.config);
  if (unsupported)
    throw new Error(
      message(
        options.lang,
        `${command} has a fixed request plan; body/profile/auth/max-cases options do not apply. Use --dry-run to review its budget.`,
        `${command} использует фиксированный план; опции body/profile/auth/max-cases к нему не относятся. Проверьте бюджет через --dry-run.`,
      ),
    );
}

async function readJsonFile(
  path: string,
  language: Language,
): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new Error(
      message(
        language,
        `Cannot read valid JSON from ${path}.`,
        `Не удалось прочитать валидный JSON из ${path}.`,
      ),
    );
  }
}

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

function resolveReportOption(
  value: string | true | undefined,
  defaultName: string,
  outputDirectory: string,
): string | undefined {
  if (value === undefined) return undefined;
  return value === true ? join(outputDirectory, defaultName) : value;
}

async function readCurlInput(language: Language): Promise<string> {
  if (input.isTTY) return readPastedCurl(input, output, language);

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

async function confirmRequests(
  caseCount: number,
  includesAuthProbes: boolean,
  language: Language,
  idor = false,
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
        idor
          ? "BreakCurl will send up to 5 GET requests using two controlled identities. Confirm this is an authorized disposable fixture and the isolation contract is true. Continue? (y/N) "
          : `BreakCurl will send 1 baseline request and ${caseCount} check requests.\nThis may modify data in the target system.${includesAuthProbes ? "\nAuth probes may execute the operation without authorization if the endpoint is vulnerable." : ""}\nContinue? (y/N) `,
        idor
          ? "BreakCurl отправит до 5 GET-запросов от двух тестовых пользователей. Подтвердите разрешенный одноразовый стенд и корректность контракта изоляции. Продолжить? (y/N) "
          : `BreakCurl отправит 1 исходный запрос и ${caseCount} проверочных запросов.\nЭто может изменить данные в целевой системе.${includesAuthProbes ? "\nAuth-probes могут выполнить операцию без авторизации, если endpoint уязвим." : ""}\nПродолжить? (y/N) `,
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
    `${method} ${redactUrl(url, outputSecrets)}`,
    colorEnabled,
  );
  printKeyValue(
    message(language, "profile", "профиль"),
    profile.toUpperCase(),
    colorEnabled,
  );
  printKeyValue(
    message(language, "planned", "план"),
    message(
      language,
      `1 baseline + ${cases.length} checks = ${cases.length + 1} requests`,
      `исходный: 1; проверки: ${cases.length}; всего запросов: ${cases.length + 1}`,
    ),
    colorEnabled,
  );
  if (dryRun)
    printKeyValue(
      message(language, "sent", "отправлено"),
      message(language, "0 requests (dry-run)", "0 запросов (только план)"),
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
      redactText(renderText(note, language), outputSecrets),
      colorEnabled,
    );
  }
}

function printResults(
  result: RunResult,
  reportPath: string,
  jsonReportPath: string,
  findingPaths: string[],
  junitPath: string | undefined,
  sarifPath: string | undefined,
  colorEnabled: boolean,
  language: Language,
  htmlReportPath?: string,
): void {
  printSection(message(language, "RUN SUMMARY", "ИТОГ"), colorEnabled);
  printRunOutcome(result, colorEnabled, language);
  printResultSummary(result.cases, colorEnabled);
  printSection(message(language, "ARTIFACTS", "АРТЕФАКТЫ"), colorEnabled);
  if (htmlReportPath)
    printFileLink(
      message(language, "browser", "браузер"),
      htmlReportPath,
      colorEnabled,
    );
  printKeyValue(message(language, "report", "отчёт"), reportPath, colorEnabled);
  printKeyValue("json", jsonReportPath, colorEnabled);
  if (junitPath) printKeyValue("junit", junitPath, colorEnabled);
  if (sarifPath) printKeyValue("sarif", sarifPath, colorEnabled);
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
      `  ${String(index + 1).padStart(3)}. [${item.category ?? "negative"}] ${safeTerminalText(redactText(renderText(item.description, language), outputSecrets))} — expect ${item.expectation ?? "legacy"}`,
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
