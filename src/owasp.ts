import { localized } from "./i18n.js";
import type {
  CaseResult,
  HttpResult,
  MutationKind,
  OwaspCoverageEntry,
  RunResult,
} from "./types.js";

/**
 * Computes what this run actually covered against the OWASP API Security
 * Top 10 (2023). Statuses are derived from the executed checks — the matrix
 * never claims coverage a run did not attempt. "out-of-scope" items are
 * deliberate design boundaries, not TODOs.
 */
export function owaspCoverage(result: RunResult): OwaspCoverageEntry[] {
  const idor = result.mode === "idor";
  const evaluated = (item: CaseResult) =>
    item.classification !== "ERROR" &&
    completeResponse(item.response) &&
    // IDOR evaluates the private canary in memory, then discards the body.
    (idor || !item.response.bodyOmitted);
  const probes = (...kinds: MutationKind[]) => {
    const sent = result.cases.filter((item) =>
      kinds.includes(item.mutation.kind),
    );
    return { sent, evaluated: sent.filter(evaluated) };
  };
  const crossRead = idor
    ? result.cases.find(
        (item) =>
          item.mutation.id === "idor-cross-a-to-b" &&
          item.mutation.kind === "custom-set",
      )
    : undefined;
  const baselineAudited =
    result.mode === "checks" &&
    result.baseline.assessment !== undefined &&
    result.baseline.assessment.classification !== "ERROR" &&
    completeResponse(result.baseline.response) &&
    !result.baseline.response.bodyOmitted;

  const auth = probes(
    "auth-missing",
    "auth-invalid",
    "jwt-alg-none",
    "jwt-signature-strip",
    "jwt-claim-tamper",
    "jwt-expired",
  );
  const authLabels = {
    "auth-missing": localized("credential removal", "удаление credentials"),
    "auth-invalid": localized("credential invalidation", "подмена credentials"),
    "jwt-alg-none": localized("JWT alg=none", "JWT alg=none"),
    "jwt-signature-strip": localized(
      "JWT signature stripping",
      "удаление подписи JWT",
    ),
    "jwt-claim-tamper": localized("JWT claim tampering", "подмена claims JWT"),
    "jwt-expired": localized(
      "modified JWT exp with an invalidated signature (not expiry enforcement)",
      "подмена exp JWT с нарушением подписи (не проверка срока действия)",
    ),
  };
  const authKinds = [
    ...new Set(auth.evaluated.map((item) => item.mutation.kind)),
  ] as (keyof typeof authLabels)[];
  const privilege = probes("privilege-field");
  const methods = probes("method-tamper");
  const specs = probes("spec-probe");

  return [
    {
      item: "API1:2023",
      title: "Broken Object Level Authorization (BOLA/IDOR)",
      status: crossRead
        ? evaluated(crossRead)
          ? "tested"
          : "partial"
        : "not-tested",
      detail: crossRead
        ? evaluated(crossRead)
          ? localized(
              "The declared A-to-B object read was evaluated using private canaries. Coverage is limited to this read and fixture contract.",
              "Заявленное чтение объекта B пользователем A проверено по приватным canary. Охват ограничен этим чтением и контрактом fixture.",
            )
          : localized(
              "The cross-identity request was sent but could not be fully evaluated; no BOLA conclusion is available.",
              "Межпользовательский запрос отправлен, но его не удалось полностью оценить; вывода о BOLA нет.",
            )
        : idor
          ? localized(
              "The cross-identity read was not reached; the run stopped during required identity or own-object controls.",
              "До межпользовательского чтения не дошли: запуск остановился на обязательном контроле личности или собственного объекта.",
            )
          : localized(
              "Requires two controlled identities and a private-object contract; use the idor command.",
              "Нужны две контролируемые личности и контракт приватного объекта; используйте команду idor.",
            ),
    },
    {
      item: "API2:2023",
      title: "Broken Authentication",
      status: probeStatus(auth),
      detail: auth.evaluated.length
        ? localized(
            `Evaluated ${auth.evaluated.length} of ${auth.sent.length} sent probes against this endpoint: ${authKinds.map((kind) => authLabels[kind].en).join(", ")}. These bounded probes do not establish full authentication coverage.${auth.sent.length !== auth.evaluated.length ? " Other sent authentication probes could not be fully evaluated." : ""}`,
            `На этом endpoint оценено ${auth.evaluated.length} из ${auth.sent.length} отправленных проб: ${authKinds.map((kind) => authLabels[kind].ru).join(", ")}. Эти ограниченные пробы не дают полного покрытия аутентификации.${auth.sent.length !== auth.evaluated.length ? " Другие отправленные auth-пробы не удалось полностью оценить." : ""}`,
          )
        : auth.sent.length
          ? localized(
              "Authentication probes were sent but could not be fully evaluated; no authentication conclusion is available.",
              "Auth-пробы отправлены, но их не удалось полностью оценить; вывода об аутентификации нет.",
            )
          : localized(
              "No credential-removal, credential-invalidation, or JWT-tampering probes were executed in this run.",
              "В этом запуске не выполнялись пробы удаления/подмены credentials или JWT.",
            ),
    },
    {
      item: "API3:2023",
      title: "Broken Object Property Level Authorization",
      status:
        baselineAudited || privilege.sent.length ? "partial" : "not-tested",
      detail: localized(
        [
          baselineAudited
            ? "The baseline response was scanned for exposure."
            : "No completed baseline exposure assessment is recorded.",
          privilege.evaluated.length
            ? `${privilege.evaluated.length} of ${privilege.sent.length} sent mass-assignment probe responses were evaluated; field persistence and authorization effects were not verified.`
            : privilege.sent.length
              ? "Mass-assignment probes were sent but could not be fully evaluated."
              : "No active property probes were executed.",
        ].join(" "),
        [
          baselineAudited
            ? "Исходный ответ проверен на утечки."
            : "Завершённая проверка исходного ответа на утечки не зафиксирована.",
          privilege.evaluated.length
            ? `Оценено ${privilege.evaluated.length} из ${privilege.sent.length} ответов mass-assignment проб; сохранение полей и влияние на авторизацию не проверялись.`
            : privilege.sent.length
              ? "Mass-assignment пробы отправлены, но их не удалось полностью оценить."
              : "Активные пробы полей не выполнялись.",
        ].join(" "),
      ),
    },
    {
      item: "API4:2023",
      title: "Unrestricted Resource Consumption",
      status: "out-of-scope",
      detail: localized(
        "Load, race, and rate-limit testing is excluded by design (sequential bounded runs).",
        "Нагрузочные, race и rate-limit тесты исключены архитектурно (строго последовательные ограниченные запуски).",
      ),
    },
    {
      item: "API5:2023",
      title: "Broken Function Level Authorization",
      status: methods.sent.length ? "partial" : "not-tested",
      detail: methods.evaluated.length
        ? localized(
            `${methods.evaluated.length} of ${methods.sent.length} sent alternative HTTP method responses were evaluated for this endpoint. Role-specific function permissions were not verified.`,
            `Оценено ${methods.evaluated.length} из ${methods.sent.length} ответов endpoint на альтернативные HTTP-методы. Права ролей на выполнение функций не проверялись.`,
          )
        : methods.sent.length
          ? localized(
              "Alternative HTTP method requests were sent but could not be fully evaluated; function authorization was not established.",
              "Запросы с альтернативными HTTP-методами отправлены, но их не удалось полностью оценить; проверка прав на функции не завершена.",
            )
          : localized(
              "Enable --attack-methods to replay the endpoint with alternative HTTP verbs (may modify or delete data).",
              "Включите --attack-methods, чтобы повторить endpoint с другими HTTP-методами (может изменить или удалить данные).",
            ),
    },
    {
      item: "API6:2023",
      title: "Unrestricted Access to Sensitive Business Flows",
      status: "out-of-scope",
      detail: localized(
        "Multi-step business-flow automation is outside the single-request model.",
        "Автоматизация многошаговых бизнес-процессов вне модели одиночных запросов.",
      ),
    },
    {
      item: "API7:2023",
      title: "Server Side Request Forgery (SSRF)",
      status: "out-of-scope",
      detail: localized(
        "No outbound SSRF testing in this version; URL-like inputs are only observed.",
        "Исходящий SSRF-тест в этой версии отсутствует; URL-подобные входы только наблюдаются.",
      ),
    },
    {
      item: "API8:2023",
      title: "Security Misconfiguration",
      status: baselineAudited ? "partial" : "not-tested",
      detail: baselineAudited
        ? localized(
            "Baseline response audited for CORS configuration, cookie flags, HSTS, and verbose headers.",
            "Исходный ответ проверен на настройки CORS, флаги cookie, HSTS и подробные заголовки.",
          )
        : localized(
            "No completed baseline response-header audit is recorded for this run.",
            "Завершённая проверка заголовков исходного ответа для этого запуска не зафиксирована.",
          ),
    },
    {
      item: "API9:2023",
      title: "Improper Inventory Management",
      status: probeStatus(specs),
      detail: specs.evaluated.length
        ? localized(
            `${specs.evaluated.length} of ${specs.sent.length} sent same-origin spec-discovery responses were evaluated. Coverage is limited to those paths, not a complete API inventory.`,
            `Оценено ${specs.evaluated.length} из ${specs.sent.length} ответов отправленных same-origin проб поиска спецификаций. Охват ограничен этими путями, а не полным инвентарём API.`,
          )
        : specs.sent.length
          ? localized(
              "Same-origin spec-discovery requests were sent but could not be fully evaluated; spec exposure was not established.",
              "Same-origin запросы поиска спецификаций отправлены, но их не удалось полностью оценить; раскрытие спецификаций не установлено.",
            )
          : localized(
              "Same-origin spec discovery runs in the security and full profiles.",
              "Same-origin поиск спецификаций выполняется в профилях security и full.",
            ),
    },
    {
      item: "API10:2023",
      title: "Unsafe Consumption of APIs",
      status: "out-of-scope",
      detail: localized(
        "BreakCurl does not act as a client of third-party APIs; nothing to attack through.",
        "BreakCurl не является клиентом сторонних API; атаковать через него нечего.",
      ),
    },
  ];
}

function completeResponse(response: HttpResult): boolean {
  return (
    response.status > 0 &&
    response.status !== 429 &&
    !response.timedOut &&
    !response.connectionError &&
    !response.bodyTruncated
  );
}

function probeStatus(probes: {
  sent: CaseResult[];
  evaluated: CaseResult[];
}): OwaspCoverageEntry["status"] {
  if (probes.sent.length === 0) return "not-tested";
  return probes.evaluated.length === probes.sent.length ? "tested" : "partial";
}
