import { localized } from "./i18n.js";
import type { LocalizedText, RunResult } from "./types.js";

export interface RunSummary {
  status: "incomplete" | "findings" | "review" | "complete";
  exitCode: 0 | 1 | 2;
  title: LocalizedText;
  explanation: LocalizedText;
  nextAction: LocalizedText;
  requestsAttempted: number;
  requestsPlanned: number | null;
  checksRun: number;
}

export function hasWorkingBaseline(result: RunResult): boolean {
  const { response, assessment } = result.baseline;
  return (
    response.status >= 200 &&
    response.status < 300 &&
    !response.timedOut &&
    !response.connectionError &&
    !response.bodyTruncated &&
    assessment?.classification !== "FAIL" &&
    assessment?.classification !== "ERROR"
  );
}

/** The same run outcome drives the CLI exit code and every human report. */
export function summarizeRun(result: RunResult): RunSummary {
  const requestsAttempted = result.completedRequests ?? result.cases.length + 1;
  const requestsPlanned = result.plannedRequests ?? null;
  const common = {
    requestsAttempted,
    requestsPlanned,
    checksRun: result.cases.length,
  };
  if (!hasWorkingBaseline(result)) {
    return {
      ...common,
      status: "incomplete",
      exitCode: 2,
      title: localized("Check incomplete", "Проверка не завершена"),
      explanation: localized(
        "The original request did not pass its control. This run cannot establish the behavior of the planned checks.",
        "Исходный запрос не прошел контроль. По этому запуску нельзя оценить поведение API в запланированных проверках.",
      ),
      nextAction: localized(
        "Inspect the baseline response below. Restore a working request and valid test credentials, then repeat the run.",
        "Посмотрите исходный ответ ниже. Восстановите рабочий запрос и действующие тестовые учетные данные, затем повторите запуск.",
      ),
    };
  }
  if (
    (requestsPlanned !== null && requestsAttempted < requestsPlanned) ||
    result.cases.some(
      (item) =>
        item.classification === "ERROR" ||
        item.response.timedOut ||
        Boolean(item.response.connectionError) ||
        item.response.bodyTruncated,
    )
  ) {
    return {
      ...common,
      status: "incomplete",
      exitCode: 2,
      title: localized("Check incomplete", "Проверка не завершена"),
      explanation: localized(
        "At least one planned check could not be fully evaluated. Any findings already recorded remain valid evidence, but this run is incomplete.",
        "Как минимум одну запланированную проверку не удалось полностью оценить. Уже полученные находки сохранены, но запуск не завершен.",
      ),
      nextAction: localized(
        "Inspect the failed control, incomplete response, or stop reason below. Resolve it before repeating the run; respect Retry-After if present.",
        "Посмотрите непройденный контроль, неполный ответ или причину остановки ниже. Устраните причину перед повтором; при наличии Retry-After выдержите указанный интервал.",
      ),
    };
  }
  if (result.cases.some((item) => item.classification === "FAIL")) {
    return {
      ...common,
      status: "findings",
      exitCode: 1,
      title: localized("Failures found", "Найдены нарушения"),
      explanation: localized(
        "The run found a server failure or a violation of a tested contract. The findings below explain the evidence and its limits.",
        "Обнаружен сбой сервера или нарушение проверяемого контракта. В находках ниже указаны доказательства и границы вывода.",
      ),
      nextAction: localized(
        "Start with a FAIL finding. Reproduce it with disposable data and confirm the impact using server logs and final state.",
        "Начните с находки FAIL. Повторите ее на одноразовых данных и подтвердите влияние по логам сервера и итоговому состоянию.",
      ),
    };
  }
  if (
    result.baseline.assessment?.classification === "WARN" ||
    result.cases.some((item) => item.classification === "WARN")
  ) {
    return {
      ...common,
      status: "review",
      exitCode: 0,
      title: localized("Signals need review", "Есть сигналы для проверки"),
      explanation: localized(
        "No FAIL was recorded, but at least one observation needs confirmation. Exit code 0 does not turn a warning into a passed security check.",
        "FAIL не зафиксирован, но как минимум одно наблюдение требует подтверждения. Код завершения 0 не означает, что предупреждение стало успешной проверкой безопасности.",
      ),
      nextAction: localized(
        "Review the WARN observations against your API contract and compare with a control request before filing a vulnerability.",
        "Сверьте наблюдения WARN с контрактом API и контрольным запросом, прежде чем оформлять уязвимость.",
      ),
    };
  }
  const baselineOnly = result.cases.length === 0;
  return {
    ...common,
    status: "complete",
    exitCode: 0,
    title: baselineOnly
      ? localized(
          "Only the original request was observed",
          "Проверен только исходный запрос",
        )
      : localized("Selected checks completed", "Выбранные проверки завершены"),
    explanation: baselineOnly
      ? localized(
          "No additional checks were run. A working original request does not establish authentication or object access protection.",
          "Дополнительные проверки не выполнялись. Работающий исходный запрос не подтверждает защиту авторизации или доступа к объектам.",
        )
      : localized(
          "No FAIL, WARN, or ERROR was recorded in the selected checks. This result covers only the requests sent, not the security of the entire API.",
          "В выбранных проверках не зафиксировано FAIL, WARN или ERROR. Результат относится только к отправленным запросам, а не к безопасности всего API.",
        ),
    nextAction: baselineOnly
      ? localized(
          "Review the coverage notes. Supply supported credentials and an auth contract, or a two-identity IDOR fixture, for the protection you want to test.",
          "Посмотрите пояснения об охвате. Для проверки защиты укажите поддерживаемые учетные данные и auth-контракт либо подготовьте IDOR-сценарий с двумя пользователями.",
        )
      : localized(
          "Review the coverage notes and keep this controlled fixture for repeatable regression checks.",
          "Посмотрите пояснения об охвате и сохраните этот тестовый сценарий для повторной проверки регрессии.",
        ),
  };
}
