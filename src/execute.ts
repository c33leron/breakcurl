import { classifyCase } from "./classify.js";
import { localized } from "./i18n.js";
import { requestForCase } from "./mutations.js";
import { hasWorkingBaseline, summarizeRun } from "./run-summary.js";
import { sendRequest } from "./runner.js";
import type {
  BaselineResult,
  CaseResult,
  CheckProfile,
  Language,
  MutationCase,
  ParsedCurl,
  RunResult,
  TranslatableText,
} from "./types.js";

interface ExecutionOptions {
  timeoutMs: number;
  profile: CheckProfile;
  language: Language;
  notes?: TranslatableText[];
  onBaseline?: (baseline: BaselineResult) => void;
  onCase?: (item: CaseResult, index: number) => void;
  onStop?: (note: TranslatableText) => void;
}

/** Executes an already reviewed plan. CLI must obtain permission before calling. */
export async function executeChecks(
  request: ParsedCurl,
  mutations: MutationCase[],
  options: ExecutionOptions,
): Promise<RunResult> {
  if (mutations.length > 200)
    throw new Error("The request plan exceeds 200 checks.");
  const response = await sendRequest(request, options.timeoutMs);
  const assessment = classifyCase(
    {
      id: "baseline",
      path: "$",
      description: "Baseline response",
      kind: "custom-set",
      category: "protocol",
      expectation: "observe",
      body: request.body,
    },
    response,
  );
  const result: RunResult = {
    baseline: { request, response, assessment },
    cases: [],
    profile: options.profile,
    language: options.language,
    mode: "checks",
    plannedRequests: mutations.length + 1,
    completedRequests: 1,
    notes: [...(options.notes ?? [])],
  };
  options.onBaseline?.(result.baseline);
  if (!hasWorkingBaseline(result)) {
    const note =
      response.timedOut || response.connectionError || response.bodyTruncated
        ? localized(
            "The baseline request did not complete. No mutations were sent.",
            "Исходный запрос не удалось проверить полностью. Мутации не отправлялись.",
          )
        : localized(
            `The baseline request returned ${response.status} with an unusable response contract. No mutations were sent.`,
            `Исходный запрос вернул ${response.status}, его контракт непригоден для проверки. Мутации не отправлялись.`,
          );
    result.notes?.push(note);
    options.onStop?.(note);
    return result;
  }
  for (const [index, mutation] of mutations.entries()) {
    const response = await sendRequest(
      requestForCase(request, mutation),
      options.timeoutMs,
    );
    const item: CaseResult = {
      mutation,
      response,
      ...classifyCase(mutation, response, {
        baseline: result.baseline.response,
      }),
    };
    result.cases.push(item);
    result.completedRequests = index + 2;
    options.onCase?.(item, index);
    if (
      response.status === 429 ||
      response.timedOut ||
      response.connectionError
    ) {
      const skipped = mutations.length - result.cases.length;
      const retryAfter = response.headers["retry-after"];
      const note =
        response.status === 429
          ? localized(
              `Safety stop: received HTTP 429${retryAfter ? ` (Retry-After: ${retryAfter})` : ""}; skipped checks: ${skipped}.`,
              `Защитная остановка: получен HTTP 429${retryAfter ? ` (Retry-After: ${retryAfter})` : ""}; пропущено проверок: ${skipped}.`,
            )
          : localized(
              `Safety stop: transport failure; skipped checks: ${skipped}.`,
              `Защитная остановка: сбой соединения; пропущено проверок: ${skipped}.`,
            );
      result.notes?.push(note);
      options.onStop?.(note);
      break;
    }
  }
  return result;
}

export { hasWorkingBaseline } from "./run-summary.js";

export function exitCodeForRun(result: RunResult): number {
  return summarizeRun(result).exitCode;
}
