import { createHash } from "node:crypto";
import { localized, renderText } from "./i18n.js";
import type {
  CaseResult,
  Classification,
  FindingConfidence,
  FindingSeverity,
  HttpResult,
  MutationCase,
  SecuritySignal,
  TranslatableText,
} from "./types.js";

export interface ClassificationContext {
  baseline?: HttpResult;
  expectAuth?: boolean;
}

export interface ClassificationResult {
  classification: Classification;
  reason: TranslatableText;
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
  securitySignals?: SecuritySignal[];
}

export function classifyCase(
  mutation: MutationCase,
  response: HttpResult,
  context: ClassificationContext = {},
): ClassificationResult {
  if (response.timedOut) {
    return {
      classification: "WARN",
      reason: localized(
        "The request timed out after a successful baseline request.",
        "Запрос завершился по тайм-ауту после успешного исходного запроса.",
      ),
      severity: "MEDIUM",
      confidence: "HIGH",
    };
  }

  if (response.connectionError) {
    return {
      classification: "WARN",
      reason: localized(
        "A connection error occurred after a successful baseline request.",
        "После успешного исходного запроса произошла ошибка соединения.",
      ),
      severity: "MEDIUM",
      confidence: "MEDIUM",
    };
  }

  if (response.status === 429) {
    return {
      classification: "ERROR",
      reason: localized(
        "The API returned HTTP 429. The check does not prove validation behavior because the rate limit was reached.",
        "API вернул HTTP 429. Результат проверки не доказывает валидацию: достигнут rate limit.",
      ),
    };
  }

  const securitySignals = detectSecuritySignals(mutation, response);

  if (response.status >= 500) {
    return withSignals(
      {
        classification: "FAIL",
        reason: localized(
          `The API returned HTTP ${response.status}.`,
          `API вернул HTTP ${response.status}.`,
        ),
        severity: "HIGH",
        confidence: "HIGH",
      },
      securitySignals,
    );
  }

  if (
    declaresJson(response) &&
    response.body.trim() !== "" &&
    !isValidJson(response.body)
  ) {
    return withSignals(
      {
        classification: "FAIL",
        reason: localized(
          "The response declares JSON but contains invalid JSON.",
          "Ответ объявлен как JSON, но содержит невалидный JSON.",
        ),
        severity: "MEDIUM",
        confidence: "HIGH",
      },
      securitySignals,
    );
  }

  if (securitySignals.length > 0) {
    return {
      classification: "WARN",
      reason: localized(
        securitySignals
          .map((signal) => renderText(signal.title, "en"))
          .join("; "),
        securitySignals
          .map((signal) => renderText(signal.title, "ru"))
          .join("; "),
      ),
      severity: highestSeverity(securitySignals),
      confidence: "HIGH",
      securitySignals,
    };
  }

  if (mutation.category === "authentication") {
    return classifyAuthentication(mutation, response, context);
  }

  if (response.status >= 300 && response.status < 400) {
    return {
      classification: "ERROR",
      reason: localized(
        `Received HTTP ${response.status} redirect; BreakCurl does not follow redirects.`,
        `Получен redirect HTTP ${response.status}; BreakCurl не переходит по redirects.`,
      ),
    };
  }

  const expectation = mutation.expectation;
  if (expectation === "reject") {
    if (response.status >= 400 && response.status < 500) {
      return {
        classification: "PASS",
        reason: localized(
          `The API rejected the check in a controlled way with HTTP ${response.status}.`,
          `API контролируемо отклонил проверку с HTTP ${response.status}.`,
        ),
      };
    }
    if (isSuccessful(response.status)) {
      return {
        classification: "WARN",
        reason: localized(
          `The API accepted a value that was expected to be rejected with HTTP ${response.status}.`,
          `API принял значение, которое ожидалось отклонить, с HTTP ${response.status}.`,
        ),
        severity: "MEDIUM",
        confidence: "MEDIUM",
      };
    }
  }

  if (expectation === "accept") {
    if (isSuccessful(response.status)) {
      return {
        classification: "PASS",
        reason: localized(
          `The API accepted the value as expected with HTTP ${response.status}.`,
          `API выполнил ожидаемое принятие с HTTP ${response.status}.`,
        ),
      };
    }
    if (response.status >= 400 && response.status < 500) {
      return {
        classification: "WARN",
        reason: localized(
          `The API rejected a value that was expected to be accepted with HTTP ${response.status}.`,
          `API отклонил значение, которое ожидалось принять, с HTTP ${response.status}.`,
        ),
        severity: "LOW",
        confidence: "HIGH",
      };
    }
  }

  if (expectation === "observe") {
    if (isSuccessful(response.status) || isClientError(response.status)) {
      return {
        classification: "INFO",
        reason: localized(
          `Observation without a strict oracle: HTTP ${response.status}.`,
          `Наблюдение без жёсткого oracle: HTTP ${response.status}.`,
        ),
      };
    }
  }

  // Legacy behavior for callers creating the original v0.1 MutationCase shape.
  if (
    isSuccessful(response.status) &&
    (mutation.kind === "remove" || mutation.kind === "wrong-type")
  ) {
    return {
      classification: "WARN",
      reason: localized(
        `The API accepted ${mutation.kind === "remove" ? "a request with a removed field" : "a value of the wrong type"} with HTTP ${response.status}.`,
        `API принял ${mutation.kind === "remove" ? "запрос с удалённым полем" : "значение неправильного типа"} с HTTP ${response.status}.`,
      ),
      severity: "MEDIUM",
      confidence: "MEDIUM",
    };
  }

  if (isClientError(response.status)) {
    return {
      classification: "PASS",
      reason: localized(
        `The API rejected the mutation with HTTP ${response.status}.`,
        `API отклонил мутацию с HTTP ${response.status}.`,
      ),
    };
  }

  if (isSuccessful(response.status)) {
    return {
      classification: "PASS",
      reason: localized(
        `The API processed the mutation with HTTP ${response.status}.`,
        `API обработал мутацию с HTTP ${response.status}.`,
      ),
    };
  }

  return {
    classification: "ERROR",
    reason: localized(
      `Received unexpected HTTP status ${response.status}.`,
      `Получен неожиданный HTTP-статус ${response.status}.`,
    ),
  };
}

export function toCaseResult(
  mutation: MutationCase,
  response: HttpResult,
  context: ClassificationContext = {},
): CaseResult {
  return { mutation, response, ...classifyCase(mutation, response, context) };
}

export const classifyResponse = classifyCase;

export function responseSchemaFingerprint(response: HttpResult): string {
  return createHash("sha256")
    .update(`${response.status}:${responseContractShape(response)}`)
    .digest("hex")
    .slice(0, 16);
}

function classifyAuthentication(
  mutation: MutationCase,
  response: HttpResult,
  context: ClassificationContext,
): ClassificationResult {
  if (response.status === 401 || response.status === 403) {
    return {
      classification: "PASS",
      reason: localized(
        `The API rejected the auth probe with HTTP ${response.status}.`,
        `API отклонил auth-probe с HTTP ${response.status}.`,
      ),
    };
  }

  if (isSuccessful(response.status)) {
    const similar = context.baseline
      ? sameResponseContract(context.baseline, response)
      : false;
    const expectsAuth =
      context.expectAuth === true || mutation.expectation === "auth-reject";
    return {
      classification: expectsAuth ? "FAIL" : "WARN",
      reason: similar
        ? localized(
            `The auth probe returned HTTP ${response.status}, and its response contract matched the authorized baseline request.`,
            `Auth-probe получил HTTP ${response.status}, а контракт ответа совпал с авторизованным исходным запросом.`,
          )
        : localized(
            `The auth probe returned successful HTTP ${response.status}; the endpoint may be public and must be checked against requirements.`,
            `Auth-probe получил успешный HTTP ${response.status}; endpoint может быть публичным, это нужно подтвердить требованиями.`,
          ),
      severity: expectsAuth ? "HIGH" : "MEDIUM",
      confidence: similar ? "HIGH" : "MEDIUM",
      securitySignals: [
        {
          id: "authentication-not-enforced",
          title: localized(
            "Successful response without valid credentials",
            "Успешный ответ без корректных credentials",
          ),
          severity: expectsAuth ? "HIGH" : "MEDIUM",
          cwe: "CWE-306",
        },
      ],
    };
  }

  if (isClientError(response.status)) {
    return {
      classification: "WARN",
      reason: localized(
        `The auth probe returned HTTP ${response.status}, but only 401/403 proves an authentication rejection.`,
        `Auth-probe вернул HTTP ${response.status}, но только 401/403 доказывает auth-отказ.`,
      ),
      severity: "LOW",
      confidence: "HIGH",
    };
  }

  return {
    classification: "ERROR",
    reason: localized(
      `The auth probe returned unexpected HTTP ${response.status}.`,
      `Auth-probe вернул неожиданный HTTP ${response.status}.`,
    ),
  };
}

function detectSecuritySignals(
  mutation: MutationCase,
  response: HttpResult,
): SecuritySignal[] {
  const signals: SecuritySignal[] = [];
  const body = response.body;
  if (
    /(?:\bat\s+\S+\s+\([^\n]+:\d+:\d+\)|\b(?:stacktrace|stack trace)\b|\/(?:app|usr|var|home|users|opt)\/|[A-Z]:\\(?:Users|Program Files)\\)/i.test(
      body,
    )
  ) {
    signals.push({
      id: "internal-details",
      title: localized(
        "Response exposes a stack trace or internal path",
        "Ответ раскрывает stack trace или внутренний путь",
      ),
      severity: "MEDIUM",
      cwe: "CWE-209",
    });
  }
  if (
    /(?:SQLSTATE|syntax error at or near|mysql|postgresql|sqliteexception|ora-\d{4,}|mongoservererror|sequelize)/i.test(
      body,
    )
  ) {
    signals.push({
      id: "database-error",
      title: localized(
        "Response exposes a database or ORM error",
        "Ответ раскрывает ошибку базы данных или ORM",
      ),
      severity: "HIGH",
      cwe: "CWE-209",
    });
  }
  if (
    /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/.test(
      body,
    ) ||
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(body) ||
    /\bAKIA[A-Z0-9]{16}\b/.test(body)
  ) {
    signals.push({
      id: "secret-exposure",
      title: localized(
        "Response may contain a credential or private key",
        "Ответ, вероятно, содержит credential или private key",
      ),
      severity: "HIGH",
      cwe: "CWE-200",
    });
  }
  if (
    mutation.kind === "markup-probe" &&
    /text\/html/i.test(getHeader(response.headers, "content-type") ?? "") &&
    body.includes("<breakcurl-probe>")
  ) {
    signals.push({
      id: "html-reflection",
      title: localized(
        "Markup probe is reflected unescaped in an HTML response",
        "Markup probe без экранирования отражён в HTML-ответе",
      ),
      severity: "MEDIUM",
      cwe: "CWE-79",
    });
  }
  if (getHeader(response.headers, "x-powered-by")) {
    signals.push({
      id: "technology-header",
      title: localized(
        "Response exposes technology through X-Powered-By",
        "Ответ раскрывает технологию через X-Powered-By",
      ),
      severity: "LOW",
      cwe: "CWE-200",
    });
  }
  return signals;
}

function sameResponseContract(left: HttpResult, right: HttpResult): boolean {
  if (Math.floor(left.status / 100) !== Math.floor(right.status / 100)) {
    return false;
  }
  return responseContractShape(left) === responseContractShape(right);
}

function responseContractShape(response: HttpResult): string {
  const contentType = getHeader(response.headers, "content-type") ?? "unknown";
  let shape: string;
  try {
    shape = JSON.stringify(jsonShape(JSON.parse(response.body)));
  } catch {
    shape = `non-json:${lengthBucket(response.body.length)}`;
  }
  return `${contentType}:${shape}`;
}

function jsonShape(value: unknown): unknown {
  if (value === null) return "null";
  if (Array.isArray(value)) {
    return {
      array: [
        ...new Set(
          value.slice(0, 10).map((item) => JSON.stringify(jsonShape(item))),
        ),
      ].sort(),
    };
  }
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, jsonShape(child)]),
    );
  }
  return typeof value;
}

function lengthBucket(length: number): string {
  if (length === 0) return "empty";
  if (length < 100) return "small";
  if (length < 1_000) return "medium";
  if (length < 10_000) return "large";
  return "very-large";
}

function withSignals(
  result: ClassificationResult,
  signals: SecuritySignal[],
): ClassificationResult {
  return signals.length > 0 ? { ...result, securitySignals: signals } : result;
}

function highestSeverity(signals: SecuritySignal[]): FindingSeverity {
  if (signals.some((signal) => signal.severity === "HIGH")) return "HIGH";
  if (signals.some((signal) => signal.severity === "MEDIUM")) return "MEDIUM";
  return "LOW";
}

function declaresJson(response: HttpResult): boolean {
  return (
    getHeader(response.headers, "content-type")
      ?.toLowerCase()
      .includes("json") ?? false
  );
}

function getHeader(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  return Object.entries(headers).find(
    ([header]) => header.toLowerCase() === name.toLowerCase(),
  )?.[1];
}

function isValidJson(body: string): boolean {
  try {
    JSON.parse(body);
    return true;
  } catch {
    return false;
  }
}

function isSuccessful(status: number): boolean {
  return status >= 200 && status < 300;
}

function isClientError(status: number): boolean {
  return status >= 400 && status < 500;
}
