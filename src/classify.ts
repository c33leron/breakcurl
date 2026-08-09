import { createHash } from "node:crypto";
import type {
  CaseResult,
  Classification,
  FindingConfidence,
  FindingSeverity,
  HttpResult,
  MutationCase,
  SecuritySignal,
} from "./types.js";

export interface ClassificationContext {
  baseline?: HttpResult;
  expectAuth?: boolean;
}

export interface ClassificationResult {
  classification: Classification;
  reason: string;
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
      reason:
        "Запрос завершился по тайм-ауту после успешного исходного запроса.",
      severity: "MEDIUM",
      confidence: "HIGH",
    };
  }

  if (response.connectionError) {
    return {
      classification: "WARN",
      reason: "После успешного исходного запроса произошла ошибка соединения.",
      severity: "MEDIUM",
      confidence: "MEDIUM",
    };
  }

  const securitySignals = detectSecuritySignals(mutation, response);

  if (response.status >= 500) {
    return withSignals(
      {
        classification: "FAIL",
        reason: `API вернул HTTP ${response.status}.`,
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
        reason: "Ответ объявлен как JSON, но содержит невалидный JSON.",
        severity: "MEDIUM",
        confidence: "HIGH",
      },
      securitySignals,
    );
  }

  if (securitySignals.length > 0) {
    return {
      classification: "WARN",
      reason: securitySignals.map((signal) => signal.title).join("; "),
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
      reason: `Получен redirect HTTP ${response.status}; BreakCurl не переходит по redirects.`,
    };
  }

  const expectation = mutation.expectation;
  if (expectation === "reject") {
    if (response.status >= 400 && response.status < 500) {
      return {
        classification: "PASS",
        reason: `API контролируемо отклонил проверку с HTTP ${response.status}.`,
      };
    }
    if (isSuccessful(response.status)) {
      return {
        classification: "WARN",
        reason: `API принял значение, которое ожидалось отклонить, с HTTP ${response.status}.`,
        severity: "MEDIUM",
        confidence: "MEDIUM",
      };
    }
  }

  if (expectation === "accept") {
    if (isSuccessful(response.status)) {
      return {
        classification: "PASS",
        reason: `API выполнил ожидаемое принятие с HTTP ${response.status}.`,
      };
    }
    if (response.status >= 400 && response.status < 500) {
      return {
        classification: "WARN",
        reason: `API отклонил значение, которое ожидалось принять, с HTTP ${response.status}.`,
        severity: "LOW",
        confidence: "HIGH",
      };
    }
  }

  if (expectation === "observe") {
    if (isSuccessful(response.status) || isClientError(response.status)) {
      return {
        classification: "INFO",
        reason: `Наблюдение без жёсткого oracle: HTTP ${response.status}.`,
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
      reason: `API принял ${mutation.kind === "remove" ? "запрос с удалённым полем" : "значение неправильного типа"} с HTTP ${response.status}.`,
      severity: "MEDIUM",
      confidence: "MEDIUM",
    };
  }

  if (isClientError(response.status)) {
    return {
      classification: "PASS",
      reason: `API отклонил мутацию с HTTP ${response.status}.`,
    };
  }

  if (isSuccessful(response.status)) {
    return {
      classification: "PASS",
      reason: `API обработал мутацию с HTTP ${response.status}.`,
    };
  }

  return {
    classification: "ERROR",
    reason: `Получен неожиданный HTTP-статус ${response.status}.`,
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
      reason: `API отклонил auth-probe с HTTP ${response.status}.`,
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
        ? `Auth-probe получил HTTP ${response.status}, а контракт ответа совпал с авторизованным исходным запросом.`
        : `Auth-probe получил успешный HTTP ${response.status}; endpoint может быть публичным, это нужно подтвердить требованиями.`,
      severity: expectsAuth ? "HIGH" : "MEDIUM",
      confidence: similar ? "HIGH" : "MEDIUM",
      securitySignals: [
        {
          id: "authentication-not-enforced",
          title: "Успешный ответ без корректных credentials",
          severity: expectsAuth ? "HIGH" : "MEDIUM",
          cwe: "CWE-306",
        },
      ],
    };
  }

  if (isClientError(response.status)) {
    return {
      classification: "WARN",
      reason: `Auth-probe вернул HTTP ${response.status}, но только 401/403 доказывает auth-отказ.`,
      severity: "LOW",
      confidence: "HIGH",
    };
  }

  return {
    classification: "ERROR",
    reason: `Auth-probe вернул неожиданный HTTP ${response.status}.`,
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
      title: "Ответ раскрывает stack trace или внутренний путь",
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
      title: "Ответ раскрывает ошибку базы данных или ORM",
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
      title: "Ответ, вероятно, содержит credential или private key",
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
      title: "Markup probe без экранирования отражён в HTML-ответе",
      severity: "MEDIUM",
      cwe: "CWE-79",
    });
  }
  if (getHeader(response.headers, "x-powered-by")) {
    signals.push({
      id: "technology-header",
      title: "Ответ раскрывает технологию через X-Powered-By",
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
