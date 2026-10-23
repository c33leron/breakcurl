import { createHash } from "node:crypto";
import { localized, renderText } from "./i18n.js";
import type {
  CaseResult,
  Classification,
  FindingConfidence,
  FindingSeverity,
  HttpResult,
  MutationCase,
  ParsedCurl,
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
  return withSignals(
    classifyHttpResult(mutation, response, context),
    detectSecuritySignals(mutation, response),
  );
}

function classifyHttpResult(
  mutation: MutationCase,
  response: HttpResult,
  context: ClassificationContext,
): ClassificationResult {
  // A received server-error status remains evidence even if its body fails.
  if (response.status >= 500) {
    return {
      classification: "FAIL",
      reason: localized(
        `The API returned HTTP ${response.status}.`,
        `API вернул HTTP ${response.status}.`,
      ),
      severity: "HIGH",
      confidence: "HIGH",
    };
  }

  if (response.timedOut) {
    return {
      classification: "ERROR",
      reason: localized(
        "The request timed out; the check could not be fully evaluated.",
        "Запрос завершился по тайм-ауту; проверку не удалось полностью выполнить.",
      ),
    };
  }

  if (response.connectionError) {
    return {
      classification: "ERROR",
      reason: localized(
        "A connection error prevented the check from being fully evaluated.",
        "Ошибка соединения не позволила полностью выполнить проверку.",
      ),
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

  if (response.status >= 300 && response.status < 400) {
    return {
      classification: "ERROR",
      reason: localized(
        `Received HTTP ${response.status} redirect; BreakCurl does not follow redirects.`,
        `Получен redirect HTTP ${response.status}; BreakCurl не переходит по redirects.`,
      ),
    };
  }

  // JWT status checks require the same explicit authentication basis as
  // ordinary auth probes. A successful status alone does not prove a bypass.
  if (mutation.kind.startsWith("jwt-")) {
    return classifyJwt(mutation, response);
  }

  if (
    (mutation.category === "authentication" ||
      mutation.expectation === "auth-reject") &&
    isSuccessful(response.status) &&
    (context.expectAuth === true || mutation.expectation === "auth-reject")
  ) {
    return classifyAuthentication(mutation, response, context);
  }

  if (response.bodyTruncated) {
    return {
      classification: "ERROR",
      reason: localized(
        `The HTTP ${response.status} response exceeded the retained body limit; the complete response contract could not be evaluated.`,
        `Ответ HTTP ${response.status} превысил лимит сохраняемого тела; контракт полного ответа не удалось проверить.`,
      ),
    };
  }

  if (
    declaresJson(response) &&
    response.body.trim() !== "" &&
    !isValidJson(response.body)
  ) {
    return {
      classification: "FAIL",
      reason: localized(
        "The response declares JSON but contains invalid JSON.",
        "Ответ объявлен как JSON, но содержит невалидный JSON.",
      ),
      severity: "MEDIUM",
      confidence: "HIGH",
    };
  }

  if (mutation.kind === "method-tamper") {
    return classifyMethodTamper(mutation, response);
  }

  if (mutation.kind === "spec-probe") {
    return classifySpecProbe(mutation, response);
  }

  if (mutation.kind === "privilege-field") {
    return {
      classification: "INFO",
      reason: localized(
        `Privilege-field probe returned HTTP ${response.status}; persistence and permission changes were not verified. An accepted request does not prove mass assignment.`,
        `Проба привилегированного поля вернула HTTP ${response.status}; сохранение поля и изменение прав не проверялись. Успешный запрос не доказывает mass assignment.`,
      ),
    };
  }

  if (
    mutation.category === "authentication" ||
    mutation.expectation === "auth-reject"
  ) {
    return classifyAuthentication(mutation, response, context);
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

export function responseSchemaFingerprint(response: HttpResult): string | null {
  if (
    response.bodyOmitted ||
    response.bodyTruncated ||
    response.timedOut ||
    response.connectionError
  )
    return null;
  return createHash("sha256")
    .update(`${response.status}:${responseContractShape(response)}`)
    .digest("hex")
    .slice(0, 16);
}

function classifyJwt(
  mutation: MutationCase,
  response: HttpResult,
): ClassificationResult {
  const expiryNote =
    mutation.kind === "jwt-expired"
      ? localized(
          " Changing exp also invalidates the signature; expiry enforcement was not assessed.",
          " Изменение exp также ломает подпись; проверка срока токена не оценивалась.",
        )
      : localized("", "");
  if (response.status === 401 || response.status === 403) {
    return {
      classification: mutation.kind === "jwt-expired" ? "INFO" : "PASS",
      reason: localized(
        `The request carrying the modified JWT was rejected with HTTP ${response.status}; the rejecting control was not identified.${renderText(expiryNote, "en")}`,
        `Запрос с изменённым JWT отклонён с HTTP ${response.status}; конкретный механизм отказа не установлен.${renderText(expiryNote, "ru")}`,
      ),
    };
  }

  if (isSuccessful(response.status)) {
    const strict = mutation.expectation === "auth-reject";
    return {
      classification: strict ? "FAIL" : "WARN",
      reason: localized(
        strict
          ? `The modified-JWT request returned HTTP ${response.status} instead of the required 401/403 under the declared sole-Bearer auth contract. Signature verification, identity and side effects were not independently verified.${renderText(expiryNote, "en")}`
          : `The modified-JWT request returned HTTP ${response.status}; JWT-only authentication is not established. Public access or another credential may explain success; no signature bypass is proven.${renderText(expiryNote, "en")}`,
        strict
          ? `Запрос с изменённым JWT вернул HTTP ${response.status} вместо требуемого 401/403 по заявленному контракту с единственным Bearer. Проверка подписи, личность и побочные эффекты независимо не подтверждались.${renderText(expiryNote, "ru")}`
          : `Запрос с изменённым JWT вернул HTTP ${response.status}; не установлено, что JWT — единственный источник авторизации. Ответ может объясняться публичным доступом или другим credential; обход подписи не доказан.${renderText(expiryNote, "ru")}`,
      ),
      severity: strict ? "HIGH" : "MEDIUM",
      confidence: strict ? "HIGH" : "MEDIUM",
      securitySignals: [
        {
          id: "jwt-auth-rejection-missing",
          title: localized(
            "Modified JWT received a successful HTTP status; review the auth contract",
            "Запрос с изменённым JWT получил успешный HTTP-статус; проверьте auth-контракт",
          ),
          severity: strict ? "HIGH" : "MEDIUM",
          cwe: "CWE-347",
          owasp: "API2:2023",
        },
      ],
    };
  }

  if (isClientError(response.status)) {
    return {
      classification: "WARN",
      reason: localized(
        `The modified-JWT request received HTTP ${response.status}; this does not identify the authentication control.${renderText(expiryNote, "en")}`,
        `Запрос с изменённым JWT получил HTTP ${response.status}; это не определяет механизм проверки авторизации.${renderText(expiryNote, "ru")}`,
      ),
      severity: "LOW",
      confidence: "HIGH",
    };
  }

  return {
    classification: "ERROR",
    reason: localized(
      `The tampered JWT probe returned unexpected HTTP ${response.status}.`,
      `Проба подменённого JWT вернула неожиданный HTTP ${response.status}.`,
    ),
  };
}

function classifyMethodTamper(
  mutation: MutationCase,
  response: HttpResult,
): ClassificationResult {
  if (isSuccessful(response.status)) {
    return {
      classification: "WARN",
      reason: localized(
        `The endpoint accepted HTTP ${mutation.method} with HTTP ${response.status}; verify per-method authorization is intended.`,
        `Endpoint принял HTTP ${mutation.method} с ответом ${response.status}; проверьте, что авторизация по методам предусмотрена.`,
      ),
      severity: "MEDIUM",
      confidence: "MEDIUM",
      securitySignals: [
        {
          id: "unexpected-method-accepted",
          title: localized(
            `Endpoint processed the request under an unexpected HTTP method (${mutation.method})`,
            `Endpoint обработал запрос неожиданным HTTP-методом (${mutation.method})`,
          ),
          severity: "MEDIUM",
          cwe: "CWE-284",
          owasp: "API5:2023",
        },
      ],
    };
  }

  return {
    classification: "PASS",
    reason: localized(
      `The endpoint rejected the alternative method with HTTP ${response.status}.`,
      `Endpoint отклонил альтернативный метод с HTTP ${response.status}.`,
    ),
  };
}

function classifySpecProbe(
  mutation: MutationCase,
  response: HttpResult,
): ClassificationResult {
  let looksLikeSpec = false;
  if (isSuccessful(response.status)) {
    try {
      const document: unknown = JSON.parse(response.body);
      if (isRecord(document)) {
        const version = document.openapi ?? document.swagger;
        const schema = isRecord(document.data)
          ? document.data.__schema
          : undefined;
        looksLikeSpec =
          (typeof version === "string" &&
            /^(?:2|3)\./.test(version) &&
            isRecord(document.paths)) ||
          (isRecord(schema) && Array.isArray(schema.types));
      }
    } catch {
      // A docs UI identifies its actual renderer, not a technology name in an error.
      looksLikeSpec =
        /text\/html/i.test(getHeader(response.headers, "content-type") ?? "") &&
        /(?:SwaggerUIBundle\s*\(|<redoc\b|swagger-ui-bundle\.js)/i.test(
          response.body,
        );
    }
  }
  if (looksLikeSpec) {
    return {
      classification: "WARN",
      reason: localized(
        `${mutation.path} is reachable without authentication and returns what looks like an API specification (HTTP ${response.status}).`,
        `${mutation.path} доступен без аутентификации и возвращает похожее на спецификацию API тело (HTTP ${response.status}).`,
      ),
      severity: "MEDIUM",
      confidence: "MEDIUM",
      securitySignals: [
        {
          id: "api-spec-exposure",
          title: localized(
            "API specification is exposed without authentication",
            "Спецификация API открыта без аутентификации",
          ),
          severity: "MEDIUM",
          cwe: "CWE-200",
          owasp: "API9:2023",
        },
      ],
    };
  }

  if (isSuccessful(response.status)) {
    return {
      classification: "INFO",
      reason: localized(
        `${mutation.path} returned HTTP ${response.status}, but the body does not look like an API specification.`,
        `${mutation.path} вернул HTTP ${response.status}, но тело не похоже на спецификацию API.`,
      ),
    };
  }

  return {
    classification: "PASS",
    reason: localized(
      `${mutation.path} is not exposed without authentication (HTTP ${response.status}).`,
      `${mutation.path} недоступен без аутентификации (HTTP ${response.status}).`,
    ),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
    const expectsAuth =
      context.expectAuth === true || mutation.expectation === "auth-reject";
    return {
      classification: expectsAuth ? "FAIL" : "WARN",
      reason: expectsAuth
        ? localized(
            `The auth probe returned HTTP ${response.status} instead of the required 401/403. Resource access and side effects were not verified.`,
            `Auth-probe получил HTTP ${response.status} вместо обязательного 401/403. Доступ к ресурсу и побочные действия не проверялись.`,
          )
        : localized(
            `The auth probe returned successful HTTP ${response.status}; the endpoint may be public and must be checked against requirements.`,
            `Auth-probe получил успешный HTTP ${response.status}; endpoint может быть публичным, это нужно подтвердить требованиями.`,
          ),
      severity: expectsAuth ? "HIGH" : "MEDIUM",
      confidence: expectsAuth ? "HIGH" : "MEDIUM",
      securitySignals: [
        {
          id: "authentication-not-enforced",
          title: localized(
            "Auth probe returned a successful HTTP status",
            "Auth-probe получил успешный HTTP-статус",
          ),
          severity: expectsAuth ? "HIGH" : "MEDIUM",
          cwe: "CWE-306",
          owasp: "API2:2023",
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

  // Excessive data exposure (API3:2023) — scan the in-memory response body
  // for password hashes and sensitive-named fields. Values never leave this
  // function: only the signal identity is reported.
  const exposure = scanBodyExposure(body);
  if (exposure.passwordHash) {
    signals.push({
      id: "password-hash-exposure",
      title: localized(
        "Response exposes a password or secret hash (bcrypt/argon2/crypt)",
        "Ответ раскрывает хеш пароля или секрета (bcrypt/argon2/crypt)",
      ),
      severity: "HIGH",
      cwe: "CWE-200",
      owasp: "API3:2023",
    });
  }
  if (exposure.sensitiveField) {
    signals.push({
      id: "sensitive-field-response",
      title: localized(
        "Response returns a value for a sensitive-named field",
        "Ответ возвращает значение чувствительного поля",
      ),
      severity: "MEDIUM",
      cwe: "CWE-200",
      owasp: "API3:2023",
    });
  }

  return signals;
}

const PASSWORD_HASH_PATTERN =
  /^\$(?:2[aby]|argon2(?:id|i|d)?|[56](?:y|b)?)[$A-Za-z0-9+/,.]/;
const SENSITIVE_RESPONSE_FIELD =
  /(?:password|passwd|pwd|secret|private[_-]?key)/i;

interface BodyExposure {
  passwordHash: boolean;
  sensitiveField: boolean;
}

function scanBodyExposure(body: string): BodyExposure {
  const result: BodyExposure = { passwordHash: false, sensitiveField: false };
  if (body.length === 0) return result;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return result;
  }
  walkJson(parsed, result);
  return result;
}

function walkJson(value: unknown, result: BodyExposure): void {
  if (Array.isArray(value)) {
    for (const item of value) walkJson(item, result);
    return;
  }
  if (typeof value === "string") {
    if (PASSWORD_HASH_PATTERN.test(value)) result.passwordHash = true;
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (
      SENSITIVE_RESPONSE_FIELD.test(key) &&
      typeof child === "string" &&
      child.trim() !== "" &&
      !PASSWORD_HASH_PATTERN.test(child)
    ) {
      result.sensitiveField = true;
    }
    walkJson(child, result);
  }
}

/**
 * Security configuration audit (API8:2023) for the baseline response:
 * CORS wildcards with credentials, missing cookie protections, missing HSTS,
 * and verbose server headers. Runs once per run on the baseline so
 * configuration observations do not repeat on every mutated response.
 */
export function auditResponseHeaders(
  request: ParsedCurl,
  response: HttpResult,
): SecuritySignal[] {
  const signals: SecuritySignal[] = [];
  const allowOrigin = getHeader(
    response.headers,
    "access-control-allow-origin",
  );
  const allowCredentials = getHeader(
    response.headers,
    "access-control-allow-credentials",
  );
  if (allowOrigin?.trim() === "*" && allowCredentials?.trim() === "true") {
    signals.push({
      id: "cors-wildcard-credentials",
      title: localized(
        "CORS wildcard and credentials are incompatible; browsers block credentialed response access",
        "CORS wildcard несовместим с credentials; браузеры блокируют чтение такого credentialed-ответа",
      ),
      severity: "LOW",
      cwe: "CWE-942",
      owasp: "API8:2023",
    });
  }

  const setCookie = getHeader(response.headers, "set-cookie");
  if (setCookie) {
    const unsafeCookie = setCookie.split("\n").some((cookie) => {
      const attributes = cookie
        .split(";")
        .slice(1)
        .map((attribute) => attribute.trim().toLowerCase());
      return !attributes.includes("secure") || !attributes.includes("httponly");
    });
    if (unsafeCookie) {
      signals.push({
        id: "cookie-flags-missing",
        title: localized(
          "Set-Cookie lacks the Secure or HttpOnly protection",
          "Set-Cookie без защиты Secure или HttpOnly",
        ),
        severity: "MEDIUM",
        cwe: "CWE-614",
        owasp: "API8:2023",
      });
    }
  }

  const hsts = getHeader(response.headers, "strict-transport-security");
  const maxAgeDirectives =
    hsts
      ?.split(";")
      .map((part) => part.trim())
      .filter((part) => /^max-age\b/i.test(part)) ?? [];
  const maxAge =
    maxAgeDirectives.length === 1
      ? maxAgeDirectives[0]?.match(/^max-age\s*=\s*(?:"(\d+)"|(\d+))$/i)
      : undefined;
  const hstsEnabled = Boolean(maxAge && Number(maxAge[1] ?? maxAge[2]) > 0);
  if (request.url.toLowerCase().startsWith("https:") && !hstsEnabled) {
    signals.push({
      id: "hsts-missing",
      title: localized(
        "HTTPS response has no valid positive HSTS max-age",
        "HTTPS-ответ не содержит валидного положительного max-age HSTS",
      ),
      severity: "LOW",
      cwe: "CWE-319",
      owasp: "API8:2023",
    });
  }

  const serverHeader = getHeader(response.headers, "server");
  if (serverHeader && /\d/.test(serverHeader)) {
    signals.push({
      id: "server-version-header",
      title: localized(
        "Server header reveals implementation version",
        "Заголовок Server раскрывает версию реализации",
      ),
      severity: "LOW",
      cwe: "CWE-200",
      owasp: "API8:2023",
    });
  }
  return signals;
}

/** Baseline assessment: classify the baseline response and audit its configuration once. */
export function classifyBaseline(
  request: ParsedCurl,
  response: HttpResult,
): ClassificationResult {
  const base = classifyCase(
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
  const configSignals = auditResponseHeaders(request, response);
  return withSignals(base, configSignals);
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
  if (signals.length === 0) return result;
  const securitySignals = [...(result.securitySignals ?? []), ...signals];
  if (result.classification === "FAIL" || result.classification === "ERROR") {
    return { ...result, securitySignals };
  }
  const strongerSignals = signals.some(
    (signal) => signal.id !== "technology-header",
  );
  return {
    ...result,
    classification:
      strongerSignals || result.classification === "WARN" ? "WARN" : "INFO",
    reason: localized(
      [
        renderText(result.reason, "en"),
        ...signals.map((signal) => renderText(signal.title, "en")),
      ].join("; "),
      [
        renderText(result.reason, "ru"),
        ...signals.map((signal) => renderText(signal.title, "ru")),
      ].join("; "),
    ),
    severity: highestSeverity(securitySignals, result.severity),
    confidence: result.confidence ?? "HIGH",
    securitySignals,
  };
}

function highestSeverity(
  signals: SecuritySignal[],
  existing?: FindingSeverity,
): FindingSeverity {
  if (
    existing === "HIGH" ||
    signals.some((signal) => signal.severity === "HIGH")
  )
    return "HIGH";
  if (
    existing === "MEDIUM" ||
    signals.some((signal) => signal.severity === "MEDIUM")
  )
    return "MEDIUM";
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
