import { createHash } from "node:crypto";
import { message } from "./i18n.js";
import { sendRequest } from "./runner.js";
import type {
  CaseResult,
  HttpResult,
  Language,
  LocalizedText,
  ParsedCurl,
  RunResult,
} from "./types.js";

/** These declarations describe the disposable fixture, not inferred API rules. */
export interface IdorConfig {
  authModel: "bearer-only";
  objectIdsGrantAccess: false;
  rule: "a-cannot-read-b";
  privateCanaries: true;
  identity: {
    url: string;
    principalPointer: string;
    actorA: string;
    actorB: string;
  };
  objects: {
    pathTemplate: string;
    idPointer: string;
    canaryPointer: string;
    objectA: { id: string; canary: string };
    objectB: { id: string; canary: string };
  };
}

export interface IdorPlannedRequest {
  id: "me-a" | "me-b" | "own-a" | "own-b" | "cross-a-to-b";
  label: string;
  description: LocalizedText;
  request: ParsedCurl;
}

export interface IdorPlan {
  origin: string;
  requests: IdorPlannedRequest[];
  /** In-memory only. Pass to report redaction, never print/serialize the plan. */
  knownSecrets: string[];
}

export interface IdorExecutionOptions {
  timeoutMs: number;
  language?: Language;
  /** Called for every completed request, including baseline at index zero. */
  onResult?: (result: CaseResult, index: number) => void;
}

// Keep expected private values separate from printable plan descriptions and
// require plans created by this module. Freeze them to close validation/use gaps.
const planConfigs = new WeakMap<IdorPlan, IdorConfig>();

export function parseIdorConfig(
  value: unknown,
  language: Language = "en",
): IdorConfig {
  const root = object(value, language);
  keys(
    root,
    [
      "authModel",
      "objectIdsGrantAccess",
      "rule",
      "privateCanaries",
      "identity",
      "objects",
      "$schema",
    ],
    language,
  );
  if (
    root.authModel !== "bearer-only" ||
    root.objectIdsGrantAccess !== false ||
    root.rule !== "a-cannot-read-b" ||
    root.privateCanaries !== true
  ) {
    fail(
      language,
      "IDOR requires bearer-only auth, non-capability object IDs, the A-to-B deny rule, and independently seeded private canaries.",
      "Для IDOR нужны bearer-only авторизация, ID без права доступа, запрет A к B и независимо созданные приватные canary.",
    );
  }
  const identity = object(root.identity, language);
  keys(identity, ["url", "principalPointer", "actorA", "actorB"], language);
  const objects = object(root.objects, language);
  keys(
    objects,
    ["pathTemplate", "idPointer", "canaryPointer", "objectA", "objectB"],
    language,
  );
  const a = object(objects.objectA, language);
  const b = object(objects.objectB, language);
  keys(a, ["id", "canary"], language);
  keys(b, ["id", "canary"], language);
  const config: IdorConfig = {
    authModel: "bearer-only",
    objectIdsGrantAccess: false,
    rule: "a-cannot-read-b",
    privateCanaries: true,
    identity: {
      url: string(identity.url, language),
      principalPointer: pointer(identity.principalPointer, language),
      actorA: string(identity.actorA, language),
      actorB: string(identity.actorB, language),
    },
    objects: {
      pathTemplate: string(objects.pathTemplate, language),
      idPointer: pointer(objects.idPointer, language),
      canaryPointer: pointer(objects.canaryPointer, language),
      objectA: {
        id: string(a.id, language),
        canary: string(a.canary, language),
      },
      objectB: {
        id: string(b.id, language),
        canary: string(b.canary, language),
      },
    },
  };
  if (
    config.identity.actorA === config.identity.actorB ||
    config.objects.objectA.id === config.objects.objectB.id
  ) {
    fail(
      language,
      "IDOR requires distinct expected actors and distinct object IDs.",
      "Для IDOR нужны разные ожидаемые пользователи и разные ID объектов.",
    );
  }
  if (config.objects.idPointer === config.objects.canaryPointer) {
    fail(
      language,
      "Object ID and private canary must use different JSON pointers.",
      "ID объекта и приватный canary должны иметь разные JSON Pointer.",
    );
  }
  validateUrl(config.identity.url, language);
  const parts = config.objects.pathTemplate.split("/");
  if (
    !config.objects.pathTemplate.startsWith("/") ||
    parts.filter((part) => part === "{objectId}").length !== 1 ||
    parts.slice(1).some((part) => part !== "{objectId}" && !safeSegment(part))
  ) {
    fail(
      language,
      "The object path template must contain exactly one {objectId} segment and otherwise literal safe path segments.",
      "Шаблон пути должен содержать ровно один сегмент {objectId} и остальные буквальные безопасные сегменты.",
    );
  }
  const fixtures = [config.objects.objectA, config.objects.objectB];
  for (const fixture of fixtures) {
    if (!safeSegment(fixture.id)) {
      fail(
        language,
        "Object IDs must be single unencoded URL path segments.",
        "ID объектов должны быть отдельными незакодированными сегментами URL.",
      );
    }
    if (!/^[\x21-\x7e]{16,256}$/.test(fixture.canary)) {
      fail(
        language,
        "Private canaries must contain 16 to 256 printable ASCII characters without spaces.",
        "Приватные canary должны содержать от 16 до 256 печатных ASCII-символов без пробелов.",
      );
    }
    for (const other of fixtures) {
      const derived = new Set([
        other.id,
        encodeURIComponent(other.id),
        Buffer.from(other.id).toString("base64"),
        Buffer.from(other.id).toString("base64url"),
        ...["md5", "sha1", "sha256"].map((algorithm) =>
          createHash(algorithm).update(other.id).digest("hex"),
        ),
      ]);
      if (
        derived.has(fixture.canary) ||
        (other.id.length >= 8 && fixture.canary.includes(other.id))
      ) {
        fail(
          language,
          "Private canaries must be independently seeded, not derived from object IDs.",
          "Приватные canary должны создаваться независимо от ID объектов.",
        );
      }
    }
  }
  if (config.objects.objectA.canary === config.objects.objectB.canary) {
    fail(
      language,
      "Objects A and B require distinct private canaries.",
      "Объектам A и B нужны разные приватные canary.",
    );
  }
  return config;
}

/** Validates the whole bounded scenario without sending any network traffic. */
export function prepareIdorPlan(
  a: ParsedCurl,
  b: ParsedCurl,
  inputConfig: IdorConfig,
  language: Language = "en",
): IdorPlan {
  const config = parseIdorConfig(inputConfig, language);
  const objectA = validateObjectRequest(a, language);
  const objectB = validateObjectRequest(b, language);
  const identityUrl = validateUrl(config.identity.url, language);
  const urlA = validateUrl(a.url, language);
  const urlB = validateUrl(b.url, language);
  if (urlA.origin !== urlB.origin || urlA.origin !== identityUrl.origin) {
    fail(
      language,
      "All IDOR requests must use the same origin.",
      "Все IDOR-запросы должны использовать один origin.",
    );
  }
  if (objectA.headers.Authorization === objectB.headers.Authorization) {
    fail(
      language,
      "Actors A and B require distinct bearer credentials.",
      "Пользователям A и B нужны разные bearer credentials.",
    );
  }
  if (objectA.headers.Accept !== objectB.headers.Accept) {
    fail(
      language,
      "The two object requests may differ only in their object ID and bearer token.",
      "Два запроса объектов могут отличаться только ID объекта и bearer-токеном.",
    );
  }
  for (const [url, fixture] of [
    [urlA, config.objects.objectA],
    [urlB, config.objects.objectB],
  ] as const) {
    if (
      url.pathname !==
      config.objects.pathTemplate.replace("{objectId}", fixture.id)
    ) {
      fail(
        language,
        "Both object URLs must match the declared path template and their expected object IDs.",
        "URL обоих объектов должны соответствовать шаблону пути и ожидаемым ID объектов.",
      );
    }
  }
  const me = (request: ParsedCurl): ParsedCurl => ({
    method: "GET",
    url: config.identity.url,
    headers: {
      Authorization: request.headers.Authorization ?? "",
      Accept: "application/json",
    },
    body: {},
  });
  const requests: IdorPlannedRequest[] = [
    {
      id: "me-a",
      label: "A identity",
      description: {
        en: "Verify actor A identity",
        ru: "Подтвердить пользователя A",
      },
      request: me(objectA),
    },
    {
      id: "me-b",
      label: "B identity",
      description: {
        en: "Verify actor B identity",
        ru: "Подтвердить пользователя B",
      },
      request: me(objectB),
    },
    {
      id: "own-a",
      label: "A reads own object",
      description: {
        en: "Verify actor A reads object A",
        ru: "Подтвердить чтение объекта A пользователем A",
      },
      request: objectA,
    },
    {
      id: "own-b",
      label: "B reads own object",
      description: {
        en: "Verify actor B reads object B",
        ru: "Подтвердить чтение объекта B пользователем B",
      },
      request: objectB,
    },
    {
      id: "cross-a-to-b",
      label: "A reads B object",
      description: {
        en: "Check denied read of object B by actor A",
        ru: "Проверить запрет чтения объекта B пользователем A",
      },
      request: {
        ...objectB,
        headers: {
          ...objectB.headers,
          Authorization: objectA.headers.Authorization ?? "",
        },
        body: {},
      },
    },
  ];
  const canaries = [
    config.objects.objectA.canary,
    config.objects.objectB.canary,
  ];
  for (const item of requests) {
    for (const value of [
      item.request.url,
      ...Object.keys(item.request.headers),
      ...Object.values(item.request.headers),
      JSON.stringify(item.request.body),
    ]) {
      if (containsCanary(value, canaries)) {
        fail(
          language,
          "A private canary or its supported encoding occurs in a prepared request; reflection cannot prove IDOR.",
          "Приватный canary или его поддерживаемое кодирование найдено в запросе; отражение не доказывает IDOR.",
        );
      }
    }
  }
  const plan: IdorPlan = {
    origin: urlA.origin,
    requests,
    knownSecrets: [
      objectA.headers.Authorization?.slice(7) ?? "",
      objectB.headers.Authorization?.slice(7) ?? "",
      ...canaries,
    ],
  };
  freeze(config);
  freeze(plan);
  planConfigs.set(plan, config);
  return plan;
}

export async function executeIdorPlan(
  plan: IdorPlan,
  options: IdorExecutionOptions,
): Promise<RunResult> {
  const language = options.language ?? "en";
  const config = planConfigs.get(plan);
  if (!config)
    fail(
      language,
      "IDOR execution requires a validated plan.",
      "Для IDOR нужен проверенный план.",
    );
  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
    fail(
      language,
      "Request timeout must be a positive number of milliseconds.",
      "Таймаут запроса должен быть положительным числом миллисекунд.",
    );
  }
  const results: CaseResult[] = [];
  const notes: LocalizedText[] = [
    {
      en: "Scope: one declared A-to-B object read, with bearer-only authentication and independently seeded private canaries. Fixture ownership, private visibility and the deny rule are user declarations. Other actors, objects, operations and authentication models were not checked. Response bodies, headers and compared values are discarded.",
      ru: "Охват: одно чтение объекта B пользователем A с bearer-only авторизацией и независимыми приватными canary. Владение, приватность и запрет доступа заданы автором fixture. Другие пользователи, объекты, операции и схемы авторизации не проверялись. Тела, заголовки ответов и сравниваемые значения не сохраняются.",
    },
  ];
  for (const [index, item] of plan.requests.entries()) {
    const response = await sendRequest(item.request, options.timeoutMs);
    const assessment = assess(response, index, config);
    const result: CaseResult = {
      mutation: {
        id: `idor-${item.id}`,
        path: item.id,
        description: item.description,
        kind: "custom-set",
        category: "custom",
        source: "custom",
        expectation: index === 4 ? "auth-reject" : "accept",
        body: {},
        url: item.request.url,
        headers: { ...item.request.headers },
      },
      response: { ...response, body: "", headers: {}, bodyOmitted: true },
      ...assessment,
    };
    results.push(result);
    const mustStop =
      response.status === 429 ||
      (index < 4 && result.classification !== "PASS");
    options.onResult?.(result, index);
    if (mustStop) {
      notes.push(
        response.status === 429
          ? {
              en: "HTTP 429 stopped the entire IDOR run immediately. No retries or remaining requests were sent.",
              ru: "HTTP 429 немедленно остановил весь IDOR-запуск. Повторные и оставшиеся запросы не отправлялись.",
            }
          : {
              en: "A required identity or own-object control failed; remaining requests were not sent. No cross-account conclusion is available.",
              ru: "Обязательный контроль пользователя или собственного объекта не пройден; оставшиеся запросы не отправлялись. Вывода о межпользовательском доступе нет.",
            },
      );
      break;
    }
  }
  const first = results[0];
  const firstRequest = plan.requests[0];
  if (!first || !firstRequest) throw new Error("Validated IDOR plan is empty.");
  const { mutation: _mutation, response, ...assessment } = first;
  return {
    baseline: { request: firstRequest.request, response, assessment },
    cases: results.slice(1),
    language,
    mode: "idor",
    profile: "security",
    plannedRequests: 5,
    completedRequests: results.length,
    notes,
  };
}

type Assessment = Pick<
  CaseResult,
  "classification" | "reason" | "severity" | "confidence" | "securitySignals"
>;

function assess(
  response: HttpResult,
  index: number,
  config: IdorConfig,
): Assessment {
  const inconclusive = (en: string, ru: string): Assessment => ({
    classification: "ERROR",
    reason: { en, ru },
  });
  if (response.status === 429)
    return inconclusive(
      "HTTP 429: rate limited; stopped without retries. IDOR is inconclusive.",
      "HTTP 429: ограничение запросов; остановлено без повторов. IDOR не определен.",
    );
  if (
    response.timedOut ||
    response.connectionError ||
    response.bodyTruncated !== false
  )
    return inconclusive(
      "The response is incomplete or transport failed; IDOR is inconclusive.",
      "Ответ неполный или произошла ошибка передачи; IDOR не определен.",
    );
  if (response.status === 401)
    return inconclusive(
      "HTTP 401: credentials were rejected or expired; IDOR is inconclusive.",
      "HTTP 401: credentials отклонены или просрочены; IDOR не определен.",
    );
  let json: unknown;
  try {
    json = JSON.parse(response.body);
  } catch {
    json = undefined;
  }
  if (index < 2) {
    const actor = index === 0 ? "A" : "B";
    const principalMatches =
      readPointer(json, config.identity.principalPointer) ===
      (index === 0 ? config.identity.actorA : config.identity.actorB);
    if (response.status >= 200 && response.status < 300 && principalMatches)
      return {
        classification: "PASS",
        reason: {
          en: `Actor ${actor} identity control: expectedPrincipalMatch=true.`,
          ru: `Контроль пользователя ${actor}: expectedPrincipalMatch=true.`,
        },
      };
    return inconclusive(
      `Actor ${actor} identity control did not pass: expectedPrincipalMatch=${principalMatches}; no following requests were sent.`,
      `Контроль пользователя ${actor} не пройден: expectedPrincipalMatch=${principalMatches}; следующие запросы не отправлены.`,
    );
  }
  const fixture = index === 2 ? config.objects.objectA : config.objects.objectB;
  const objectIdMatch =
    readPointer(json, config.objects.idPointer) === fixture.id;
  const privateCanaryMatch =
    readPointer(json, config.objects.canaryPointer) === fixture.canary;
  const evidence = `objectIdMatch=${objectIdMatch}; privateCanaryMatch=${privateCanaryMatch}`;
  if (index < 4) {
    const actor = index === 2 ? "A" : "B";
    if (
      response.status >= 200 &&
      response.status < 300 &&
      objectIdMatch &&
      privateCanaryMatch
    )
      return {
        classification: "PASS",
        reason: {
          en: `Actor ${actor} own-object control: ${evidence}.`,
          ru: `Контроль собственного объекта пользователя ${actor}: ${evidence}.`,
        },
      };
    return inconclusive(
      `Actor ${actor} own-object control did not pass: ${evidence}; no following requests were sent.`,
      `Контроль собственного объекта пользователя ${actor} не пройден: ${evidence}; следующие запросы не отправлены.`,
    );
  }
  // Inspect evidence before the denial status: an HTTP 403 can still leak data.
  if (objectIdMatch && privateCanaryMatch)
    return {
      classification: "FAIL",
      severity: "HIGH",
      confidence: "HIGH",
      reason: {
        en: `Actor A received object B and its private canary despite the declared deny rule: ${evidence}. Evidence applies only to this read and fixture contract.`,
        ru: `Пользователь A получил объект B и его приватный canary вопреки заявленному запрету: ${evidence}. Доказательство относится только к этому чтению и контракту fixture.`,
      },
      securitySignals: [
        {
          id: "idor-private-object-disclosure",
          title: {
            en: "Cross-account private object disclosure",
            ru: "Раскрытие приватного объекта другому пользователю",
          },
          severity: "HIGH",
          cwe: "CWE-639",
        },
      ],
    };
  if (
    (response.status === 403 || response.status === 404) &&
    !privateCanaryMatch &&
    !containsCanary(response.body, [fixture.canary])
  )
    return {
      classification: "PASS",
      reason: {
        en: `Actor A was denied object B without its private marker: ${evidence}.`,
        ru: `Пользователю A отказано в объекте B без его приватного маркера: ${evidence}.`,
      },
    };
  return inconclusive(
    `The cross-account response does not establish either the expected denial or private object disclosure: ${evidence}.`,
    `Ответ межпользовательского запроса не подтверждает ожидаемый отказ или раскрытие приватного объекта: ${evidence}.`,
  );
}

function validateObjectRequest(
  request: ParsedCurl,
  language: Language,
): ParsedCurl {
  if (request.method !== "GET" || Object.keys(request.body).length !== 0)
    fail(
      language,
      "IDOR supports only two GET object requests without bodies.",
      "IDOR поддерживает только два GET-запроса объектов без тела.",
    );
  validateUrl(request.url, language);
  const normalized: Record<string, string> = {};
  const seen = new Set<string>();
  for (const [name, value] of Object.entries(request.headers)) {
    const key = name.toLowerCase();
    if (seen.has(key) || (key !== "authorization" && key !== "accept"))
      fail(
        language,
        "IDOR permits only one Authorization header and optional Accept: application/json; duplicate or extra headers are forbidden.",
        "IDOR разрешает только один Authorization и необязательный Accept: application/json; дубли и лишние заголовки запрещены.",
      );
    seen.add(key);
    if (key === "authorization") {
      if (!/^Bearer [A-Za-z0-9._~+/-]+=*$/i.test(value))
        fail(
          language,
          "IDOR requires a single Bearer token in Authorization.",
          "Для IDOR нужен один Bearer-токен в Authorization.",
        );
      normalized.Authorization = `Bearer ${value.slice(7)}`;
    } else {
      if (value !== "application/json")
        fail(
          language,
          "IDOR only supports Accept: application/json.",
          "IDOR поддерживает только Accept: application/json.",
        );
      normalized.Accept = value;
    }
  }
  if (!normalized.Authorization)
    fail(
      language,
      "Both IDOR requests require bearer authorization.",
      "Обоим IDOR-запросам нужна bearer-авторизация.",
    );
  return { method: "GET", url: request.url, headers: normalized, body: {} };
}

function validateUrl(value: string, language: Language): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(
      language,
      "IDOR requires valid absolute HTTP(S) URLs.",
      "Для IDOR нужны валидные абсолютные HTTP(S) URL.",
    );
  }
  if (
    !/^https?:$/.test(url.protocol) ||
    url.username ||
    url.password ||
    value.includes("?") ||
    value.includes("#") ||
    /[\s\\]/.test(value) ||
    url.href !== value
  )
    fail(
      language,
      "IDOR URLs must be canonical HTTP(S), without userinfo, query strings, fragments, whitespace or backslashes.",
      "IDOR URL должны быть каноническими HTTP(S), без userinfo, query, fragment, пробелов и обратных слешей.",
    );
  return url;
}

function containsCanary(value: string, canaries: string[]): boolean {
  let candidates = new Set([value]);
  for (let depth = 0; depth < 4; depth += 1) {
    const next = new Set<string>();
    for (const candidate of candidates) {
      if (canaries.some((canary) => candidate.includes(canary))) return true;
      try {
        next.add(decodeURIComponent(candidate));
      } catch {
        /* Malformed encoding is not a decoder input. */
      }
      next.add(
        candidate
          .replace(/\\u([\da-f]{4})/gi, (_match, hex: string) =>
            String.fromCharCode(Number.parseInt(hex, 16)),
          )
          .replaceAll("\\/", "/"),
      );
      for (const chunk of [
        ...(candidate.match(/[A-Za-z\d+/_-]{16,}={0,2}/g) ?? []),
        ...(candidate.match(/[A-Za-z\d_-]{16,}/g) ?? []),
      ]) {
        const decoded = Buffer.from(chunk, "base64url").toString("utf8");
        if (!decoded.includes("\ufffd")) next.add(decoded);
      }
    }
    candidates = next;
  }
  return [...candidates].some((candidate) =>
    canaries.some((canary) => candidate.includes(canary)),
  );
}

function readPointer(value: unknown, jsonPointer: string): unknown {
  let current = value;
  for (const segment of jsonPointer
    .slice(1)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))) {
    if (
      typeof current !== "object" ||
      current === null ||
      !Object.hasOwn(current, segment)
    )
      return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function object(value: unknown, language: Language): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    fail(
      language,
      "IDOR config sections must be objects.",
      "Разделы IDOR-конфига должны быть объектами.",
    );
  return value as Record<string, unknown>;
}

function keys(
  value: Record<string, unknown>,
  allowed: string[],
  language: Language,
): void {
  if (Object.keys(value).some((key) => !allowed.includes(key)))
    fail(
      language,
      "IDOR config contains an unsupported field.",
      "IDOR-конфиг содержит неподдерживаемое поле.",
    );
}

function string(value: unknown, language: Language): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2048 ||
    [...value].some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    fail(
      language,
      "IDOR config requires nonempty bounded strings without control characters.",
      "IDOR-конфиг требует непустые строки ограниченной длины без управляющих символов.",
    );
  return value;
}

function pointer(value: unknown, language: Language): string {
  const result = string(value, language);
  if (!result.startsWith("/") || /~(?![01])/.test(result))
    fail(
      language,
      "IDOR response paths must be non-root RFC 6901 JSON pointers.",
      "Пути ответов IDOR должны быть некорневыми JSON Pointer по RFC 6901.",
    );
  return result;
}

function safeSegment(value: string): boolean {
  return (
    /^[A-Za-z\d_~-][A-Za-z\d._~-]*$/.test(value) &&
    value !== "." &&
    value !== ".."
  );
}

function freeze(value: object): void {
  for (const item of Object.values(value))
    if (typeof item === "object" && item !== null) freeze(item);
  Object.freeze(value);
}

function fail(language: Language, en: string, ru: string): never {
  throw new Error(message(language, en, ru));
}
