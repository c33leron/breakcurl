import { englishText, localized, message } from "./i18n.js";
import type {
  CheckCategory,
  CheckExpectation,
  CheckGenerationOptions,
  CheckProfile,
  CustomCaseDefinition,
  GeneratedChecks,
  JsonObject,
  JsonValue,
  Language,
  MutationCase,
  MutationKind,
  ParsedCurl,
  TranslatableText,
} from "./types.js";

type PathSegment = string | number;

interface Field {
  path: string;
  segments: PathSegment[];
  value: JsonValue;
}

interface CaseTemplate {
  kind: MutationKind;
  value: JsonValue;
  category: CheckCategory;
  expectation: CheckExpectation;
}

const MAX_CASES = 200;
const INVALID_CREDENTIAL = "BREAKCURL_INVALID_CREDENTIAL";
const SENSITIVE_FIELD_NAME =
  /password|passphrase|token|secret|authorization|auth|credential|cookie|session|jwt|api[_-]?key/i;
const SENSITIVE_QUERY_NAME =
  /password|token|secret|auth|credential|cookie|session|jwt|api[_-]?key/i;
const AUTH_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "x-api-key",
  "api-key",
  "x-auth-token",
]);

/**
 * Generates profile-driven checks. Explicit custom cases are never silently
 * discarded by the limit, and automatic checks are distributed breadth-first
 * across JSON paths instead of exhausting the first field.
 */
export function generateChecks(
  request: ParsedCurl,
  options: CheckGenerationOptions,
): GeneratedChecks {
  const language = options.language ?? "en";
  validateMaxCases(options.maxCases, language);

  const notes: GeneratedChecks["notes"] = [];
  const customCases = (options.customCases ?? []).map((definition, index) =>
    createCustomCase(request, definition, index, language),
  );
  const fixedCases: MutationCase[] = [...customCases];

  if (options.profile === "security" || options.profile === "full") {
    const authCases = createAuthCases(request, options.expectAuth ?? false);
    if (authCases.length === 0) {
      notes.push(
        localized(
          "Auth checks were skipped: no credentials were found in the source cURL.",
          "Auth-проверки пропущены: в исходном cURL не найдено credentials.",
        ),
      );
    } else {
      fixedCases.push(...authCases);
    }
  }

  if (fixedCases.length > options.maxCases) {
    throw new Error(
      message(
        language,
        `Explicit and priority checks require ${fixedCases.length} cases, but --max-cases=${options.maxCases}. Increase the limit.`,
        `Явные и приоритетные проверки требуют ${fixedCases.length} кейсов, но --max-cases=${options.maxCases}. Увеличьте лимит.`,
      ),
    );
  }

  const fields = collectFields(request.body).filter((field) =>
    pathIsSelected(
      field.path,
      options.onlyPaths ?? [],
      options.excludePaths ?? [],
    ),
  );
  const perField = fields.map((field) =>
    mutationsForField(request.body, field, options.profile),
  );
  const automaticCases = interleave(perField);
  if (options.profile === "security" || options.profile === "full") {
    automaticCases.push(createContentTypeCase(request));
  }
  if (options.profile !== "quick") {
    automaticCases.push(createUnknownFieldCase(request));
  }
  const cases = [...fixedCases, ...automaticCases].slice(0, options.maxCases);

  if (automaticCases.length + fixedCases.length > cases.length) {
    notes.push(
      localized(
        `The limit stopped generation: selected ${cases.length} of ${automaticCases.length + fixedCases.length} available checks.`,
        `Лимит остановил генерацию: выбрано ${cases.length} из ${automaticCases.length + fixedCases.length} доступных проверок.`,
      ),
    );
  }
  if (
    fields.length === 0 &&
    customCases.length === 0 &&
    fixedCases.length === 0
  ) {
    notes.push(
      localized(
        "No checks were generated for the selected JSON paths.",
        "По выбранным JSON paths проверки не сгенерированы.",
      ),
    );
  }

  return { cases, notes };
}

/** Backward-compatible helper for the original v0.1 unit-level API. */
export function generateMutations(
  body: JsonObject,
  maxCases: number,
): MutationCase[] {
  return generateChecks(
    { method: "POST", url: "https://breakcurl.invalid", headers: {}, body },
    { profile: "quick", maxCases },
  ).cases;
}

export function requestForCase(
  baseline: ParsedCurl,
  mutation: MutationCase,
): ParsedCurl {
  return {
    ...baseline,
    url: mutation.url ?? baseline.url,
    headers: mutation.headers ?? baseline.headers,
    body: mutation.body,
  };
}

export function parseInlineCustomCase(
  input: string,
  index: number,
  language: Language = "en",
): CustomCaseDefinition {
  const separator = input.indexOf("=");
  if (separator < 2) {
    throw new Error(
      message(
        language,
        `Invalid --set #${index + 1}. Use the format '$.path=<JSON>'.`,
        `Некорректный --set #${index + 1}. Используйте формат '$.path=<JSON>'.`,
      ),
    );
  }
  const path = input.slice(0, separator).trim();
  const rawValue = input.slice(separator + 1).trim();
  let value: JsonValue;
  try {
    value = JSON.parse(rawValue) as JsonValue;
  } catch {
    throw new Error(
      message(
        language,
        `The --set value for ${path} must be valid JSON. Wrap strings in double quotes.`,
        `Значение --set для ${path} должно быть валидным JSON. Строку передавайте в двойных кавычках.`,
      ),
    );
  }
  if (!isJsonValue(value)) {
    throw new Error(
      message(
        language,
        `The --set value for ${path} is not a JSON value.`,
        `Значение --set для ${path} не является JSON.`,
      ),
    );
  }
  return {
    name: localized(
      `Custom value for ${path}`,
      `Пользовательское значение для ${path}`,
    ),
    path,
    operation: "set",
    value,
    expect: "reject",
  };
}

function validateMaxCases(maxCases: number, language: Language): void {
  if (!Number.isInteger(maxCases) || maxCases <= 0 || maxCases > MAX_CASES) {
    throw new Error(
      message(
        language,
        `maxCases must be an integer from 1 to ${MAX_CASES}.`,
        `maxCases должен быть целым числом от 1 до ${MAX_CASES}.`,
      ),
    );
  }
}

function collectFields(
  value: JsonValue,
  segments: PathSegment[] = [],
  path = "$",
): Field[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => {
      const itemPath = `${path}[${index}]`;
      const itemSegments = [...segments, index];
      return [
        { path: itemPath, segments: itemSegments, value: item },
        ...collectFields(item, itemSegments, itemPath),
      ];
    });
  }

  if (!isJsonObject(value)) return [];

  return Object.entries(value).flatMap(([key, item]) => {
    if (SENSITIVE_FIELD_NAME.test(key)) return [];
    const itemPath = appendObjectPath(path, key);
    const itemSegments = [...segments, key];
    return [
      { path: itemPath, segments: itemSegments, value: item },
      ...collectFields(item, itemSegments, itemPath),
    ];
  });
}

function mutationsForField(
  body: JsonObject,
  field: Field,
  profile: CheckProfile,
): MutationCase[] {
  const templates: CaseTemplate[] = [
    {
      kind: "remove",
      value: null,
      category: "structure",
      expectation: "reject",
    },
  ];

  if (field.value !== null) {
    templates.push({
      kind: "null",
      value: null,
      category: "structure",
      expectation: "reject",
    });
  }

  const wrongType = getWrongTypeValue(field.value);
  if (wrongType !== undefined) {
    templates.push({
      kind: "wrong-type",
      value: wrongType,
      category: "structure",
      expectation: "reject",
    });
  }

  const empty = getEmptyValue(field.value);
  if (empty !== undefined) {
    templates.push({
      kind: "empty",
      value: empty,
      category: "boundary",
      expectation: "observe",
    });
  }

  if (typeof field.value === "number") {
    templates.push({
      kind: "numeric-boundary",
      value: field.value === 0 ? -1 : 0,
      category: "boundary",
      expectation: "observe",
    });
  }

  if (profile === "negative" || profile === "full") {
    templates.push(...negativeTemplates(field.value));
  }
  if (profile === "security" || profile === "full") {
    templates.push(...securityTemplates(field.value));
  }

  return templates.map((template) => createCase(body, field, template));
}

function negativeTemplates(value: JsonValue): CaseTemplate[] {
  if (typeof value === "string") {
    return [
      {
        kind: "whitespace",
        value: "   ",
        category: "boundary",
        expectation: "observe",
      },
      {
        kind: "long-string",
        value: "A".repeat(1024),
        category: "boundary",
        expectation: "observe",
      },
      {
        kind: "unicode",
        value: "BREAKCURL_тест_🚀_\u200B",
        category: "boundary",
        expectation: "observe",
      },
    ];
  }
  if (typeof value === "number") {
    return [
      {
        kind: "negative-number",
        value: value === -1 ? -999_999 : -1,
        category: "boundary",
        expectation: "observe",
      },
      {
        kind: "large-number",
        value: Number.MAX_SAFE_INTEGER,
        category: "boundary",
        expectation: "observe",
      },
      {
        kind: "fractional-number",
        value: Number.isInteger(value) ? value + 0.5 : Math.trunc(value),
        category: "boundary",
        expectation: "observe",
      },
    ];
  }
  return [];
}

function securityTemplates(value: JsonValue): CaseTemplate[] {
  if (typeof value !== "string") return [];
  return [
    {
      kind: "sql-probe",
      value: "'BREAKCURL_PROBE",
      category: "injection",
      expectation: "observe",
    },
    {
      kind: "nosql-probe",
      value: { $ne: "BREAKCURL_PROBE" },
      category: "injection",
      expectation: "reject",
    },
    {
      kind: "path-probe",
      value: "../../BREAKCURL_NON_EXISTENT",
      category: "injection",
      expectation: "observe",
    },
    {
      kind: "markup-probe",
      value: "<breakcurl-probe>",
      category: "injection",
      expectation: "observe",
    },
    {
      kind: "template-probe",
      value: "$" + "{BREAKCURL_PROBE}",
      category: "injection",
      expectation: "observe",
    },
    {
      kind: "newline-probe",
      value: "BREAKCURL\r\nPROBE",
      category: "injection",
      expectation: "observe",
    },
  ];
}

function createCase(
  original: JsonObject,
  field: Field,
  template: CaseTemplate,
): MutationCase {
  const body = structuredClone(original);
  if (template.kind === "remove") {
    removeAtPath(body, field.segments);
  } else {
    setAtPath(body, field.segments, template.value);
  }

  return {
    id: `${template.kind}:${field.path}`,
    path: field.path,
    description: describe(field.path, template.kind, template.value),
    kind: template.kind,
    body,
    category: template.category,
    expectation: template.expectation,
    source: "built-in",
  };
}

function createCustomCase(
  request: ParsedCurl,
  definition: CustomCaseDefinition,
  index: number,
  language: Language,
): MutationCase {
  if (!englishText(definition.name).trim()) {
    throw new Error(
      message(
        language,
        `customCases[${index}].name cannot be empty.`,
        `customCases[${index}].name не может быть пустым.`,
      ),
    );
  }
  const segments = parseJsonPath(definition.path, language);
  const body = structuredClone(request.body);
  if (definition.operation === "remove") {
    ensurePathExists(body, segments, definition.path, language);
    removeAtPath(body, segments, language);
  } else {
    if (definition.value === undefined) {
      throw new Error(
        message(
          language,
          `customCases[${index}] with operation=set must contain value.`,
          `customCases[${index}] с operation=set должен содержать value.`,
        ),
      );
    }
    setAtPath(body, segments, definition.value, language);
  }

  return {
    id: `custom-${index + 1}:${slug(englishText(definition.name))}`,
    path: definition.path,
    description: definition.name,
    kind: definition.operation === "remove" ? "custom-remove" : "custom-set",
    body,
    category: "custom",
    expectation: definition.expect ?? "reject",
    source: "custom",
  };
}

function createUnknownFieldCase(request: ParsedCurl): MutationCase {
  const body = structuredClone(request.body);
  let key = "__breakcurl_probe";
  let suffix = 2;
  while (Object.hasOwn(body, key)) {
    key = `__breakcurl_probe_${suffix}`;
    suffix += 1;
  }
  body[key] = "BREAKCURL_PROBE";
  return {
    id: "unknown-field:$",
    path: `$.${key}`,
    description: localized(
      `unknown field $.${key} added`,
      `добавлено неизвестное поле $.${key}`,
    ),
    kind: "unknown-field",
    body,
    category: "structure",
    expectation: "observe",
    source: "built-in",
  };
}

function createContentTypeCase(request: ParsedCurl): MutationCase {
  const headers = Object.fromEntries(
    Object.entries(request.headers).filter(
      ([name]) => name.toLowerCase() !== "content-type",
    ),
  );
  return {
    id: "content-type-missing:headers",
    path: "$headers.content-type",
    description: localized(
      "Content-Type header removed",
      "заголовок Content-Type удалён",
    ),
    kind: "content-type-missing",
    body: structuredClone(request.body),
    headers,
    category: "protocol",
    expectation: "observe",
    source: "built-in",
  };
}

function createAuthCases(
  request: ParsedCurl,
  expectAuth: boolean,
): MutationCase[] {
  const missingHeaders = Object.fromEntries(
    Object.entries(request.headers).filter(
      ([name]) => !AUTH_HEADERS.has(name.toLowerCase()),
    ),
  );
  const missingUrl = mutateSensitiveQuery(request.url, "remove");
  const hasHeaderAuth =
    Object.keys(missingHeaders).length !== Object.keys(request.headers).length;
  const hasQueryAuth = missingUrl !== request.url;
  if (!hasHeaderAuth && !hasQueryAuth) return [];

  const invalidHeaders = Object.fromEntries(
    Object.entries(request.headers).map(([name, value]) => [
      name,
      invalidHeaderValue(name, value),
    ]),
  );
  const expectation: CheckExpectation = expectAuth ? "auth-reject" : "observe";
  return [
    {
      id: "auth-missing:credentials",
      path: "$auth",
      description: localized(
        "all credentials removed",
        "все credentials удалены",
      ),
      kind: "auth-missing",
      body: structuredClone(request.body),
      headers: missingHeaders,
      url: missingUrl,
      category: "authentication",
      expectation,
      source: "built-in",
    },
    {
      id: "auth-invalid:credentials",
      path: "$auth",
      description: localized(
        "credentials replaced with invalid values",
        "credentials заменены на невалидные",
      ),
      kind: "auth-invalid",
      body: structuredClone(request.body),
      headers: invalidHeaders,
      url: mutateSensitiveQuery(request.url, "invalidate"),
      category: "authentication",
      expectation,
      source: "built-in",
    },
  ];
}

function mutateSensitiveQuery(
  url: string,
  operation: "remove" | "invalidate",
): string {
  const parsed = new URL(url);
  for (const name of [...parsed.searchParams.keys()]) {
    if (!SENSITIVE_QUERY_NAME.test(name)) continue;
    if (operation === "remove") parsed.searchParams.delete(name);
    else parsed.searchParams.set(name, INVALID_CREDENTIAL);
  }
  return parsed.toString();
}

function invalidHeaderValue(name: string, value: string): string {
  const normalized = name.toLowerCase();
  if (!AUTH_HEADERS.has(normalized)) return value;
  if (normalized === "cookie") return "breakcurl_invalid=1";
  if (normalized === "authorization" || normalized === "proxy-authorization") {
    const scheme = value.trim().match(/^([^\s]+)\s+/)?.[1];
    return scheme ? `${scheme} ${INVALID_CREDENTIAL}` : INVALID_CREDENTIAL;
  }
  return INVALID_CREDENTIAL;
}

function interleave(groups: MutationCase[][]): MutationCase[] {
  const result: MutationCase[] = [];
  const longest = Math.max(0, ...groups.map((group) => group.length));
  for (let index = 0; index < longest; index += 1) {
    for (const group of groups) {
      const item = group[index];
      if (item) result.push(item);
    }
  }
  return result;
}

function pathIsSelected(
  path: string,
  onlyPaths: string[],
  excludePaths: string[],
): boolean {
  const matches = (filter: string) =>
    path === filter ||
    path.startsWith(`${filter}.`) ||
    path.startsWith(`${filter}[`);
  if (excludePaths.some(matches)) return false;
  return onlyPaths.length === 0 || onlyPaths.some(matches);
}

function parseJsonPath(path: string, language: Language): PathSegment[] {
  if (!path.startsWith("$")) {
    throw new Error(
      message(
        language,
        `JSON path must start with $: ${path}`,
        `JSON path должен начинаться с $: ${path}`,
      ),
    );
  }
  const segments: PathSegment[] = [];
  let index = 1;
  while (index < path.length) {
    if (path[index] === ".") {
      const match = path.slice(index + 1).match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
      if (!match) throw invalidJsonPath(path, language);
      assertSafeSegment(match[0], language);
      segments.push(match[0]);
      index += match[0].length + 1;
      continue;
    }
    if (path[index] === "[") {
      const rest = path.slice(index);
      const numeric = rest.match(/^\[(\d+)\]/);
      if (numeric?.[1] !== undefined) {
        segments.push(Number(numeric[1]));
        index += numeric[0].length;
        continue;
      }
      const quoted = rest.match(
        /^\[((?:"(?:\\.|[^"\\])*")|(?:'(?:\\.|[^'\\])*'))\]/,
      );
      if (!quoted?.[1]) throw invalidJsonPath(path, language);
      const raw = quoted[1];
      const key = raw.startsWith("'")
        ? raw.slice(1, -1).replaceAll("\\'", "'")
        : (JSON.parse(raw) as string);
      assertSafeSegment(key, language);
      segments.push(key);
      index += quoted[0].length;
      continue;
    }
    throw invalidJsonPath(path, language);
  }
  if (segments.length === 0) {
    throw new Error(
      message(
        language,
        "The root JSON object cannot be replaced as a whole.",
        "Корневой JSON-объект нельзя заменить целиком.",
      ),
    );
  }
  return segments;
}

function assertSafeSegment(segment: string, language: Language): void {
  if (["__proto__", "prototype", "constructor"].includes(segment)) {
    throw new Error(
      message(
        language,
        `Unsafe JSON path segment: ${segment}`,
        `Небезопасный сегмент JSON path: ${segment}`,
      ),
    );
  }
}

function ensurePathExists(
  body: JsonObject,
  segments: PathSegment[],
  path: string,
  language: Language,
): void {
  const parent = getParent(body, segments, language);
  const key = segments.at(-1);
  const exists = Array.isArray(parent)
    ? typeof key === "number" && key >= 0 && key < parent.length
    : typeof key === "string" && Object.hasOwn(parent, key);
  if (!exists) {
    throw new Error(
      message(
        language,
        `JSON path not found: ${path}`,
        `JSON path не найден: ${path}`,
      ),
    );
  }
}

function removeAtPath(
  body: JsonObject,
  segments: PathSegment[],
  language: Language = "en",
): void {
  const parent = getParent(body, segments, language);
  const key = segments.at(-1);
  if (key === undefined)
    throw new Error(
      message(
        language,
        "The root JSON object cannot be removed.",
        "Нельзя удалить корневой JSON-объект.",
      ),
    );

  if (Array.isArray(parent)) {
    if (typeof key !== "number" || key < 0 || key >= parent.length) {
      throw arrayIndexError(language);
    }
    parent.splice(key, 1);
  } else {
    if (typeof key !== "string") throw invalidJsonPath("", language);
    delete parent[key];
  }
}

function setAtPath(
  body: JsonObject,
  segments: PathSegment[],
  value: JsonValue,
  language: Language = "en",
): void {
  const parent = getParent(body, segments, language);
  const key = segments.at(-1);
  if (key === undefined)
    throw new Error(
      message(
        language,
        "The root JSON object cannot be replaced.",
        "Нельзя заменить корневой JSON-объект.",
      ),
    );
  if (Array.isArray(parent)) {
    if (typeof key !== "number" || key < 0 || key >= parent.length) {
      throw arrayIndexError(language);
    }
    parent[key] = value;
  } else {
    if (typeof key !== "string") throw invalidJsonPath("", language);
    parent[key] = value;
  }
}

function getParent(
  body: JsonObject,
  segments: PathSegment[],
  language: Language,
): JsonObject | JsonValue[] {
  if (segments.length === 0)
    throw new Error(
      message(
        language,
        "The root JSON object cannot be modified.",
        "Нельзя изменить корневой JSON-объект.",
      ),
    );
  let current: JsonObject | JsonValue[] = body;
  for (const segment of segments.slice(0, -1)) {
    const next: JsonValue | undefined = Array.isArray(current)
      ? current[segment as number]
      : current[segment as string];
    if (next === undefined || (!isJsonObject(next) && !Array.isArray(next))) {
      throw new Error(
        message(
          language,
          "JSON path no longer points to a container.",
          "JSON path больше не указывает на контейнер.",
        ),
      );
    }
    current = next;
  }
  return current;
}

function getWrongTypeValue(value: JsonValue): JsonValue | undefined {
  if (typeof value === "string") return 123;
  if (typeof value === "number") return "not-a-number";
  if (typeof value === "boolean") return "true";
  if (Array.isArray(value)) return {};
  if (isJsonObject(value)) return [];
  return undefined;
}

function getEmptyValue(value: JsonValue): JsonValue | undefined {
  if (typeof value === "string") return "";
  if (Array.isArray(value)) return [];
  if (isJsonObject(value)) return {};
  return undefined;
}

function describe(
  path: string,
  kind: MutationKind,
  value: JsonValue,
): TranslatableText {
  const labels: Partial<Record<MutationKind, TranslatableText>> = {
    remove: localized(`field ${path} removed`, `поле ${path} удалено`),
    whitespace: localized(
      `${path} = whitespace-only string`,
      `${path} = строка из пробелов`,
    ),
    "long-string": localized(
      `${path} = 1024-character string`,
      `${path} = строка длиной 1024 символа`,
    ),
    unicode: localized(
      `${path} = Unicode and invisible character`,
      `${path} = Unicode и невидимый символ`,
    ),
    "negative-number": localized(
      `${path} = negative number`,
      `${path} = отрицательное число`,
    ),
    "large-number": localized(
      `${path} = Number.MAX_SAFE_INTEGER`,
      `${path} = Number.MAX_SAFE_INTEGER`,
    ),
    "fractional-number": localized(
      `${path} = fractional number`,
      `${path} = дробное число`,
    ),
    "sql-probe": localized(
      `${path} = safe SQL syntax probe`,
      `${path} = безопасный SQL syntax probe`,
    ),
    "nosql-probe": localized(
      `${path} = object with $ne operator`,
      `${path} = объект с оператором $ne`,
    ),
    "path-probe": localized(
      `${path} = safe path traversal probe`,
      `${path} = безопасный path traversal probe`,
    ),
    "markup-probe": localized(
      `${path} = non-executable markup probe`,
      `${path} = неисполняемый markup probe`,
    ),
    "template-probe": localized(
      `${path} = template expression probe`,
      `${path} = template expression probe`,
    ),
    "newline-probe": localized(
      `${path} = CRLF/newline probe`,
      `${path} = CRLF/newline probe`,
    ),
  };
  return (
    labels[kind] ??
    localized(
      `${path} = ${compactValue(value)}`,
      `${path} = ${compactValue(value)}`,
    )
  );
}

function invalidJsonPath(path: string, language: Language): Error {
  const suffix = path ? `: ${path}` : ".";
  return new Error(
    message(
      language,
      `Invalid JSON path${suffix}`,
      `Некорректный JSON path${suffix}`,
    ),
  );
}

function arrayIndexError(language: Language): Error {
  return new Error(
    message(
      language,
      "Array index in JSON path is out of bounds.",
      "Индекс массива в JSON path находится вне границ.",
    ),
  );
}

function compactValue(value: JsonValue): string {
  const rendered = JSON.stringify(value);
  return rendered.length > 80 ? `${rendered.slice(0, 77)}...` : rendered;
}

function appendObjectPath(parentPath: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)
    ? `${parentPath}.${key}`
    : `${parentPath}[${JSON.stringify(key)}]`;
}

function slug(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9а-яё]+/gi, "-")
      .replace(/^-+|-+$/g, "") || "case"
  );
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null) return true;
  if (["string", "number", "boolean"].includes(typeof value)) return true;
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (!isUnknownObject(value)) return false;
  return Object.values(value).every(isJsonValue);
}

function isUnknownObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJsonObject(value: JsonValue): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
