import { message } from "./i18n.js";
import { collectSensitiveValues } from "./redact.js";
import { isUnsafeTransportHeader } from "./runner.js";
import type { JsonObject, JsonValue, Language, ParsedCurl } from "./types.js";

export type AuthSource =
  | { in: "header"; name: string }
  | { in: "query"; name: string }
  | { in: "json"; pointer: string };

export interface AuthContract {
  complete: true;
  sources: AuthSource[];
}

export interface DeclaredAuthProbes {
  missing: ParsedCurl;
  invalid: ParsedCurl;
  knownSecrets: string[];
  sources: string[];
}

export const INVALID_AUTH_CREDENTIAL = "BREAKCURL_INVALID_CREDENTIAL";
const SENSITIVE_NAME =
  /password|passphrase|token|secret|authorization|auth|credential|cookie|session|jwt|api[_-]?key/i;
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** Parses locations only. Credential values belong in the input request. */
export function parseAuthContract(
  value: unknown,
  language: Language = "en",
): AuthContract {
  if (
    !isObject(value) ||
    value.complete !== true ||
    !Array.isArray(value.sources) ||
    value.sources.length === 0 ||
    Object.keys(value).some((key) => !["complete", "sources"].includes(key))
  ) {
    throw contractError(
      language,
      "Auth contract must contain only complete: true and a non-empty sources array.",
      "Auth-контракт должен содержать только complete: true и непустой массив sources.",
    );
  }
  const sources: AuthSource[] = value.sources.map(
    (source: unknown, index: number) => {
      if (!isObject(source)) throw invalidSource(index, language);
      if (source.in === "json") {
        if (
          typeof source.pointer !== "string" ||
          Object.keys(source).some((key) => !["in", "pointer"].includes(key))
        )
          throw invalidSource(index, language);
        pointerSegments(source.pointer, language);
        return { in: "json", pointer: source.pointer };
      }
      if (source.in !== "header" && source.in !== "query")
        throw invalidSource(index, language);
      if (
        typeof source.name !== "string" ||
        source.name.length === 0 ||
        [...source.name].some(
          (character) =>
            character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
        ) ||
        Object.keys(source).some((key) => !["in", "name"].includes(key))
      )
        throw invalidSource(index, language);
      if (
        source.in === "header" &&
        (!HEADER_NAME.test(source.name) || isUnsafeTransportHeader(source.name))
      )
        throw invalidSource(index, language);
      return { in: source.in, name: source.name };
    },
  );
  const identities = new Set<string>();
  const pointers: string[][] = [];
  for (const source of sources) {
    const identity =
      source.in === "json"
        ? `json:${source.pointer}`
        : `${source.in}:${source.in === "header" ? source.name.toLowerCase() : source.name}`;
    if (identities.has(identity))
      throw contractError(
        language,
        "Duplicate auth source.",
        "Источник auth указан повторно.",
      );
    identities.add(identity);
    if (source.in === "json") {
      const segments = pointerSegments(source.pointer, language);
      if (
        pointers.some(
          (other) => isPrefix(segments, other) || isPrefix(other, segments),
        )
      )
        throw contractError(
          language,
          "Overlapping JSON auth pointers are not supported.",
          "Пересекающиеся JSON auth pointers не поддерживаются.",
        );
      pointers.push(segments);
    }
  }
  return { complete: true, sources };
}

/** Validates the entire declaration before changing cloned request data. */
export function buildDeclaredAuthProbes(
  request: ParsedCurl,
  value: AuthContract,
  language: Language = "en",
): DeclaredAuthProbes {
  const contract = parseAuthContract(value, language);
  const url = new URL(request.url);
  if (url.username || url.password || url.hash)
    throw contractError(
      language,
      "Auth contracts do not support URL userinfo or fragments.",
      "Auth-контракты не поддерживают userinfo или fragment в URL.",
    );
  const knownSecrets = new Set<string>();
  const resolved = contract.sources.map((source) => {
    if (source.in === "header") {
      const names = Object.keys(request.headers).filter(
        (name) => name.toLowerCase() === source.name.toLowerCase(),
      );
      const name = names[0];
      if (names.length !== 1 || name === undefined)
        throw absentSource(language);
      const credential = requireCredential(request.headers[name], language);
      knownSecrets.add(credential);
      if (
        ["authorization", "proxy-authorization"].includes(name.toLowerCase())
      ) {
        const inner = credential.match(/^\s*\S+\s+(.+)$/)?.[1];
        if (inner) knownSecrets.add(inner);
      }
      if (name.toLowerCase() === "cookie") {
        for (const part of credential.split(";")) {
          const equals = part.indexOf("=");
          if (equals >= 0 && part.slice(equals + 1).trim())
            knownSecrets.add(part.slice(equals + 1).trim());
        }
      }
      return { source, key: name, credential };
    }
    if (source.in === "query") {
      const matches = url.searchParams.getAll(source.name);
      if (matches.length !== 1) throw absentSource(language);
      const credential = requireCredential(matches[0], language);
      knownSecrets.add(credential);
      return { source, key: source.name, credential };
    }
    if (request.method === "GET")
      throw contractError(
        language,
        "JSON auth sources are not supported for GET requests.",
        "JSON auth sources не поддерживаются для GET-запросов.",
      );
    const segments = pointerSegments(source.pointer, language);
    const { parent, key } = pointerParent(request.body, segments, language);
    const credential = requireCredential(parent[key], language);
    knownSecrets.add(credential);
    return { source, key, segments, credential };
  });

  const missing = structuredClone(request);
  const invalid = structuredClone(request);
  const missingUrl = new URL(request.url);
  const invalidUrl = new URL(request.url);
  for (const entry of resolved) {
    if (entry.source.in === "header") {
      delete missing.headers[entry.key];
      invalid.headers[entry.key] = invalidAuthHeader(
        entry.key,
        entry.credential,
      );
    } else if (entry.source.in === "query") {
      missingUrl.searchParams.delete(entry.key);
      invalidUrl.searchParams.set(
        entry.key,
        invalidAuthValue(entry.credential),
      );
    } else {
      const missingParent = pointerParent(
        missing.body,
        pointerSegments(entry.source.pointer, language),
        language,
      );
      const invalidParent = pointerParent(
        invalid.body,
        pointerSegments(entry.source.pointer, language),
        language,
      );
      delete missingParent.parent[missingParent.key];
      invalidParent.parent[invalidParent.key] = invalidAuthValue(
        entry.credential,
      );
    }
  }
  missing.url = missingUrl.toString();
  invalid.url = invalidUrl.toString();
  const possibleSecrets = [...knownSecrets, ...collectSensitiveValues(request)];
  if (
    Object.entries(missing.headers).some(
      ([name, value]) =>
        SENSITIVE_NAME.test(name) ||
        containsKnownCredential(value, possibleSecrets),
    ) ||
    [...missingUrl.searchParams].some(
      ([name, value]) =>
        SENSITIVE_NAME.test(name) ||
        containsKnownCredential(value, possibleSecrets),
    ) ||
    hasPossibleBodyCredentials(missing.body, possibleSecrets)
  ) {
    throw contractError(
      language,
      "The complete auth contract leaves possible credentials undeclared. Include their sources before running auth probes.",
      "Полный auth-контракт оставляет возможные credentials незаявленными. Укажите их источники перед auth-проверками.",
    );
  }
  return {
    missing,
    invalid,
    knownSecrets: [...knownSecrets].sort(
      (left, right) => right.length - left.length,
    ),
    sources: contract.sources.map((source) =>
      source.in === "json"
        ? `json:${source.pointer}`
        : `${source.in}:${source.name}`,
    ),
  };
}

export function collectAuthContractSecrets(
  request: ParsedCurl,
  contract: AuthContract,
  language: Language = "en",
): string[] {
  return buildDeclaredAuthProbes(request, contract, language).knownSecrets;
}

export function invalidAuthHeader(name: string, value: string): string {
  const normalized = name.toLowerCase();
  if (normalized === "cookie")
    return value === "breakcurl_invalid=1"
      ? "breakcurl_invalid=2"
      : "breakcurl_invalid=1";
  if (normalized === "authorization" || normalized === "proxy-authorization") {
    const scheme = value.trim().match(/^([^\s]+)\s+/)?.[1];
    const replacement = scheme
      ? `${scheme} ${INVALID_AUTH_CREDENTIAL}`
      : INVALID_AUTH_CREDENTIAL;
    return value === replacement ? `${replacement}_2` : replacement;
  }
  return invalidAuthValue(value);
}

export function invalidAuthValue(value: string): string {
  return value === INVALID_AUTH_CREDENTIAL
    ? `${INVALID_AUTH_CREDENTIAL}_2`
    : INVALID_AUTH_CREDENTIAL;
}

export function hasPossibleBodyCredentials(
  value: JsonValue,
  knownSecrets: string[],
): boolean {
  if (typeof value === "string")
    return containsKnownCredential(value, knownSecrets);
  if (Array.isArray(value))
    return value.some((child) =>
      hasPossibleBodyCredentials(child, knownSecrets),
    );
  if (value === null || typeof value !== "object") return false;
  return Object.entries(value).some(
    ([key, child]) =>
      (SENSITIVE_NAME.test(key) && hasNonemptyValue(child)) ||
      hasPossibleBodyCredentials(child, knownSecrets),
  );
}

/** Bounded supported representations; unknown encodings remain operator scope. */
function containsKnownCredential(
  value: string,
  knownSecrets: string[],
): boolean {
  const candidates = [value];
  try {
    candidates.push(decodeURIComponent(value));
  } catch {
    // Malformed percent encoding must not suppress the raw-value comparison.
  }
  return knownSecrets.some((secret) => {
    if (secret === "") return false;
    const variants = [
      secret,
      JSON.stringify(secret).slice(1, -1),
      Buffer.from(secret).toString("base64"),
      Buffer.from(secret).toString("base64url"),
    ];
    return candidates.some((candidate) =>
      variants.some((variant) => candidate.includes(variant)),
    );
  });
}

function hasNonemptyValue(value: JsonValue): boolean {
  if (value === null || value === "") return false;
  if (Array.isArray(value)) return value.some(hasNonemptyValue);
  if (typeof value === "object")
    return Object.values(value).some(hasNonemptyValue);
  return true;
}

function pointerSegments(pointer: string, language: Language): string[] {
  if (!pointer.startsWith("/") || /~(?![01])/.test(pointer))
    throw contractError(
      language,
      "JSON auth pointers must be non-root RFC 6901 pointers.",
      "JSON auth pointers должны быть некорневыми указателями RFC 6901.",
    );
  const segments = pointer
    .slice(1)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  if (segments.some((segment) => FORBIDDEN_SEGMENTS.has(segment)))
    throw contractError(
      language,
      "Prototype traversal is not supported in auth pointers.",
      "Обход prototype в auth pointers не поддерживается.",
    );
  return segments;
}

function pointerParent(
  body: JsonObject,
  segments: string[],
  language: Language,
): { parent: JsonObject; key: string } {
  let current: JsonValue = body;
  for (const key of segments.slice(0, -1)) {
    if (!isObject(current) || !Object.hasOwn(current, key))
      throw absentSource(language);
    current = current[key] as JsonValue;
  }
  const key = segments.at(-1);
  if (key === undefined || !isObject(current) || !Object.hasOwn(current, key))
    throw absentSource(language);
  return { parent: current as JsonObject, key };
}

function requireCredential(value: unknown, language: Language): string {
  if (typeof value !== "string" || value.trim() === "")
    throw contractError(
      language,
      "Declared auth sources must resolve to non-empty strings; arrays, objects, numbers and null are unsupported.",
      "Заявленные auth sources должны указывать на непустые строки; массивы, объекты, числа и null не поддерживаются.",
    );
  return value;
}

function isPrefix(left: string[], right: string[]): boolean {
  return (
    left.length <= right.length &&
    left.every((part, index) => part === right[index])
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidSource(index: number, language: Language): Error {
  return contractError(
    language,
    `Unsupported auth source at index ${index}; use header/query name or json pointer, without credential values.`,
    `Неподдерживаемый auth source с индексом ${index}; используйте header/query name или json pointer, без значений credentials.`,
  );
}

function absentSource(language: Language): Error {
  return contractError(
    language,
    "Declared auth source is missing, duplicated in the request, or traverses a non-object value.",
    "Заявленный auth source отсутствует, повторяется в запросе или проходит через значение, не являющееся объектом.",
  );
}

function contractError(language: Language, en: string, ru: string): Error {
  return new Error(message(language, en, ru));
}
