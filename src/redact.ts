import type { JsonObject, JsonValue, ParsedCurl } from "./types.js";

export const REDACTED = "<REDACTED>";

const SENSITIVE_NAME =
  /token|secret|key|password|passphrase|session|cookie|authorization|auth|credential|jwt|refresh/i;
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "api-key",
  "x-auth-token",
]);
const SECRET_PATTERNS = [
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
];

export function collectSensitiveValues(request: ParsedCurl): string[] {
  const values = new Set<string>();
  try {
    const url = new URL(request.url);
    addSecret(values, url.username);
    addSecret(values, url.password);
    for (const [name, value] of url.searchParams) {
      if (isSensitiveName(name)) addSecret(values, value);
      collectPatternSecrets(value, values);
    }
  } catch {
    collectPatternSecrets(request.url, values);
  }

  for (const [name, value] of Object.entries(request.headers)) {
    if (isSensitiveHeader(name)) {
      addSecret(values, value);
      const credential = value.match(/^\s*[^\s]+\s+(.+)$/)?.[1];
      addSecret(values, credential);
      if (name.toLowerCase() === "cookie") {
        for (const part of value.split(";")) {
          addSecret(values, part.slice(part.indexOf("=") + 1).trim());
        }
      }
    }
    collectPatternSecrets(value, values);
  }
  collectJsonSecrets(request.body, values);
  return [...values].sort((left, right) => right.length - left.length);
}

export function redactUrl(url: string, knownSecrets: string[] = []): string {
  try {
    const parsed = new URL(url);
    if (parsed.username) parsed.username = REDACTED;
    if (parsed.password) parsed.password = REDACTED;
    for (const name of [...parsed.searchParams.keys()]) {
      const value = parsed.searchParams.get(name) ?? "";
      if (isSensitiveName(name) || containsSecretPattern(value)) {
        parsed.searchParams.set(name, REDACTED);
      } else {
        parsed.searchParams.set(name, redactText(value, knownSecrets));
      }
    }
    return redactText(parsed.toString(), knownSecrets);
  } catch {
    return redactText(redactQueryWithoutParsing(url), knownSecrets);
  }
}

export function redactHeaders(
  headers: Record<string, string>,
  knownSecrets: string[] = [],
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name,
      redactHeaderValue(name, value, knownSecrets),
    ]),
  );
}

export function redactJson(
  value: JsonValue,
  knownSecrets: string[] = [],
): JsonValue {
  if (Array.isArray(value))
    return value.map((item) => redactJson(item, knownSecrets));
  if (!isJsonObject(value)) {
    return typeof value === "string" ? redactText(value, knownSecrets) : value;
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [
      key,
      isSensitiveName(key) ? REDACTED : redactJson(child, knownSecrets),
    ]),
  ) as JsonObject;
}

export function sanitizeRequest(
  request: ParsedCurl,
  inheritedSecrets: string[] = [],
): ParsedCurl {
  const knownSecrets = uniqueSecrets([
    ...inheritedSecrets,
    ...collectSensitiveValues(request),
  ]);
  return {
    ...request,
    url: redactUrl(request.url, knownSecrets),
    headers: redactHeaders(request.headers, knownSecrets),
    body: redactJson(request.body, knownSecrets) as JsonObject,
  };
}

export function redactText(value: string, knownSecrets: string[] = []): string {
  let redacted = value;
  for (const secret of uniqueSecrets(knownSecrets)) {
    redacted = redacted.replaceAll(secret, REDACTED);
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret)
      redacted = redacted.replaceAll(encoded, encodeURIComponent(REDACTED));
  }
  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, REDACTED);
  }
  return redacted;
}

function collectJsonSecrets(value: JsonValue, values: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) collectJsonSecrets(item, values);
    return;
  }
  if (!isJsonObject(value)) {
    if (typeof value === "string") collectPatternSecrets(value, values);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (isSensitiveName(key)) collectAllStringValues(child, values);
    collectJsonSecrets(child, values);
  }
}

function collectAllStringValues(value: JsonValue, values: Set<string>): void {
  if (typeof value === "string") {
    addSecret(values, value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectAllStringValues(item, values);
    return;
  }
  if (isJsonObject(value)) {
    for (const child of Object.values(value)) {
      collectAllStringValues(child, values);
    }
  }
}

function collectPatternSecrets(value: string, values: Set<string>): void {
  for (const pattern of SECRET_PATTERNS) {
    for (const match of value.matchAll(pattern)) addSecret(values, match[0]);
  }
}

function containsSecretPattern(value: string): boolean {
  return SECRET_PATTERNS.some((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(value);
  });
}

function addSecret(values: Set<string>, value: string | undefined): void {
  const normalized = value?.trim();
  if (normalized && normalized.length >= 4 && normalized !== REDACTED) {
    values.add(normalized);
  }
}

function uniqueSecrets(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.length >= 4))].sort(
    (left, right) => right.length - left.length,
  );
}

function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADERS.has(name.toLowerCase()) || isSensitiveName(name);
}

function redactHeaderValue(
  name: string,
  value: string,
  knownSecrets: string[],
): string {
  if (!isSensitiveHeader(name)) return redactText(value, knownSecrets);
  if (["authorization", "proxy-authorization"].includes(name.toLowerCase())) {
    const scheme = value.match(/^\s*([^\s]+)\s+/)?.[1];
    if (scheme) return `${scheme} ${REDACTED}`;
  }
  return REDACTED;
}

function isSensitiveName(name: string): boolean {
  return SENSITIVE_NAME.test(name);
}

function redactQueryWithoutParsing(url: string): string {
  const separator = url.indexOf("?");
  if (separator === -1) return url;

  const prefix = url.slice(0, separator + 1);
  const queryAndFragment = url.slice(separator + 1);
  const hashIndex = queryAndFragment.indexOf("#");
  const query =
    hashIndex === -1 ? queryAndFragment : queryAndFragment.slice(0, hashIndex);
  const fragment = hashIndex === -1 ? "" : queryAndFragment.slice(hashIndex);

  const redactedQuery = query
    .split("&")
    .map((part) => {
      const equals = part.indexOf("=");
      const rawName = equals === -1 ? part : part.slice(0, equals);
      let name = rawName;
      try {
        name = decodeURIComponent(rawName.replace(/\+/g, " "));
      } catch {
        // A malformed query must not prevent best-effort redaction.
      }
      return isSensitiveName(name)
        ? `${rawName}=${encodeURIComponent(REDACTED)}`
        : part;
    })
    .join("&");

  return `${prefix}${redactedQuery}${fragment}`;
}

function isJsonObject(value: JsonValue): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
