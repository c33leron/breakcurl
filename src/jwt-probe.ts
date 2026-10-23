import { isDeepStrictEqual } from "node:util";
import { localized } from "./i18n.js";
import type {
  JsonObject,
  JsonValue,
  MutationCase,
  ParsedCurl,
} from "./types.js";

/**
 * JWT attack probes (OWASP API2:2023 Broken Authentication).
 *
 * When the source cURL carries a Bearer JWT, BreakCurl replays the request
 * with cryptographically broken tokens. A strict HTTP rejection expectation
 * requires a complete contract declaring Authorization as the sole auth source.
 * Other credentials are preserved, so status alone does not establish how the
 * server authenticated the request. Tokens are only reassembled from parsed
 * segments — no cryptographic operations, no guessing of secrets.
 */

interface JwtParts {
  header: JsonObject;
  payload: JsonObject;
  signature: string;
  encodedHeader: string;
  encodedPayload: string;
}

interface ExtractedBearer {
  headerName: string;
  token: string;
}

/** Finds an Authorization header holding a three-segment Bearer JWT. */
export function extractBearerJwt(
  request: ParsedCurl,
): ExtractedBearer | undefined {
  const entry = Object.entries(request.headers).find(
    ([name]) => name.toLowerCase() === "authorization",
  );
  if (!entry) return undefined;
  const match = entry[1].match(
    /^\s*Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)\s*$/,
  );
  if (!match?.[1]) return undefined;
  return { headerName: entry[0], token: match[1] };
}

function parseJwt(token: string): JwtParts | undefined {
  const segments = token.split(".");
  if (segments.length !== 3) return undefined;
  const [encodedHeader, encodedPayload, signature] = segments as [
    string,
    string,
    string,
  ];
  try {
    const header = JSON.parse(
      Buffer.from(encodedHeader, "base64url").toString("utf8"),
    ) as JsonValue;
    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8"),
    ) as JsonValue;
    if (
      typeof header !== "object" ||
      header === null ||
      Array.isArray(header) ||
      typeof payload !== "object" ||
      payload === null ||
      Array.isArray(payload)
    ) {
      return undefined;
    }
    return { header, payload, signature, encodedHeader, encodedPayload };
  } catch {
    return undefined;
  }
}

function encodeSegment(value: JsonObject): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

const CLAIM_KEYS = ["sub", "role", "roles", "user_id", "userId"] as const;

/** Builds up to four tampered-token replay cases; empty when no Bearer JWT is present. */
export function createJwtCases(
  request: ParsedCurl,
  strictAuth = false,
): MutationCase[] {
  const bearer = extractBearerJwt(request);
  if (!bearer) return [];
  const jwt = parseJwt(bearer.token);
  if (!jwt) return [];

  const algorithm = typeof jwt.header.alg === "string" ? jwt.header.alg : "";
  const unsigned = algorithm.toLowerCase() === "none";
  // Changing an unsigned payload does not manufacture an invalid signature.
  if (unsigned) return [];
  const baseHeaders = { ...request.headers };
  const body = structuredClone(request.body);
  const base = {
    path: "$auth.token",
    body,
    category: "authorization" as const,
    expectation: strictAuth ? ("auth-reject" as const) : ("observe" as const),
    source: "built-in" as const,
  };
  const withToken = (token: string): Record<string, string> => ({
    ...baseHeaders,
    [bearer.headerName]: `Bearer ${token}`,
  });

  const cases: MutationCase[] = [];

  // alg=none: the classic unsigned-token bypass; some verifiers trust the header.
  const noneHeader: JsonObject = { ...jwt.header, alg: "none" };
  cases.push({
    ...base,
    id: "jwt-alg-none:credentials",
    description: localized(
      "JWT replayed with alg=none and an empty signature",
      "JWT отправлен с alg=none и пустой подписью",
    ),
    kind: "jwt-alg-none",
    headers: withToken(`${encodeSegment(noneHeader)}.${jwt.encodedPayload}.`),
  });

  // An empty signature would replay an unchanged baseline token.
  if (jwt.signature) {
    cases.push({
      ...base,
      id: "jwt-signature-strip:credentials",
      description: localized(
        "JWT replayed with the signature segment removed",
        "JWT отправлен без сегмента подписи",
      ),
      kind: "jwt-signature-strip",
      headers: withToken(`${jwt.encodedHeader}.${jwt.encodedPayload}.`),
    });
  }

  // Claim tampering invalidates the original signature. Only change values
  // that differ, so an already privileged payload is not replayed unchanged.
  const tampered = structuredClone(jwt.payload);
  const tamperedClaims: string[] = [];
  for (const key of CLAIM_KEYS) {
    if (!Object.hasOwn(tampered, key)) continue;
    const value = key === "roles" ? ["admin"] : "admin";
    if (isDeepStrictEqual(tampered[key], value)) continue;
    tampered[key] = value;
    tamperedClaims.push(key);
  }
  if (tamperedClaims.length > 0) {
    cases.push({
      ...base,
      id: "jwt-claim-tamper:credentials",
      description: localized(
        `JWT replayed with privileged claims tampered (${tamperedClaims.join(", ")}) and the original signature kept`,
        `JWT отправлен с подменёнными привилегированными claims (${tamperedClaims.join(", ")}) и оригинальной подписью`,
      ),
      kind: "jwt-claim-tamper",
      headers: withToken(
        `${jwt.encodedHeader}.${encodeSegment(tampered)}.${jwt.signature}`,
      ),
    });
  }

  // Keep the kind for report compatibility. Changing exp invalidates the
  // original signature, so this cannot test expiry enforcement independently.
  if (typeof jwt.payload.exp === "number" && jwt.payload.exp !== 1) {
    const expired = structuredClone(jwt.payload);
    expired.exp = 1;
    cases.push({
      ...base,
      id: "jwt-expired:credentials",
      description: localized(
        "JWT replayed with exp tampered to the past and the original signature kept; this is an invalid-signature probe, not an expiry-enforcement test",
        "JWT отправлен с exp в прошлом и оригинальной подписью; это проба невалидной подписи, а не проверка срока действия",
      ),
      kind: "jwt-expired",
      headers: withToken(
        `${jwt.encodedHeader}.${encodeSegment(expired)}.${jwt.signature}`,
      ),
    });
  }

  return cases;
}
