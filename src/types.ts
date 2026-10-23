import type { AuthContract } from "./auth-contract.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export type Language = "en" | "ru";
export interface LocalizedText {
  en: string;
  ru: string;
}
export type TranslatableText = string | LocalizedText;

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface ParsedCurl {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  body: JsonObject;
}

export type CheckProfile = "quick" | "negative" | "security" | "full";

export type CheckCategory =
  | "structure"
  | "boundary"
  | "protocol"
  | "injection"
  | "authentication"
  | "authorization"
  | "recon"
  | "custom";

export type CheckExpectation = "reject" | "accept" | "auth-reject" | "observe";

export type MutationKind =
  | "remove"
  | "null"
  | "wrong-type"
  | "empty"
  | "numeric-boundary"
  | "whitespace"
  | "long-string"
  | "unicode"
  | "negative-number"
  | "large-number"
  | "fractional-number"
  | "unknown-field"
  | "sql-probe"
  | "nosql-probe"
  | "path-probe"
  | "markup-probe"
  | "template-probe"
  | "newline-probe"
  | "content-type-missing"
  | "auth-missing"
  | "auth-invalid"
  | "jwt-alg-none"
  | "jwt-signature-strip"
  | "jwt-claim-tamper"
  | "jwt-expired"
  | "privilege-field"
  | "method-tamper"
  | "spec-probe"
  | "custom-set"
  | "custom-remove";

export interface MutationCase {
  id: string;
  path: string;
  description: TranslatableText;
  kind: MutationKind;
  body: JsonObject;
  category?: CheckCategory;
  expectation?: CheckExpectation;
  source?: "built-in" | "custom";
  headers?: Record<string, string>;
  url?: string;
  /** Overrides the baseline HTTP method for this case (method tampering, recon GETs). */
  method?: HttpMethod;
}

export interface HttpResult {
  status: number;
  latencyMs: number;
  headers: Record<string, string>;
  body: string;
  /** Intentionally discarded after an in-memory oracle, not transport truncation. */
  bodyOmitted?: boolean;
  /**
   * Runner: true when bytes beyond its cap were observed; false after EOF
   * within the cap. Omitted on read failures (see transport flags), and
   * optional for compatibility with callers supplying complete bodies.
   */
  bodyTruncated?: boolean;
  timedOut: boolean;
  connectionError?: string;
}

export type Classification = "PASS" | "INFO" | "WARN" | "FAIL" | "ERROR";

export type FindingSeverity = "LOW" | "MEDIUM" | "HIGH";
export type FindingConfidence = "LOW" | "MEDIUM" | "HIGH";

export interface SecuritySignal {
  id: string;
  title: TranslatableText;
  severity: FindingSeverity;
  cwe?: string;
  /** OWASP API Security Top 10 (2023) category, e.g. "API2:2023". */
  owasp?: string;
}

/** OWASP API Security Top 10 (2023) item ids used in coverage reporting. */
export type OwaspApiItem =
  | "API1:2023"
  | "API2:2023"
  | "API3:2023"
  | "API4:2023"
  | "API5:2023"
  | "API6:2023"
  | "API7:2023"
  | "API8:2023"
  | "API9:2023"
  | "API10:2023";

export interface OwaspCoverageEntry {
  item: OwaspApiItem;
  title: string;
  status: "tested" | "partial" | "not-tested" | "out-of-scope";
  detail: TranslatableText;
}

export interface CaseResult {
  mutation: MutationCase;
  response: HttpResult;
  classification: Classification;
  reason: TranslatableText;
  replayFile?: string;
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
  securitySignals?: SecuritySignal[];
}

export interface BaselineResult {
  request: ParsedCurl;
  response: HttpResult;
  assessment?: Pick<
    CaseResult,
    "classification" | "reason" | "severity" | "confidence" | "securitySignals"
  >;
}

export interface RunResult {
  baseline: BaselineResult;
  cases: CaseResult[];
  profile?: CheckProfile;
  notes?: TranslatableText[];
  language?: Language;
  mode?: "checks" | "idor";
  plannedRequests?: number;
  completedRequests?: number;
}

export interface RunOptions {
  maxCases: number;
  timeoutMs: number;
}

export interface CustomCaseDefinition {
  name: TranslatableText;
  path: string;
  operation: "set" | "remove";
  value?: JsonValue;
  expect?: CheckExpectation;
}

export interface CheckGenerationOptions {
  profile: CheckProfile;
  maxCases: number;
  onlyPaths?: string[];
  excludePaths?: string[];
  customCases?: CustomCaseDefinition[];
  expectAuth?: boolean;
  authBodyPaths?: string[];
  authContract?: AuthContract;
  /** Opt-in: add HTTP method tampering cases (may modify or delete target data). */
  attackMethods?: boolean;
  language?: Language;
}

export interface GeneratedChecks {
  cases: MutationCase[];
  notes: TranslatableText[];
}
