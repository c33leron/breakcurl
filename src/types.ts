export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export type HttpMethod = "POST" | "PUT" | "PATCH" | "DELETE";

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
  | "custom-set"
  | "custom-remove";

export interface MutationCase {
  id: string;
  path: string;
  description: string;
  kind: MutationKind;
  body: JsonObject;
  category?: CheckCategory;
  expectation?: CheckExpectation;
  source?: "built-in" | "custom";
  headers?: Record<string, string>;
  url?: string;
}

export interface HttpResult {
  status: number;
  latencyMs: number;
  headers: Record<string, string>;
  body: string;
  timedOut: boolean;
  connectionError?: string;
}

export type Classification = "PASS" | "INFO" | "WARN" | "FAIL" | "ERROR";

export type FindingSeverity = "LOW" | "MEDIUM" | "HIGH";
export type FindingConfidence = "LOW" | "MEDIUM" | "HIGH";

export interface SecuritySignal {
  id: string;
  title: string;
  severity: FindingSeverity;
  cwe?: string;
}

export interface CaseResult {
  mutation: MutationCase;
  response: HttpResult;
  classification: Classification;
  reason: string;
  replayFile?: string;
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
  securitySignals?: SecuritySignal[];
}

export interface BaselineResult {
  request: ParsedCurl;
  response: HttpResult;
}

export interface RunResult {
  baseline: BaselineResult;
  cases: CaseResult[];
  profile?: CheckProfile;
  notes?: string[];
}

export interface RunOptions {
  maxCases: number;
  timeoutMs: number;
}

export interface CustomCaseDefinition {
  name: string;
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
}

export interface GeneratedChecks {
  cases: MutationCase[];
  notes: string[];
}
