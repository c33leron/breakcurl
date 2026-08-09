import { readFile } from "node:fs/promises";
import type {
  CheckExpectation,
  CheckProfile,
  CustomCaseDefinition,
  JsonValue,
} from "./types.js";

export interface BreakCurlConfig {
  profile?: CheckProfile;
  maxCases?: number;
  onlyPaths?: string[];
  excludePaths?: string[];
  expectAuth?: boolean;
  customCases?: CustomCaseDefinition[];
}

const PROFILES = new Set<CheckProfile>([
  "quick",
  "negative",
  "security",
  "full",
]);
const EXPECTATIONS = new Set<CheckExpectation>([
  "reject",
  "accept",
  "auth-reject",
  "observe",
]);
const CONFIG_KEYS = new Set([
  "profile",
  "maxCases",
  "onlyPaths",
  "excludePaths",
  "expectAuth",
  "customCases",
]);

export async function loadConfig(path: string): Promise<BreakCurlConfig> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : "неизвестная ошибка";
    throw new Error(`Не удалось прочитать конфиг ${path}: ${reason}`);
  }
  if (!isObject(raw))
    throw new Error("Корень конфига должен быть JSON-объектом.");

  const unknownKeys = Object.keys(raw).filter((key) => !CONFIG_KEYS.has(key));
  if (unknownKeys.length > 0) {
    throw new Error(`Неизвестные поля конфига: ${unknownKeys.join(", ")}.`);
  }

  const config: BreakCurlConfig = {};
  if (raw.profile !== undefined) {
    if (
      typeof raw.profile !== "string" ||
      !PROFILES.has(raw.profile as CheckProfile)
    ) {
      throw new Error(
        "profile должен быть quick, negative, security или full.",
      );
    }
    config.profile = raw.profile as CheckProfile;
  }
  if (raw.maxCases !== undefined) {
    if (!Number.isInteger(raw.maxCases) || (raw.maxCases as number) <= 0) {
      throw new Error("maxCases должен быть положительным целым числом.");
    }
    config.maxCases = raw.maxCases as number;
  }
  if (raw.onlyPaths !== undefined) {
    config.onlyPaths = stringArray(raw.onlyPaths, "onlyPaths");
  }
  if (raw.excludePaths !== undefined) {
    config.excludePaths = stringArray(raw.excludePaths, "excludePaths");
  }
  if (raw.expectAuth !== undefined) {
    if (typeof raw.expectAuth !== "boolean") {
      throw new Error("expectAuth должен быть boolean.");
    }
    config.expectAuth = raw.expectAuth;
  }
  if (raw.customCases !== undefined) {
    if (!Array.isArray(raw.customCases)) {
      throw new Error("customCases должен быть массивом.");
    }
    config.customCases = raw.customCases.map(parseCustomCase);
  }
  return config;
}

function parseCustomCase(value: unknown, index: number): CustomCaseDefinition {
  if (!isObject(value)) {
    throw new Error(`customCases[${index}] должен быть JSON-объектом.`);
  }
  const name = requiredString(value.name, `customCases[${index}].name`);
  const path = requiredString(value.path, `customCases[${index}].path`);
  if (value.operation !== "set" && value.operation !== "remove") {
    throw new Error(
      `customCases[${index}].operation должен быть set или remove.`,
    );
  }
  let expect: CheckExpectation | undefined;
  if (value.expect !== undefined) {
    if (
      typeof value.expect !== "string" ||
      !EXPECTATIONS.has(value.expect as CheckExpectation)
    ) {
      throw new Error(
        `customCases[${index}].expect должен быть reject, accept, auth-reject или observe.`,
      );
    }
    expect = value.expect as CheckExpectation;
  }

  if (value.operation === "set" && value.value === undefined) {
    throw new Error(`customCases[${index}] с operation=set требует value.`);
  }
  if (value.value !== undefined && !isJsonValue(value.value)) {
    throw new Error(`customCases[${index}].value должен быть JSON-значением.`);
  }

  return {
    name,
    path,
    operation: value.operation,
    ...(value.value !== undefined ? { value: value.value as JsonValue } : {}),
    ...(expect ? { expect } : {}),
  };
}

function stringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`${name} должен быть массивом строк.`);
  }
  return value as string[];
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${name} должен быть непустой строкой.`);
  }
  return value;
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null) return true;
  if (["string", "number", "boolean"].includes(typeof value)) return true;
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (!isObject(value)) return false;
  return Object.values(value).every(isJsonValue);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
