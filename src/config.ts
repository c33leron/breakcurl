import { readFile } from "node:fs/promises";
import { message } from "./i18n.js";
import type {
  CheckExpectation,
  CheckProfile,
  CustomCaseDefinition,
  JsonValue,
  Language,
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

export async function loadConfig(
  path: string,
  language: Language = "en",
): Promise<BreakCurlConfig> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    const reason =
      error instanceof Error
        ? error.message
        : message(language, "unknown error", "неизвестная ошибка");
    throw new Error(
      message(
        language,
        `Failed to read config ${path}: ${reason}`,
        `Не удалось прочитать конфиг ${path}: ${reason}`,
      ),
    );
  }
  if (!isObject(raw))
    throw new Error(
      message(
        language,
        "The config root must be a JSON object.",
        "Корень конфига должен быть JSON-объектом.",
      ),
    );

  const unknownKeys = Object.keys(raw).filter((key) => !CONFIG_KEYS.has(key));
  if (unknownKeys.length > 0) {
    throw new Error(
      message(
        language,
        `Unknown config fields: ${unknownKeys.join(", ")}.`,
        `Неизвестные поля конфига: ${unknownKeys.join(", ")}.`,
      ),
    );
  }

  const config: BreakCurlConfig = {};
  if (raw.profile !== undefined) {
    if (
      typeof raw.profile !== "string" ||
      !PROFILES.has(raw.profile as CheckProfile)
    ) {
      throw new Error(
        message(
          language,
          "profile must be quick, negative, security, or full.",
          "profile должен быть quick, negative, security или full.",
        ),
      );
    }
    config.profile = raw.profile as CheckProfile;
  }
  if (raw.maxCases !== undefined) {
    if (!Number.isInteger(raw.maxCases) || (raw.maxCases as number) <= 0) {
      throw new Error(
        message(
          language,
          "maxCases must be a positive integer.",
          "maxCases должен быть положительным целым числом.",
        ),
      );
    }
    config.maxCases = raw.maxCases as number;
  }
  if (raw.onlyPaths !== undefined) {
    config.onlyPaths = stringArray(raw.onlyPaths, "onlyPaths", language);
  }
  if (raw.excludePaths !== undefined) {
    config.excludePaths = stringArray(
      raw.excludePaths,
      "excludePaths",
      language,
    );
  }
  if (raw.expectAuth !== undefined) {
    if (typeof raw.expectAuth !== "boolean") {
      throw new Error(
        message(
          language,
          "expectAuth must be a boolean.",
          "expectAuth должен быть boolean.",
        ),
      );
    }
    config.expectAuth = raw.expectAuth;
  }
  if (raw.customCases !== undefined) {
    if (!Array.isArray(raw.customCases)) {
      throw new Error(
        message(
          language,
          "customCases must be an array.",
          "customCases должен быть массивом.",
        ),
      );
    }
    config.customCases = raw.customCases.map((item, index) =>
      parseCustomCase(item, index, language),
    );
  }
  return config;
}

function parseCustomCase(
  value: unknown,
  index: number,
  language: Language,
): CustomCaseDefinition {
  if (!isObject(value)) {
    throw new Error(
      message(
        language,
        `customCases[${index}] must be a JSON object.`,
        `customCases[${index}] должен быть JSON-объектом.`,
      ),
    );
  }
  const name = requiredString(
    value.name,
    `customCases[${index}].name`,
    language,
  );
  const path = requiredString(
    value.path,
    `customCases[${index}].path`,
    language,
  );
  if (value.operation !== "set" && value.operation !== "remove") {
    throw new Error(
      message(
        language,
        `customCases[${index}].operation must be set or remove.`,
        `customCases[${index}].operation должен быть set или remove.`,
      ),
    );
  }
  let expect: CheckExpectation | undefined;
  if (value.expect !== undefined) {
    if (
      typeof value.expect !== "string" ||
      !EXPECTATIONS.has(value.expect as CheckExpectation)
    ) {
      throw new Error(
        message(
          language,
          `customCases[${index}].expect must be reject, accept, auth-reject, or observe.`,
          `customCases[${index}].expect должен быть reject, accept, auth-reject или observe.`,
        ),
      );
    }
    expect = value.expect as CheckExpectation;
  }

  if (value.operation === "set" && value.value === undefined) {
    throw new Error(
      message(
        language,
        `customCases[${index}] with operation=set requires value.`,
        `customCases[${index}] с operation=set требует value.`,
      ),
    );
  }
  if (value.value !== undefined && !isJsonValue(value.value)) {
    throw new Error(
      message(
        language,
        `customCases[${index}].value must be a JSON value.`,
        `customCases[${index}].value должен быть JSON-значением.`,
      ),
    );
  }

  return {
    name,
    path,
    operation: value.operation,
    ...(value.value !== undefined ? { value: value.value as JsonValue } : {}),
    ...(expect ? { expect } : {}),
  };
}

function stringArray(
  value: unknown,
  name: string,
  language: Language,
): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(
      message(
        language,
        `${name} must be an array of strings.`,
        `${name} должен быть массивом строк.`,
      ),
    );
  }
  return value as string[];
}

function requiredString(
  value: unknown,
  name: string,
  language: Language,
): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(
      message(
        language,
        `${name} must be a non-empty string.`,
        `${name} должен быть непустой строкой.`,
      ),
    );
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
