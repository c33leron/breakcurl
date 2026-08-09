import { parse as tokenize } from "shell-quote";
import type { HttpMethod, JsonObject, ParsedCurl } from "./types.js";

const METHODS = new Set<HttpMethod>(["POST", "PUT", "PATCH", "DELETE"]);
const DATA_OPTIONS = new Set([
  "-d",
  "--data",
  "--data-raw",
  "--data-binary",
  "--json",
]);
const HEADER_OPTIONS = new Set(["-H", "--header"]);
const REQUEST_OPTIONS = new Set(["-X", "--request"]);
const COOKIE_OPTIONS = new Set(["-b", "--cookie"]);
const URL_OPTIONS = new Set(["--url"]);
const IGNORED_COPY_OPTIONS = new Set([
  "--compressed",
  "--globoff",
  "--location",
  "-L",
  "--show-error",
  "-S",
  "--silent",
  "-s",
  "-sS",
]);

/**
 * Parses the deliberately small supported cURL subset as data. This module never
 * executes the input and intentionally rejects shell syntax instead of trying to
 * emulate a shell.
 */
export function parseCurl(input: string): ParsedCurl {
  if (typeof input !== "string" || input.trim() === "") {
    throw new Error("cURL не может быть пустым.");
  }

  rejectCommandSubstitution(input);

  let tokens: ReturnType<typeof tokenize>;
  try {
    tokens = tokenize(input.replace(/\\\r?\n/g, " ").trim(), (name) => ({
      shellVariable: name,
    }));
  } catch {
    throw new Error("В cURL некорректно расставлены кавычки.");
  }

  const args = tokens.map((token) => {
    if (typeof token === "string") return token;
    if ("op" in token && token.op === "glob") return token.pattern;
    if ("shellVariable" in token) {
      throw new Error("Shell-переменные не поддерживаются.");
    }
    throw new Error("Shell-операторы и перенаправления не поддерживаются.");
  });
  if (args.shift() !== "curl") {
    throw new Error("Ввод должен начинаться с curl.");
  }

  let method: HttpMethod | undefined;
  let url: string | undefined;
  let bodyText: string | undefined;
  const headers: Record<string, string> = {};

  for (let index = 0; index < args.length; index += 1) {
    const rawArgument = args[index];
    if (!rawArgument) continue;
    const equals = rawArgument.startsWith("--") ? rawArgument.indexOf("=") : -1;
    const argument = equals > 2 ? rawArgument.slice(0, equals) : rawArgument;
    const inlineValue = equals > 2 ? rawArgument.slice(equals + 1) : undefined;
    const readOptionValue = (message: string): string => {
      if (inlineValue !== undefined) return inlineValue;
      const value = args[index + 1];
      if (value === undefined) throw new Error(message);
      index += 1;
      return value;
    };

    if (REQUEST_OPTIONS.has(argument)) {
      const value = readOptionValue(
        "После -X/--request требуется HTTP-метод.",
      ).toUpperCase();
      if (!value || !METHODS.has(value as HttpMethod)) {
        throw new Error(
          "Поддерживаются только методы POST, PUT, PATCH и DELETE.",
        );
      }
      method = value as HttpMethod;
      continue;
    }

    if (HEADER_OPTIONS.has(argument)) {
      const value = readOptionValue(
        "После -H/--header требуется HTTP-заголовок.",
      );
      const separator = value.indexOf(":");
      if (separator < 1) throw new Error("Некорректный HTTP-заголовок в cURL.");
      const name = value.slice(0, separator).trim();
      const headerValue = value.slice(separator + 1).trim();
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) {
        throw new Error(`Некорректное имя HTTP-заголовка: ${name}`);
      }
      if (/[\0\r\n]/.test(headerValue)) {
        throw new Error(`HTTP-заголовок ${name} содержит управляющие символы.`);
      }
      headers[name] = headerValue;
      continue;
    }

    if (COOKIE_OPTIONS.has(argument)) {
      const value = readOptionValue(
        "После -b/--cookie требуется строка cookie.",
      );
      if (value.startsWith("@")) {
        throw new Error("Cookie-файлы не поддерживаются.");
      }
      if (/[\0\r\n]/.test(value)) {
        throw new Error("Cookie содержит управляющие символы.");
      }
      headers.Cookie = headers.Cookie ? `${headers.Cookie}; ${value}` : value;
      continue;
    }

    if (DATA_OPTIONS.has(argument)) {
      if (bodyText !== undefined)
        throw new Error("Поддерживается только одно JSON-тело.");
      const value = readOptionValue("После опции data требуется JSON-тело.");
      if (value.startsWith("@"))
        throw new Error("Тела запросов из файлов не поддерживаются.");
      bodyText = value;
      if (argument === "--json") {
        setHeaderIfMissing(headers, "Content-Type", "application/json");
        setHeaderIfMissing(headers, "Accept", "application/json");
      }
      continue;
    }

    if (URL_OPTIONS.has(argument)) {
      if (url) throw new Error("Поддерживается только один URL.");
      url = parseHttpUrl(
        readOptionValue("После --url требуется HTTP- или HTTPS-адрес."),
      );
      continue;
    }

    if (IGNORED_COPY_OPTIONS.has(argument)) {
      if (inlineValue !== undefined) {
        throw new Error(`Некорректная опция cURL: ${rawArgument}`);
      }
      continue;
    }

    if (argument.startsWith("-")) {
      throw new Error(`Неподдерживаемая опция cURL: ${argument}`);
    }

    if (inlineValue !== undefined) {
      throw new Error(`Некорректный аргумент cURL: ${rawArgument}`);
    }
    if (url) throw new Error("Поддерживается только один URL.");
    url = parseHttpUrl(argument);
  }

  if (!url || bodyText === undefined) {
    throw new Error("cURL должен содержать один URL и одно JSON-тело.");
  }

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(bodyText);
  } catch {
    throw new Error("Тело запроса должно содержать валидный JSON.");
  }
  if (!isJsonObject(parsedBody))
    throw new Error("В корне JSON-тела должен находиться объект.");

  return { method: method ?? "POST", url, headers, body: parsedBody };
}

function rejectCommandSubstitution(input: string): void {
  let quote: "single" | "double" | undefined;
  let escaped = false;

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "single") {
      escaped = true;
      continue;
    }
    if (character === "'" && quote !== "double") {
      quote = quote === "single" ? undefined : "single";
      continue;
    }
    if (character === '"' && quote !== "single") {
      quote = quote === "double" ? undefined : "double";
      continue;
    }
    if (quote !== "single" && character === "`") {
      throw new Error("Подстановка команд не поддерживается.");
    }
    if (quote !== "single" && character === "$" && input[index + 1] === "(") {
      throw new Error("Подстановка команд не поддерживается.");
    }
  }

  if (quote || escaped)
    throw new Error("В cURL некорректно расставлены кавычки.");
}

function parseHttpUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("cURL должен содержать валидный HTTP-адрес.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Поддерживаются только URL с HTTP или HTTPS.");
  }
  return value;
}

function setHeaderIfMissing(
  headers: Record<string, string>,
  name: string,
  value: string,
): void {
  if (
    !Object.keys(headers).some(
      (header) => header.toLowerCase() === name.toLowerCase(),
    )
  ) {
    headers[name] = value;
  }
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
