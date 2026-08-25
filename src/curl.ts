import { parse as tokenize } from "shell-quote";
import { message } from "./i18n.js";
import type { HttpMethod, JsonObject, Language, ParsedCurl } from "./types.js";

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
export function parseCurl(
  input: string,
  language: Language = "en",
): ParsedCurl {
  if (typeof input !== "string" || input.trim() === "") {
    throw localizedError(
      language,
      "cURL cannot be empty.",
      "cURL не может быть пустым.",
    );
  }

  rejectCommandSubstitution(input, language);

  let tokens: ReturnType<typeof tokenize>;
  try {
    tokens = tokenize(input.replace(/\\\r?\n/g, " ").trim(), (name) => ({
      shellVariable: name,
    }));
  } catch {
    throw localizedError(
      language,
      "cURL contains mismatched quotes.",
      "В cURL некорректно расставлены кавычки.",
    );
  }

  const args = tokens.map((token) => {
    if (typeof token === "string") return token;
    if ("op" in token && token.op === "glob") return token.pattern;
    if ("shellVariable" in token) {
      throw localizedError(
        language,
        "Shell variables are not supported.",
        "Shell-переменные не поддерживаются.",
      );
    }
    throw localizedError(
      language,
      "Shell operators and redirects are not supported.",
      "Shell-операторы и перенаправления не поддерживаются.",
    );
  });
  if (args.shift() !== "curl") {
    throw localizedError(
      language,
      "Input must start with curl.",
      "Ввод должен начинаться с curl.",
    );
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
        message(
          language,
          "-X/--request requires an HTTP method.",
          "После -X/--request требуется HTTP-метод.",
        ),
      ).toUpperCase();
      if (!value || !METHODS.has(value as HttpMethod)) {
        throw new Error(
          message(
            language,
            "Only POST, PUT, PATCH, and DELETE methods are supported.",
            "Поддерживаются только методы POST, PUT, PATCH и DELETE.",
          ),
        );
      }
      method = value as HttpMethod;
      continue;
    }

    if (HEADER_OPTIONS.has(argument)) {
      const value = readOptionValue(
        message(
          language,
          "-H/--header requires an HTTP header.",
          "После -H/--header требуется HTTP-заголовок.",
        ),
      );
      const separator = value.indexOf(":");
      if (separator < 1) {
        throw localizedError(
          language,
          "Invalid HTTP header in cURL.",
          "Некорректный HTTP-заголовок в cURL.",
        );
      }
      const name = value.slice(0, separator).trim();
      const headerValue = value.slice(separator + 1).trim();
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) {
        throw localizedError(
          language,
          `Invalid HTTP header name: ${name}`,
          `Некорректное имя HTTP-заголовка: ${name}`,
        );
      }
      if (/[\0\r\n]/.test(headerValue)) {
        throw localizedError(
          language,
          `HTTP header ${name} contains control characters.`,
          `HTTP-заголовок ${name} содержит управляющие символы.`,
        );
      }
      headers[name] = headerValue;
      continue;
    }

    if (COOKIE_OPTIONS.has(argument)) {
      const value = readOptionValue(
        message(
          language,
          "-b/--cookie requires a cookie string.",
          "После -b/--cookie требуется строка cookie.",
        ),
      );
      if (value.startsWith("@")) {
        throw localizedError(
          language,
          "Cookie files are not supported.",
          "Cookie-файлы не поддерживаются.",
        );
      }
      if (/[\0\r\n]/.test(value)) {
        throw localizedError(
          language,
          "Cookie contains control characters.",
          "Cookie содержит управляющие символы.",
        );
      }
      headers.Cookie = headers.Cookie ? `${headers.Cookie}; ${value}` : value;
      continue;
    }

    if (DATA_OPTIONS.has(argument)) {
      if (bodyText !== undefined)
        throw localizedError(
          language,
          "Only one JSON body is supported.",
          "Поддерживается только одно JSON-тело.",
        );
      const value = readOptionValue(
        message(
          language,
          "The data option requires a JSON body.",
          "После опции data требуется JSON-тело.",
        ),
      );
      if (value.startsWith("@"))
        throw localizedError(
          language,
          "Request bodies from files are not supported.",
          "Тела запросов из файлов не поддерживаются.",
        );
      bodyText = value;
      if (argument === "--json") {
        setHeaderIfMissing(headers, "Content-Type", "application/json");
        setHeaderIfMissing(headers, "Accept", "application/json");
      }
      continue;
    }

    if (URL_OPTIONS.has(argument)) {
      if (url)
        throw localizedError(
          language,
          "Only one URL is supported.",
          "Поддерживается только один URL.",
        );
      url = parseHttpUrl(
        readOptionValue(
          message(
            language,
            "--url requires an HTTP or HTTPS address.",
            "После --url требуется HTTP- или HTTPS-адрес.",
          ),
        ),
        language,
      );
      continue;
    }

    if (IGNORED_COPY_OPTIONS.has(argument)) {
      if (inlineValue !== undefined) {
        throw localizedError(
          language,
          `Invalid cURL option: ${rawArgument}`,
          `Некорректная опция cURL: ${rawArgument}`,
        );
      }
      continue;
    }

    if (argument.startsWith("-")) {
      throw localizedError(
        language,
        `Unsupported cURL option: ${argument}`,
        `Неподдерживаемая опция cURL: ${argument}`,
      );
    }

    if (inlineValue !== undefined) {
      throw localizedError(
        language,
        `Invalid cURL argument: ${rawArgument}`,
        `Некорректный аргумент cURL: ${rawArgument}`,
      );
    }
    if (url)
      throw localizedError(
        language,
        "Only one URL is supported.",
        "Поддерживается только один URL.",
      );
    url = parseHttpUrl(argument, language);
  }

  if (!url || bodyText === undefined) {
    throw localizedError(
      language,
      "cURL must contain one URL and one JSON body.",
      "cURL должен содержать один URL и одно JSON-тело.",
    );
  }

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(bodyText);
  } catch {
    throw localizedError(
      language,
      "Request body must contain valid JSON.",
      "Тело запроса должно содержать валидный JSON.",
    );
  }
  if (!isJsonObject(parsedBody))
    throw localizedError(
      language,
      "The root JSON value must be an object.",
      "В корне JSON-тела должен находиться объект.",
    );

  return { method: method ?? "POST", url, headers, body: parsedBody };
}

function rejectCommandSubstitution(input: string, language: Language): void {
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
      throw localizedError(
        language,
        "Command substitution is not supported.",
        "Подстановка команд не поддерживается.",
      );
    }
    if (quote !== "single" && character === "$" && input[index + 1] === "(") {
      throw localizedError(
        language,
        "Command substitution is not supported.",
        "Подстановка команд не поддерживается.",
      );
    }
  }

  if (quote || escaped)
    throw localizedError(
      language,
      "cURL contains mismatched quotes.",
      "В cURL некорректно расставлены кавычки.",
    );
}

function parseHttpUrl(value: string, language: Language): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw localizedError(
      language,
      "cURL must contain a valid HTTP address.",
      "cURL должен содержать валидный HTTP-адрес.",
    );
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw localizedError(
      language,
      "Only HTTP and HTTPS URLs are supported.",
      "Поддерживаются только URL с HTTP или HTTPS.",
    );
  }
  return value;
}

function localizedError(language: Language, en: string, ru: string): Error {
  return new Error(message(language, en, ru));
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
