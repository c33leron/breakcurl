import { message } from "./i18n.js";
import type { Language } from "./types.js";

type Quote = "single" | "double" | "ansi";
type Issue = "substitution" | "escape" | "utf8" | "nul";

// Normalize only quoting, never evaluate shell input. The paste reader shares
// this scanner so a complete browser command cannot get stuck waiting for quotes.
export function needsMoreShellInput(input: string): boolean {
  return scan(input).incomplete;
}

export function normalizeShellInput(input: string, language: Language): string {
  const result = scan(input);
  if (result.incomplete) {
    throw new Error(
      message(
        language,
        "cURL contains mismatched quotes.",
        "В cURL некорректно расставлены кавычки.",
      ),
    );
  }
  if (result.issue) {
    const errors: Record<Issue, [string, string]> = {
      substitution: [
        "Command substitution is not supported.",
        "Подстановка команд не поддерживается.",
      ],
      escape: [
        "Unsupported or invalid ANSI-C escape in cURL.",
        "Неподдерживаемая или некорректная ANSI-C escape-последовательность в cURL.",
      ],
      utf8: [
        "ANSI-C quoted text must contain valid UTF-8.",
        "Текст в ANSI-C кавычках должен содержать валидный UTF-8.",
      ],
      nul: [
        "NUL characters are not supported in cURL.",
        "NUL-символы в cURL не поддерживаются.",
      ],
    };
    throw new Error(message(language, ...errors[result.issue]));
  }
  return result.normalized;
}

function scan(input: string): {
  normalized: string;
  incomplete: boolean;
  issue: Issue | undefined;
} {
  let quote: Quote | undefined;
  let normalized = "";
  let issue: Issue | undefined = input.includes("\0") ? "nul" : undefined;
  let trailingEscape = false;
  let literal = "";
  let bytes: Buffer[] = [];
  const flushLiteral = () => {
    // Buffer would replace lone UTF-16 surrogates with U+FFFD before decoding.
    if (/[\ud800-\udfff]/u.test(literal)) issue ??= "utf8";
    if (literal) bytes.push(Buffer.from(literal, "utf8"));
    literal = "";
  };

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index] ?? "";
    const next = input[index + 1];
    if (quote === "ansi") {
      if (character === "'") {
        flushLiteral();
        try {
          const decoded = new TextDecoder("utf-8", {
            fatal: true,
            ignoreBOM: true,
          }).decode(Buffer.concat(bytes));
          if (decoded.includes("\0")) issue ??= "nul";
          // Decoded quotes and shell metacharacters remain literal argument data.
          normalized += `'${decoded.replaceAll("'", "'\\''")}'`;
        } catch {
          issue ??= "utf8";
        }
        bytes = [];
        quote = undefined;
      } else if (character === "\\") {
        if (next === undefined) {
          trailingEscape = true;
          break;
        }
        flushLiteral();
        const simple: Record<string, string> = {
          a: "\x07",
          b: "\b",
          e: "\x1b",
          E: "\x1b",
          f: "\f",
          n: "\n",
          r: "\r",
          t: "\t",
          v: "\v",
          "\\": "\\",
          "'": "'",
          '"': '"',
          "?": "?",
        };
        const decoded = simple[next];
        if (decoded !== undefined) {
          bytes.push(Buffer.from(decoded));
          index += 1;
        } else if (next === "x" || next === "u" || next === "U") {
          const width = next === "x" ? 2 : next === "u" ? 4 : 8;
          const digits = input.slice(index + 2, index + 2 + width);
          if (digits.length !== width || !/^[\da-f]+$/i.test(digits)) {
            issue ??= "escape";
            index += 1;
            continue;
          }
          const value = Number.parseInt(digits, 16);
          if (value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
            issue ??= "escape";
          } else {
            bytes.push(
              next === "x"
                ? Buffer.from([value])
                : Buffer.from(String.fromCodePoint(value)),
            );
          }
          index += 1 + width;
        } else if (/[0-7]/.test(next)) {
          const digits = input.slice(index + 1).match(/^[0-7]{1,3}/)?.[0] ?? "";
          const value = Number.parseInt(digits, 8);
          if (value > 0xff) issue ??= "escape";
          else bytes.push(Buffer.from([value]));
          index += digits.length;
        } else if (next === "\n") {
          // ANSI-C quoting preserves backslash-newline, unlike an unquoted
          // shell continuation. Do not silently change the request body.
          bytes.push(Buffer.from("\\\n"));
          index += 1;
        } else {
          issue ??= "escape";
          index += 1;
        }
      } else {
        literal += character;
      }
      continue;
    }
    if (quote === "single") {
      normalized += character;
      if (character === "'") quote = undefined;
      continue;
    }
    if (character === "\\") {
      if (next === undefined) {
        trailingEscape = true;
        break;
      }
      if (next === "\n") index += 1;
      else if (next === "\r" && input[index + 2] === "\n") index += 2;
      else if (quote === "double" && next === "\x60") {
        // shell-quote does not unescape double-quoted backticks itself.
        normalized += next;
        index += 1;
      } else if (quote !== "double" || ['"', "\\", "$"].includes(next)) {
        normalized += character + next;
        index += 1;
      } else {
        normalized += character;
      }
      continue;
    }
    if (character === "\x60" || (character === "$" && next === "(")) {
      issue ??= "substitution";
    }
    if (quote === "double") {
      normalized += character;
      if (character === '"') quote = undefined;
    } else if (character === "$" && next === "'") {
      quote = "ansi";
      index += 1;
    } else {
      normalized += character;
      if (character === "'") quote = "single";
      if (character === '"') quote = "double";
    }
  }
  return {
    normalized,
    incomplete: quote !== undefined || trailingEscape,
    issue,
  };
}
