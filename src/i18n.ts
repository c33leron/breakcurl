import type { Language, TranslatableText } from "./types.js";

export function localized(en: string, ru: string): TranslatableText {
  return { en, ru };
}

export function renderText(
  value: TranslatableText,
  language: Language,
): string {
  return typeof value === "string" ? value : value[language];
}

export function englishText(value: TranslatableText): string {
  return typeof value === "string" ? value : value.en;
}

export function message(language: Language, en: string, ru: string): string {
  return language === "ru" ? ru : en;
}

export function isLanguage(value: string): value is Language {
  return value === "en" || value === "ru";
}

export function detectInitialLanguage(
  args: string[],
  environmentLanguage: string | undefined,
): Language {
  let candidate = environmentLanguage;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--lang") {
      candidate = args[index + 1];
      index += 1;
      continue;
    }
    if (argument?.startsWith("--lang=")) {
      candidate = argument.slice("--lang=".length);
    }
  }
  return candidate === "ru" ? "ru" : "en";
}
