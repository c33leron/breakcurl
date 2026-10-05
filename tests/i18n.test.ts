import { describe, expect, it } from "vitest";
import {
  detectInitialLanguage,
  englishText,
  explicitLanguageArgument,
  localized,
  renderText,
} from "../src/i18n.js";

describe("interface language", () => {
  it("uses English by default and lets argv override the environment", () => {
    expect(detectInitialLanguage([], undefined)).toBe("en");
    expect(detectInitialLanguage([], "ru")).toBe("ru");
    expect(detectInitialLanguage(["--lang", "en"], "ru")).toBe("en");
    expect(detectInitialLanguage(["--lang=ru"], "en")).toBe("ru");
  });

  it("renders human text in the selected language and machine text in English", () => {
    const text = localized("English", "Русский");

    expect(renderText(text, "ru")).toBe("Русский");
    expect(renderText(text, "en")).toBe("English");
    expect(englishText(text)).toBe("English");
  });

  it("uses saved language below explicit flags and environment overrides", () => {
    expect(detectInitialLanguage([], undefined, "ru")).toBe("ru");
    expect(detectInitialLanguage([], "en", "ru")).toBe("en");
    expect(detectInitialLanguage(["--lang=ru"], "en", "en")).toBe("ru");
    expect(detectInitialLanguage(["--lang", "en"], "ru", "ru")).toBe("en");
    expect(detectInitialLanguage([], "invalid", "ru")).toBe("ru");
    expect(detectInitialLanguage(["--lang", "invalid"], "ru", "en")).toBe("ru");
  });

  it("honors the last explicit language and stops scanning at the option terminator", () => {
    expect(explicitLanguageArgument(["--lang=ru", "--lang", "en"])).toBe("en");
    expect(
      explicitLanguageArgument(["--lang", "ru", "--lang"]),
    ).toBeUndefined();
    expect(explicitLanguageArgument(["--", "--lang=ru"])).toBeUndefined();
    expect(detectInitialLanguage(["--", "--lang", "ru"], "en")).toBe("en");
  });
});
