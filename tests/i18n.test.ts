import { describe, expect, it } from "vitest";
import {
  detectInitialLanguage,
  englishText,
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
});
