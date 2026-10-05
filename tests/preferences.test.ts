import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  loadLanguagePreference,
  preferencesPath,
  saveLanguagePreference,
  shouldPersistLanguagePreference,
} from "../src/preferences.js";

const directories: string[] = [];

async function directory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "breakcurl-preferences-"));
  directories.push(path);
  return path;
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("user language preferences", () => {
  it("uses per-user config directories independently of the working directory", () => {
    expect(
      preferencesPath({ platform: "linux", home: "/users/qa", env: {} }),
    ).toBe("/users/qa/.config/breakcurl/preferences.json");
    expect(
      preferencesPath({ platform: "darwin", home: "/users/qa", env: {} }),
    ).toBe("/users/qa/Library/Application Support/breakcurl/preferences.json");
    expect(
      preferencesPath({
        platform: "linux",
        home: "/users/qa",
        env: { XDG_CONFIG_HOME: "/custom/config" },
      }),
    ).toBe("/custom/config/breakcurl/preferences.json");
    expect(
      preferencesPath({
        platform: "linux",
        home: "/users/qa",
        env: { XDG_CONFIG_HOME: "relative/config" },
      }),
    ).toBe("/users/qa/.config/breakcurl/preferences.json");
    expect(
      preferencesPath({
        platform: "win32",
        home: "C:\\Users\\qa",
        env: { APPDATA: "C:\\Users\\qa\\Roaming" },
      }),
    ).toBe("C:\\Users\\qa\\Roaming\\breakcurl\\preferences.json");
    expect(
      preferencesPath({ platform: "win32", home: "C:\\Users\\qa", env: {} }),
    ).toBe("C:\\Users\\qa\\AppData\\Roaming\\breakcurl\\preferences.json");
  });

  it("saves only language, replaces the choice, and leaves no temporary files", async () => {
    const root = await directory();
    const path = join(root, "breakcurl", "preferences.json");
    expect(await loadLanguagePreference(path)).toBeUndefined();
    expect(await saveLanguagePreference("ru", path)).toBeUndefined();
    expect(await loadLanguagePreference(path)).toBe("ru");
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual({
      language: "ru",
    });
    expect(await saveLanguagePreference("en", path)).toBeUndefined();
    expect(await loadLanguagePreference(path)).toBe("en");
    expect(await readdir(join(root, "breakcurl"))).toEqual([
      "preferences.json",
    ]);
    if (process.platform !== "win32") {
      expect((await stat(path)).mode & 0o777).toBe(0o600);
    }
  });

  it("keeps concurrent writes valid and complete", async () => {
    const root = await directory();
    const path = join(root, "preferences.json");
    expect(
      await Promise.all([
        saveLanguagePreference("ru", path),
        saveLanguagePreference("en", path),
      ]),
    ).toEqual([undefined, undefined]);
    expect(["en", "ru"]).toContain(await loadLanguagePreference(path));
    expect(await readdir(root)).toEqual(["preferences.json"]);
  });

  it.each([
    "not JSON",
    "null",
    "[]",
    '"ru"',
    "{}",
    '{"language":42}',
    '{"language":"de"}',
  ])("ignores invalid preferences: %s", async (contents) => {
    const path = join(await directory(), "preferences.json");
    await writeFile(path, contents);
    expect(await loadLanguagePreference(path)).toBeUndefined();
  });

  it("ignores read failures and returns a localized write warning", async () => {
    const root = await directory();
    const blocker = join(root, "file");
    await writeFile(blocker, "existing unrelated file");
    const path = join(blocker, "preferences.json");
    expect(await loadLanguagePreference(path)).toBeUndefined();
    expect(await saveLanguagePreference("ru", path)).toContain(
      "Не удалось сохранить выбранный язык",
    );
    expect(await saveLanguagePreference("en", path)).toContain(
      "Could not save your language preference",
    );
    expect(await readFile(blocker, "utf8")).toBe("existing unrelated file");
  });

  it("cleans temporary files when replacing the destination fails", async () => {
    const root = await directory();
    const path = join(root, "preferences.json");
    await mkdir(path);
    await writeFile(join(path, "keep"), "untouched");
    expect(await saveLanguagePreference("en", path)).toContain(
      "Could not save",
    );
    expect(await readdir(root)).toEqual(["preferences.json"]);
    expect(await readFile(join(path, "keep"), "utf8")).toBe("untouched");
  });

  it("persists explicit interactive choices only, leaving CI and pipes temporary", () => {
    const interactive = {
      explicitLanguage: "ru",
      stdinIsTTY: true,
      stdoutIsTTY: true,
      ci: undefined,
    };
    expect(shouldPersistLanguagePreference(interactive)).toBe(true);
    for (const override of [
      { explicitLanguage: undefined },
      { explicitLanguage: "de" },
      { stdinIsTTY: false },
      { stdinIsTTY: undefined },
      { stdoutIsTTY: false },
      { stdoutIsTTY: undefined },
      { ci: "true" },
      { ci: "1" },
    ]) {
      expect(
        shouldPersistLanguagePreference({ ...interactive, ...override }),
      ).toBe(false);
    }
    expect(
      shouldPersistLanguagePreference({ ...interactive, ci: "false" }),
    ).toBe(true);
  });
});
