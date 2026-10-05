import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, posix, win32 } from "node:path";
import { isLanguage, message } from "./i18n.js";
import type { Language } from "./types.js";

interface PreferencesPathOptions {
  platform?: NodeJS.Platform;
  home?: string;
  env?: NodeJS.ProcessEnv;
}

export function preferencesPath(options: PreferencesPathOptions = {}): string {
  const platform = options.platform ?? process.platform;
  const home = options.home ?? homedir();
  const env = options.env ?? process.env;
  const path = platform === "win32" ? win32 : posix;
  let configDirectory: string;
  if (platform === "win32") {
    configDirectory =
      env.APPDATA && path.isAbsolute(env.APPDATA)
        ? env.APPDATA
        : path.join(home, "AppData", "Roaming");
  } else if (env.XDG_CONFIG_HOME && path.isAbsolute(env.XDG_CONFIG_HOME)) {
    configDirectory = env.XDG_CONFIG_HOME;
  } else {
    configDirectory =
      platform === "darwin"
        ? path.join(home, "Library", "Application Support")
        : path.join(home, ".config");
  }
  return path.join(configDirectory, "breakcurl", "preferences.json");
}

export async function loadLanguagePreference(
  path?: string,
): Promise<Language | undefined> {
  try {
    const value: unknown = JSON.parse(
      await readFile(path ?? preferencesPath(), "utf8"),
    );
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return undefined;
    }
    const language = (value as Record<string, unknown>).language;
    return typeof language === "string" && isLanguage(language)
      ? language
      : undefined;
  } catch {
    return undefined;
  }
}

export async function saveLanguagePreference(
  language: Language,
  path?: string,
): Promise<string | undefined> {
  let temporaryPath: string | undefined;
  try {
    const targetPath = path ?? preferencesPath();
    await mkdir(dirname(targetPath), { recursive: true, mode: 0o700 });
    temporaryPath = `${targetPath}.${randomUUID()}.tmp`;
    await writeFile(
      temporaryPath,
      `${JSON.stringify({ language }, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600, flag: "wx" },
    );
    await rename(temporaryPath, targetPath);
    return undefined;
  } catch {
    return message(
      language,
      "Could not save your language preference. This run will still use the selected language.",
      "Не удалось сохранить выбранный язык. В этом запуске выбранный язык все равно будет использоваться.",
    );
  } finally {
    if (temporaryPath) await unlink(temporaryPath).catch(() => {});
  }
}

export function shouldPersistLanguagePreference(options: {
  explicitLanguage: string | undefined;
  stdinIsTTY: boolean | undefined;
  stdoutIsTTY: boolean | undefined;
  ci: string | undefined;
}): boolean {
  const ci = options.ci?.toLowerCase();
  return (
    options.explicitLanguage !== undefined &&
    isLanguage(options.explicitLanguage) &&
    options.stdinIsTTY === true &&
    options.stdoutIsTTY === true &&
    (!ci || ci === "false" || ci === "0")
  );
}
