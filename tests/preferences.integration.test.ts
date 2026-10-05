import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const FORCE_TTY = `data:text/javascript,${encodeURIComponent(
  'Object.defineProperty(process.stdin, "isTTY", { value: true }); Object.defineProperty(process.stdout, "isTTY", { value: true });',
)}`;
const directories: string[] = [];
const RUSSIAN_DEMO = "План демо: 0 запросов";
const ENGLISH_DEMO = "Demo dry-run: 0 requests";

async function configDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "breakcurl-preferences-cli-"));
  directories.push(path);
  return path;
}

function preferenceFile(directory: string): string {
  return join(directory, "breakcurl", "preferences.json");
}

function runCli(
  directory: string,
  args: string[] = [],
  options: {
    interactive?: boolean;
    env?: NodeJS.ProcessEnv;
    cwd?: string;
  } = {},
): { code: number | null; stdout: string; stderr: string } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    XDG_CONFIG_HOME: directory,
    APPDATA: directory,
    NO_COLOR: "1",
  };
  delete env.BREAKCURL_LANG;
  delete env.CI;
  delete env.FORCE_COLOR;
  Object.assign(env, options.env);
  const nodeArgs = options.interactive === false ? [] : ["--import", FORCE_TTY];
  const result = spawnSync(
    process.execPath,
    [...nodeArgs, CLI, "demo", "--dry-run", "--no-color", ...args],
    {
      cwd: options.cwd ?? directory,
      env,
      encoding: "utf8",
      timeout: 10_000,
    },
  );
  if (result.error) throw result.error;
  return {
    code: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

async function saveRussian(directory: string): Promise<void> {
  const result = runCli(directory, ["--lang", "ru"]);
  expect(result.code, result.stderr).toBe(0);
  expect(result.stdout).toContain(RUSSIAN_DEMO);
  expect(JSON.parse(await readFile(preferenceFile(directory), "utf8"))).toEqual(
    {
      language: "ru",
    },
  );
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("language preferences across CLI processes", () => {
  it("remembers an interactive language choice in another process and working directory", async () => {
    const directory = await configDirectory();
    await saveRussian(directory);
    const anotherProject = join(directory, "another-project");
    await mkdir(anotherProject);

    const nextRun = runCli(directory, [], { cwd: anotherProject });
    expect(nextRun.code, nextRun.stderr).toBe(0);
    expect(nextRun.stdout).toContain(RUSSIAN_DEMO);
  });

  it("lets another explicit choice override both environment and the saved language", async () => {
    const directory = await configDirectory();
    await saveRussian(directory);

    const changed = runCli(directory, ["--lang=en"], {
      env: { BREAKCURL_LANG: "ru" },
    });
    expect(changed.code, changed.stderr).toBe(0);
    expect(changed.stdout).toContain(ENGLISH_DEMO);
    expect(
      JSON.parse(await readFile(preferenceFile(directory), "utf8")),
    ).toEqual({
      language: "en",
    });
    expect(runCli(directory).stdout).toContain(ENGLISH_DEMO);
  });

  it("uses an environment override for one run without changing the saved choice", async () => {
    const directory = await configDirectory();
    await saveRussian(directory);

    const overridden = runCli(directory, [], { env: { BREAKCURL_LANG: "en" } });
    expect(overridden.code, overridden.stderr).toBe(0);
    expect(overridden.stdout).toContain(ENGLISH_DEMO);
    expect(
      JSON.parse(await readFile(preferenceFile(directory), "utf8")),
    ).toEqual({
      language: "ru",
    });
    expect(runCli(directory).stdout).toContain(RUSSIAN_DEMO);
  });

  it.each([
    { label: "CI", options: { env: { CI: "true" } } },
    { label: "noninteractive", options: { interactive: false } },
  ])(
    "keeps explicit language changes temporary in $label runs",
    async ({ options }) => {
      const directory = await configDirectory();
      await saveRussian(directory);

      const overridden = runCli(directory, ["--lang", "en"], options);
      expect(overridden.code, overridden.stderr).toBe(0);
      expect(overridden.stdout).toContain(ENGLISH_DEMO);
      expect(
        JSON.parse(await readFile(preferenceFile(directory), "utf8")),
      ).toEqual({
        language: "ru",
      });
      expect(runCli(directory).stdout).toContain(RUSSIAN_DEMO);
    },
  );

  it("rejects invalid language flags without creating or replacing preferences", async () => {
    const directory = await configDirectory();
    const invalidFirstRun = runCli(directory, ["--lang", "de"]);
    expect(invalidFirstRun.code).not.toBe(0);
    expect(invalidFirstRun.stderr).toContain("language must be en or ru");
    await expect(
      readFile(preferenceFile(directory), "utf8"),
    ).rejects.toMatchObject({
      code: "ENOENT",
    });

    await saveRussian(directory);
    const invalidLaterRun = runCli(directory, ["--lang=de"]);
    expect(invalidLaterRun.code).not.toBe(0);
    expect(
      JSON.parse(await readFile(preferenceFile(directory), "utf8")),
    ).toEqual({
      language: "ru",
    });
    expect(runCli(directory).stdout).toContain(RUSSIAN_DEMO);
  });

  it("ignores corrupt preferences and replaces them after a valid explicit choice", async () => {
    const directory = await configDirectory();
    await mkdir(join(directory, "breakcurl"));
    await writeFile(preferenceFile(directory), "not JSON");

    const fallback = runCli(directory);
    expect(fallback.code, fallback.stderr).toBe(0);
    expect(fallback.stdout).toContain(ENGLISH_DEMO);
    await saveRussian(directory);
    expect(runCli(directory).stdout).toContain(RUSSIAN_DEMO);
  });

  it("keeps the selected language and exits successfully when persistence fails", async () => {
    const directory = await configDirectory();
    await writeFile(join(directory, "breakcurl"), "unrelated existing file");

    const result = runCli(directory, ["--lang", "ru"]);
    expect(result.code, result.stderr).toBe(0);
    expect(result.stdout).toContain(RUSSIAN_DEMO);
    expect(result.stderr).toContain("Не удалось сохранить выбранный язык");
    expect(await readFile(join(directory, "breakcurl"), "utf8")).toBe(
      "unrelated existing file",
    );
  });
});
