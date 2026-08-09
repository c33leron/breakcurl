import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("BreakCurl config", () => {
  it("loads profile, path filters, auth expectation and custom cases", async () => {
    const directory = await mkdtemp(join(tmpdir(), "breakcurl-config-"));
    directories.push(directory);
    const path = join(directory, "breakcurl.config.json");
    await writeFile(
      path,
      JSON.stringify({
        profile: "security",
        maxCases: 75,
        onlyPaths: ["$.profile"],
        excludePaths: ["$.profile.secret"],
        expectAuth: true,
        customCases: [
          {
            name: "Unknown enum",
            path: "$.profile.status",
            operation: "set",
            value: "UNKNOWN",
            expect: "reject",
          },
        ],
      }),
      "utf8",
    );

    await expect(loadConfig(path)).resolves.toMatchObject({
      profile: "security",
      maxCases: 75,
      expectAuth: true,
      customCases: [{ operation: "set", value: "UNKNOWN" }],
    });
  });

  it("rejects unknown keys and malformed custom cases", async () => {
    const directory = await mkdtemp(join(tmpdir(), "breakcurl-config-"));
    directories.push(directory);
    const unknown = join(directory, "unknown.json");
    const malformed = join(directory, "malformed.json");
    await writeFile(unknown, JSON.stringify({ profille: "security" }), "utf8");
    await writeFile(
      malformed,
      JSON.stringify({
        customCases: [{ name: "broken", path: "$.x", operation: "set" }],
      }),
      "utf8",
    );

    await expect(loadConfig(unknown)).rejects.toThrow("Неизвестные поля");
    await expect(loadConfig(malformed)).rejects.toThrow("требует value");
  });
});
