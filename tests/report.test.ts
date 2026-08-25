import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseCurl } from "../src/curl.js";
import { localized } from "../src/i18n.js";
import { writeReport } from "../src/report.js";
import type { RunResult } from "../src/types.js";

const CANARY = "CANARY_SUPER_SECRET_123";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("writeReport", () => {
  it("writes all cases and sanitized replay cURLs for FAIL and WARN findings", async () => {
    const outputDirectory = await mkdtemp(join(tmpdir(), "breakcurl-report-"));
    directories.push(outputDirectory);
    const result: RunResult = {
      baseline: {
        request: {
          method: "POST",
          url: `https://api.example.test/users?token=${CANARY}`,
          headers: {
            Authorization: `Bearer ${CANARY}`,
            "Content-Type": "application/json",
          },
          body: { email: "qa@example.test", password: CANARY, age: 30 },
        },
        response: {
          status: 201,
          latencyMs: 11,
          headers: {},
          body: "",
          timedOut: false,
        },
      },
      cases: [
        {
          mutation: {
            id: "null-age",
            path: "$.age",
            description: "$.age = null",
            kind: "null",
            body: { email: "qa@example.test", password: CANARY, age: null },
          },
          response: {
            status: 500,
            latencyMs: 9,
            headers: {},
            body: "",
            timedOut: false,
          },
          classification: "FAIL",
          reason: localized(
            "The API returned HTTP 500.",
            "API вернул HTTP 500.",
          ),
        },
        {
          mutation: {
            id: "wrong-type-age",
            path: "$.age",
            description: '$.age = "not-a-number"',
            kind: "wrong-type",
            body: {
              email: "qa@example.test",
              password: CANARY,
              age: "not-a-number",
            },
          },
          response: {
            status: 200,
            latencyMs: 7,
            headers: {},
            body: "",
            timedOut: false,
          },
          classification: "WARN",
          reason: localized(
            "The API accepted a wrong-type value with HTTP 200.",
            "API принял значение неправильного типа с HTTP 200.",
          ),
        },
        {
          mutation: {
            id: "remove-email",
            path: "$.email",
            description: localized(
              "field $.email removed",
              "поле $.email удалено",
            ),
            kind: "remove",
            body: { password: CANARY, age: 30 },
          },
          response: {
            status: 422,
            latencyMs: 6,
            headers: {},
            body: "",
            timedOut: false,
          },
          classification: "PASS",
          reason: localized(
            "The API rejected the mutation with HTTP 422.",
            "API отклонил мутацию с HTTP 422.",
          ),
        },
      ],
    };

    const files = await writeReport(result, outputDirectory);
    const output = await Promise.all(
      [files.reportPath, files.jsonReportPath, ...files.findingPaths].map(
        (file) => readFile(file, "utf8"),
      ),
    );
    const rendered = output.join("\n");

    expect(files.findingPaths).toHaveLength(2);
    expect(files.findingPaths.map((file) => file.split("/").at(-1))).toEqual([
      "fail-age-null.curl",
      "warn-age-wrong-type.curl",
    ]);
    expect(rendered).toContain("field $.email removed");
    expect(rendered).toContain("sanitized replay cURL");
    expect(rendered).toContain("# BreakCurl report");
    expect(rendered).toContain('"schemaVersion": 1');
    expect(rendered).toContain('"language": "en"');
    expect(rendered).not.toContain('"body"');
    expect(rendered).not.toContain("# Отчёт BreakCurl");
    expect(rendered).toContain("<REDACTED>");
    expect(rendered).not.toContain(CANARY);

    const failReplay = parseCurl(output[2] ?? "");
    expect(failReplay.body).toEqual({
      email: "qa@example.test",
      password: "<REDACTED>",
      age: null,
    });
    expect(failReplay.headers.Authorization).toBe("Bearer <REDACTED>");
  });

  it("localizes Markdown while keeping report.json in stable English", async () => {
    const outputDirectory = await mkdtemp(join(tmpdir(), "breakcurl-report-"));
    directories.push(outputDirectory);
    const result: RunResult = {
      language: "ru",
      baseline: {
        request: {
          method: "POST",
          url: "https://api.example.test/users",
          headers: { "Content-Type": "application/json" },
          body: { age: 30 },
        },
        response: {
          status: 201,
          latencyMs: 11,
          headers: {},
          body: "",
          timedOut: false,
        },
      },
      cases: [
        {
          mutation: {
            id: "null-age",
            path: "$.age",
            description: localized("$.age = null", "$.age = null"),
            kind: "null",
            body: { age: null },
          },
          response: {
            status: 422,
            latencyMs: 8,
            headers: {},
            body: "",
            timedOut: false,
          },
          classification: "PASS",
          reason: localized(
            "The API rejected the mutation with HTTP 422.",
            "API отклонил мутацию с HTTP 422.",
          ),
        },
      ],
    };

    const files = await writeReport(result, outputDirectory);
    const markdown = await readFile(files.reportPath, "utf8");
    const json = await readFile(files.jsonReportPath, "utf8");

    expect(markdown).toContain("# Отчёт BreakCurl");
    expect(markdown).toContain("API отклонил мутацию");
    expect(json).toContain('"language": "en"');
    expect(json).toContain("The API rejected the mutation");
    expect(json).not.toContain("API отклонил мутацию");
  });
});
