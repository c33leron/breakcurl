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
    const html = await readFile(files.htmlReportPath, "utf8");
    expect(files.htmlReportPath).toBe(join(outputDirectory, "report.html"));
    expect(html).toContain("<!doctype html>");
    expect(html).not.toContain(CANARY);
    expect(html).toContain('href="findings/fail-age-null.curl"');
    const machineReport = JSON.parse(output[1] ?? "{}");
    expect(machineReport.outcome).toMatchObject({
      status: "findings",
      exitCode: 1,
      requestsAttempted: 4,
      checksRun: 3,
    });
    expect(machineReport.cases[0].replay).toBe("findings/fail-age-null.curl");

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
    const html = await readFile(files.htmlReportPath, "utf8");

    expect(markdown).toContain("# Отчёт BreakCurl");
    expect(markdown).toContain("API отклонил мутацию");
    expect(json).toContain('"language": "en"');
    expect(json).toContain("The API rejected the mutation");
    expect(json).not.toContain("API отклонил мутацию");
    expect(html).toContain("Отчет BreakCurl");
    expect(html).toContain("API отклонил мутацию");
  });

  it("keeps untrusted Markdown inert and preserves incomplete-response metadata", async () => {
    const outputDirectory = await mkdtemp(join(tmpdir(), "breakcurl-report-"));
    directories.push(outputDirectory);
    const attack =
      "`code` ![pixel](https://evil.test/pixel) [link](https://evil.test) </script><img src=x onerror=alert(1)> |\n# forged";
    const response = {
      status: 200,
      latencyMs: 1,
      headers: {},
      body: "PRIVATE_RESPONSE_CANARY",
      timedOut: false,
      bodyTruncated: true,
    };
    const result: RunResult = {
      mode: "idor",
      completedRequests: 2,
      plannedRequests: 3,
      baseline: {
        request: {
          method: "GET",
          url: `https://example.test/path?value=${encodeURIComponent(attack)}`,
          headers: { Authorization: `Bearer ${CANARY}` },
          body: {},
        },
        response,
        assessment: {
          classification: "WARN",
          reason: `${attack} ${CANARY}`,
          securitySignals: [
            {
              id: CANARY,
              title: `Signal ${CANARY}`,
              severity: "HIGH",
              cwe: attack,
            },
          ],
        },
      },
      notes: [attack],
      cases: [
        {
          mutation: {
            id: "case-1",
            path: attack,
            description: attack,
            kind: "custom-set",
            body: {},
          },
          response,
          classification: "WARN",
          reason: attack,
        },
      ],
    };
    const files = await writeReport(result, outputDirectory);
    const markdown = await readFile(files.reportPath, "utf8");
    const json = JSON.parse(await readFile(files.jsonReportPath, "utf8"));
    const html = await readFile(files.htmlReportPath, "utf8");
    const replay = await readFile(files.findingPaths[0] ?? "", "utf8");
    expect(markdown).not.toContain("![pixel](");
    expect(markdown).not.toContain("[link](");
    expect(markdown).not.toContain("`code`");
    expect(markdown).not.toContain("<img");
    expect(markdown).not.toContain("https://evil.test");
    expect(markdown).not.toContain("\n# forged");
    expect(markdown).toContain("&#96;code&#96;");
    expect(markdown).toContain("&#33;&#91;pixel&#93;");
    expect(markdown).not.toMatch(/\| Reason \| Fingerprint/);
    expect(markdown).toContain("unavailable (incomplete response)");
    expect(json.baseline.schemaFingerprint).toBeNull();
    expect(json.baseline.bodyTruncated).toBe(true);
    expect(json.cases[0].schemaFingerprint).toBeNull();
    expect(json.cases[0].bodyTruncated).toBe(true);
    expect(json.baseline.assessment.classification).toBe("WARN");
    expect(json.baseline.assessment.securitySignals[0].id).toBe("<REDACTED>");
    expect(json.mode).toBe("idor");
    expect(json.completedRequests).toBe(2);
    expect(json.plannedRequests).toBe(3);
    expect(html).toContain("Unavailable: response incomplete");
    expect(replay).toContain("curl -X GET");
    expect(replay).not.toContain("--data-raw");
    expect(
      [markdown, JSON.stringify(json), html, replay].join("\n"),
    ).not.toContain("PRIVATE_RESPONSE_CANARY");
    expect(
      [markdown, JSON.stringify(json), html, replay].join("\n"),
    ).not.toContain(CANARY);
  });
});
