import { describe, expect, it } from "vitest";
import { localized } from "../src/i18n.js";
import { formatJunitXml } from "../src/junit.js";
import { formatSarif } from "../src/sarif.js";
import type { RunResult } from "../src/types.js";

const CANARY = "CANARY_SUPER_SECRET_123";

function buildResult(): RunResult {
  return {
    profile: "security",
    baseline: {
      request: {
        method: "POST",
        url: `https://api.example.test/users?token=${CANARY}`,
        headers: { Authorization: `Bearer ${CANARY}` },
        body: { email: "qa@example.test", age: 30 },
      },
      response: {
        status: 201,
        latencyMs: 10,
        headers: {},
        body: "",
        timedOut: false,
      },
    },
    cases: [
      {
        mutation: {
          id: "null:$.age",
          path: "$.age",
          description: localized("$.age = null", "$.age = null"),
          kind: "null",
          body: { email: "qa@example.test", age: null },
          category: "structure",
        },
        response: {
          status: 500,
          latencyMs: 20,
          headers: {},
          body: "",
          timedOut: false,
        },
        classification: "FAIL",
        reason: localized("The API returned HTTP 500.", "API вернул HTTP 500."),
        severity: "HIGH",
        confidence: "HIGH",
      },
      {
        mutation: {
          id: "wrong-type:$.age",
          path: "$.age",
          description: localized(
            '$.age = "not-a-number"',
            '$.age = "not-a-number"',
          ),
          kind: "wrong-type",
          body: { email: "qa@example.test", age: "not-a-number" },
          category: "structure",
        },
        response: {
          status: 200,
          latencyMs: 30,
          headers: {},
          body: "",
          timedOut: false,
        },
        classification: "WARN",
        reason: localized(
          "The API accepted a value that was expected to be rejected with HTTP 200.",
          "API принял значение, которое ожидалось отклонить, с HTTP 200.",
        ),
        severity: "MEDIUM",
        confidence: "MEDIUM",
      },
      {
        mutation: {
          id: "remove:$.email",
          path: "$.email",
          description: localized(
            "field $.email removed",
            "поле $.email удалено",
          ),
          kind: "remove",
          body: { age: 30 },
          category: "structure",
        },
        response: {
          status: 422,
          latencyMs: 40,
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
      {
        mutation: {
          id: "auth-missing:credentials",
          path: "$auth",
          description: localized(
            "all credentials removed",
            "все credentials удалены",
          ),
          kind: "auth-missing",
          body: { email: "qa@example.test", age: 30 },
          category: "authentication",
        },
        response: {
          status: 200,
          latencyMs: 50,
          headers: {},
          body: "",
          timedOut: false,
        },
        classification: "FAIL",
        reason: localized(
          "The auth probe returned HTTP 200.",
          "Auth-probe получил HTTP 200.",
        ),
        severity: "HIGH",
        confidence: "HIGH",
        securitySignals: [
          {
            id: "authentication-not-enforced",
            title: localized(
              "Successful response without valid credentials",
              "Успешный ответ без корректных credentials",
            ),
            severity: "HIGH",
            cwe: "CWE-306",
          },
        ],
      },
    ],
  };
}

describe("formatJunitXml", () => {
  it("maps FAIL to failure, ERROR to error, WARN to skipped, PASS to a clean testcase", () => {
    const result = buildResult();
    const xml = formatJunitXml(result, []);

    expect(xml).toContain(
      '<testsuites name="breakcurl" tests="4" failures="2" errors="0" skipped="1"',
    );
    expect(xml).toContain("<failure ");
    expect(xml).toContain("<skipped ");
    expect(xml).not.toContain("<error ");
    expect(xml).toContain("</failure>");
    expect(xml).toContain("[structure] $.age = null");
    expect(xml).toContain("WARN: The API accepted a value");
  });

  it("keeps secrets out of names, classnames, and messages", () => {
    const xml = formatJunitXml(buildResult(), []);

    expect(xml).not.toContain(CANARY);
    expect(xml).toContain("%3CREDACTED%3E");
  });

  it("escapes XML-significant characters", () => {
    const result = buildResult();
    result.cases = [
      {
        mutation: {
          id: 'custom-1:quote-"test"',
          path: '$.field["<tag>"]',
          description: localized(
            'value with <tag> & "quotes"',
            'value with <tag> & "quotes"',
          ),
          kind: "custom-set",
          body: {},
          category: "custom",
        },
        response: {
          status: 500,
          latencyMs: 5,
          headers: {},
          body: "",
          timedOut: false,
        },
        classification: "FAIL",
        reason: localized("Reason with <tag>.", "Reason with <tag>."),
      },
    ];
    const xml = formatJunitXml(result, []);

    expect(xml).toContain("&lt;tag&gt;");
    expect(xml).toContain("&quot;quotes&quot;");
    expect(xml).toContain("&amp;");
  });
});

describe("formatSarif", () => {
  it("produces SARIF 2.1.0 with only FAIL, WARN, and ERROR cases", () => {
    const sarif = JSON.parse(formatSarif(buildResult(), [])) as {
      version: string;
      runs: {
        tool: { driver: { name: string; rules: { id: string }[] } };
        results: {
          ruleId: string;
          level: string;
          properties: Record<string, unknown>;
        }[];
      }[];
    };

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.tool.driver.name).toBe("BreakCurl");
    expect(sarif.runs[0]?.results).toHaveLength(3);
    const levels = sarif.runs[0]?.results.map((result) => result.level);
    expect(levels).toEqual(["error", "warning", "error"]);
    const ruleIds = sarif.runs[0]?.tool.driver.rules.map((rule) => rule.id);
    expect(ruleIds).toContain("authentication-not-enforced");
    expect(ruleIds).toContain("structure-finding");
  });

  it("redacts secrets and points locations at the sanitized target", () => {
    const sarif = formatSarif(buildResult(), []);
    const parsed = JSON.parse(sarif) as {
      runs: [
        {
          results: {
            locations: [
              { physicalLocation: { artifactLocation: { uri: string } } },
            ];
          }[];
        },
      ];
    };

    expect(sarif).not.toContain(CANARY);
    expect(sarif).toContain("%3CREDACTED%3E");
    const uris = parsed.runs[0]?.results.map(
      (result) => result.locations[0]?.physicalLocation.artifactLocation.uri,
    );
    expect(
      uris?.every((uri) => uri.startsWith("https://api.example.test/users")),
    ).toBe(true);
    expect(uris?.every((uri) => !uri.includes(CANARY))).toBe(true);
  });

  it("maps security signals to rules with CWE links", () => {
    const sarif = JSON.parse(formatSarif(buildResult(), [])) as {
      runs: [
        { tool: { driver: { rules: { id: string; helpUri?: string }[] } } },
      ];
    };
    const rule = sarif.runs[0]?.tool.driver.rules.find(
      (item) => item.id === "authentication-not-enforced",
    );
    expect(rule?.helpUri).toBe(
      "https://cwe.mitre.org/data/definitions/306.html",
    );
  });
});
