import { describe, expect, it } from "vitest";
import { englishText } from "../src/i18n.js";
import {
  generateChecks,
  parseInlineCustomCase,
  requestForCase,
} from "../src/mutations.js";
import type { ParsedCurl } from "../src/types.js";

const request: ParsedCurl = {
  method: "POST",
  url: "https://api.example.test/users?access_token=secret-query-token",
  headers: {
    Authorization: "Bearer secret-header-token",
    Cookie: "session=secret-cookie",
    "Content-Type": "application/json",
  },
  body: {
    email: "qa@example.test",
    age: 30,
    active: true,
    profile: { name: "QA", score: 7 },
    tags: ["one", "two"],
    description: "A sufficiently rich test payload",
    retries: 3,
  },
};

describe("profile-driven checks", () => {
  it("generates more than 15 negative checks and spreads early cases across paths", () => {
    const generated = generateChecks(request, {
      profile: "negative",
      maxCases: 60,
    });

    expect(generated.cases).toHaveLength(60);
    expect(
      new Set(generated.cases.slice(0, 8).map((item) => item.path)).size,
    ).toBe(8);
    expect(generated.cases.some((item) => item.kind === "long-string")).toBe(
      true,
    );
    expect(generated.notes.map(englishText).join(" ")).toContain(
      "The limit stopped generation",
    );
  });

  it("adds bounded auth and injection probes for the security profile", () => {
    const generated = generateChecks(request, {
      profile: "security",
      maxCases: 60,
      expectAuth: true,
    });
    const missing = generated.cases.find(
      (item) => item.kind === "auth-missing",
    );
    const invalid = generated.cases.find(
      (item) => item.kind === "auth-invalid",
    );

    expect(missing?.expectation).toBe("auth-reject");
    expect(missing?.headers).not.toHaveProperty("Authorization");
    expect(missing?.headers).not.toHaveProperty("Cookie");
    expect(missing?.url).not.toContain("access_token");
    expect(invalid?.headers?.Authorization).toBe(
      "Bearer BREAKCURL_INVALID_CREDENTIAL",
    );
    expect(invalid?.headers?.Cookie).toBe("breakcurl_invalid=1");
    expect(generated.cases.some((item) => item.kind === "sql-probe")).toBe(
      true,
    );
    expect(generated.cases.some((item) => item.kind === "nosql-probe")).toBe(
      true,
    );
  });

  it("supports path filters and explicit custom set/remove cases", () => {
    const generated = generateChecks(request, {
      profile: "negative",
      maxCases: 20,
      onlyPaths: ["$.profile"],
      excludePaths: ["$.profile.score"],
      customCases: [
        {
          name: "Invalid email",
          path: "$.email",
          operation: "set",
          value: "qa@",
          expect: "reject",
        },
        {
          name: "Remove active",
          path: "$.active",
          operation: "remove",
          expect: "accept",
        },
      ],
    });

    expect(generated.cases[0]?.body.email).toBe("qa@");
    expect(generated.cases[1]?.body).not.toHaveProperty("active");
    const automaticPaths = generated.cases
      .filter(
        (item) =>
          item.source === "built-in" && item.path !== "$.__breakcurl_probe",
      )
      .map((item) => item.path);
    expect(automaticPaths.every((path) => path.startsWith("$.profile"))).toBe(
      true,
    );
    expect(automaticPaths).not.toContain("$.profile.score");
  });

  it("parses inline custom JSON and rejects unsafe paths", () => {
    expect(parseInlineCustomCase('$.email="broken"', 0)).toMatchObject({
      path: "$.email",
      value: "broken",
    });
    expect(() => parseInlineCustomCase("$.age=not-json", 0)).toThrow(
      "valid JSON",
    );
    expect(() =>
      generateChecks(request, {
        profile: "quick",
        maxCases: 10,
        customCases: [
          {
            name: "prototype pollution",
            path: "$.__proto__.polluted",
            operation: "set",
            value: true,
          },
        ],
      }),
    ).toThrow("Unsafe JSON path segment");
  });

  it("applies header and URL mutations only to the selected case request", () => {
    const authCase = generateChecks(request, {
      profile: "security",
      maxCases: 10,
    }).cases.find((item) => item.kind === "auth-missing");
    if (!authCase) throw new Error("auth-missing case was not generated");
    const mutated = requestForCase(request, authCase);

    expect(mutated.headers).not.toHaveProperty("Authorization");
    expect(request.headers.Authorization).toContain("secret-header-token");
    expect(mutated.body).toEqual(request.body);
    expect(mutated.body).not.toBe(request.body);
  });

  it("rejects limits above the hard safety boundary", () => {
    expect(() =>
      generateChecks(request, { profile: "full", maxCases: 201 }),
    ).toThrow("from 1 to 200");
  });
});
