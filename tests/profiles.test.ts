import { describe, expect, it } from "vitest";
import { parseAuthContract } from "../src/auth-contract.js";
import { classifyCase } from "../src/classify.js";
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

    expect(missing?.expectation).toBe("observe");
    expect(generated.notes.map(englishText).join(" ")).toContain(
      "--expect-auth alone does not establish complete auth coverage",
    );
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

  it("reserves default quick slots for auth and keeps body checks within 15", () => {
    const generated = generateChecks(request, {
      profile: "quick",
      maxCases: 15,
    });
    expect(generated.cases).toHaveLength(15);
    expect(generated.cases.slice(0, 2).map((item) => item.kind)).toEqual([
      "auth-missing",
      "auth-invalid",
    ]);
    expect(
      generated.cases
        .slice(2)
        .every((item) => item.category !== "authentication"),
    ).toBe(true);
    expect(generated.cases.slice(2).some((item) => item.path === "$.age")).toBe(
      true,
    );
  });

  it("keeps explicit custom checks and names auth coverage omitted by small budgets", () => {
    const single = generateChecks(request, { profile: "quick", maxCases: 1 });
    expect(single.cases.map((item) => item.kind)).toEqual(["auth-missing"]);
    expect(single.notes.map(englishText).join(" ")).toContain(
      "selected 1 of 2 probes; skipped by --max-cases: auth-invalid",
    );
    const custom = generateChecks(request, {
      profile: "quick",
      maxCases: 1,
      customCases: [
        { name: "age explicit", path: "$.age", operation: "set", value: 0 },
      ],
    });
    expect(custom.cases.map((item) => item.kind)).toEqual(["custom-set"]);
    expect(custom.notes.map(englishText).join(" ")).toContain(
      "selected 0 of 2 probes; skipped by --max-cases: auth-missing, auth-invalid",
    );
  });

  it("keeps no-contract auth successes as candidates even with expectAuth", () => {
    const auth = generateChecks(request, {
      profile: "quick",
      maxCases: 2,
      expectAuth: true,
    }).cases[0];
    if (!auth) throw new Error("Missing auth probe");
    expect(auth.expectation).toBe("observe");
    const result = classifyCase(auth, {
      status: 200,
      body: '{"created":true}',
      headers: { "content-type": "application/json" },
      latencyMs: 1,
      timedOut: false,
    });
    expect(result.classification).toBe("WARN");
  });

  it("applies strict expectations only with the complete source declaration", () => {
    const authContract = parseAuthContract({
      complete: true,
      sources: [
        { in: "header", name: "Authorization" },
        { in: "header", name: "Cookie" },
        { in: "query", name: "access_token" },
      ],
    });
    const full = generateChecks(request, {
      profile: "quick",
      maxCases: 2,
      expectAuth: true,
      authContract,
    });
    expect(full.cases.every((item) => item.expectation === "auth-reject")).toBe(
      true,
    );
    expect(full.notes.map(englishText).join(" ")).toContain(
      "the tool cannot verify that assumption",
    );
    const exploratory = generateChecks(request, {
      profile: "quick",
      maxCases: 2,
      authContract,
    });
    expect(
      exploratory.cases.every((item) => item.expectation === "observe"),
    ).toBe(true);
    const negative = generateChecks(request, {
      profile: "negative",
      maxCases: 10,
      authContract,
    });
    expect(
      negative.cases.some((item) => item.category === "authentication"),
    ).toBe(false);
  });

  it("skips partial probes while undeclared obvious body credentials remain", () => {
    const bodyAuth = {
      ...request,
      body: { ...request.body, access_token: "body-fixture-secret" },
    };
    const skipped = generateChecks(bodyAuth, {
      profile: "quick",
      maxCases: 15,
      expectAuth: true,
    });
    expect(
      skipped.cases.some((item) => item.category === "authentication"),
    ).toBe(false);
    expect(skipped.notes.map(englishText).join(" ")).toContain(
      "possible credentials remain in the JSON body",
    );
    const selected = generateChecks(bodyAuth, {
      profile: "quick",
      maxCases: 2,
      expectAuth: true,
      authBodyPaths: ["$.access_token"],
    });
    expect(selected.cases[0]?.body).not.toHaveProperty("access_token");
    expect(selected.cases.every((item) => item.expectation === "observe")).toBe(
      true,
    );
  });

  it("supports body-only convenience probes without promoting them to a complete contract", () => {
    const bodyAuth = {
      ...request,
      url: "https://api.example.test/items",
      headers: {},
      body: { ticket: "opaque-ticket", amount: 1 },
    };
    const selected = generateChecks(bodyAuth, {
      profile: "quick",
      maxCases: 2,
      expectAuth: true,
      authBodyPaths: ["$.ticket"],
    });
    expect(selected.cases[0]?.body).toEqual({ amount: 1 });
    expect(selected.cases[1]?.body.ticket).toBe("BREAKCURL_INVALID_CREDENTIAL");
    expect(selected.cases.every((item) => item.expectation === "observe")).toBe(
      true,
    );
  });
});
