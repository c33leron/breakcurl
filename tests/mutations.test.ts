import { describe, expect, it } from "vitest";
import {
  generateChecks,
  generateMutations,
  requestForCase,
} from "../src/mutations.js";
import type { CheckProfile, JsonObject, ParsedCurl } from "../src/types.js";

describe("generateMutations", () => {
  const body: JsonObject = {
    email: "qa@example.com",
    age: 30,
    active: true,
    profile: { displayName: "QA", score: 5 },
    tags: ["smoke"],
    password: "do-not-touch",
    accessToken: "also-do-not-touch",
  };

  it("creates all five mutation kinds without changing the source body", () => {
    const cases = generateMutations(body, 100);

    expect(cases.map((item) => item.kind)).toContain("remove");
    expect(cases.map((item) => item.kind)).toContain("null");
    expect(cases.map((item) => item.kind)).toContain("wrong-type");
    expect(cases.map((item) => item.kind)).toContain("empty");
    expect(cases.map((item) => item.kind)).toContain("numeric-boundary");
    expect(body).toEqual({
      email: "qa@example.com",
      age: 30,
      active: true,
      profile: { displayName: "QA", score: 5 },
      tags: ["smoke"],
      password: "do-not-touch",
      accessToken: "also-do-not-touch",
    });
  });

  it("uses nested JSON paths and changes only the selected field", () => {
    const mutation = generateMutations(body, 100).find(
      (item) => item.path === "$.profile.score" && item.kind === "wrong-type",
    );

    expect(mutation?.body).toEqual({
      email: "qa@example.com",
      age: 30,
      active: true,
      profile: { displayName: "QA", score: "not-a-number" },
      tags: ["smoke"],
      password: "do-not-touch",
      accessToken: "also-do-not-touch",
    });
  });

  it("has deterministic order, observes maxCases, and skips secret-like fields", () => {
    expect(
      generateMutations(body, 4).map((item) => `${item.kind}:${item.path}`),
    ).toEqual([
      "remove:$.email",
      "remove:$.age",
      "remove:$.active",
      "remove:$.profile",
    ]);
    expect(
      generateMutations(body, 100).some((item) =>
        /password|accessToken/.test(item.path),
      ),
    ).toBe(false);
  });

  it("uses -1 when zero would not change a numeric field", () => {
    const cases = generateMutations({ retries: 0 }, 100);
    expect(
      cases.find((item) => item.kind === "numeric-boundary")?.body,
    ).toEqual({ retries: -1 });
  });

  it("uses the specified replacement for every supported JSON type", () => {
    const cases = generateMutations(
      {
        text: "value",
        count: 2,
        enabled: true,
        list: ["item"],
        object: { value: "nested" },
      },
      100,
    );
    const replacement = (path: string, kind: string) =>
      cases.find((item) => item.path === path && item.kind === kind)?.body;

    expect(replacement("$.text", "wrong-type")).toMatchObject({ text: 123 });
    expect(replacement("$.count", "wrong-type")).toMatchObject({
      count: "not-a-number",
    });
    expect(replacement("$.enabled", "wrong-type")).toMatchObject({
      enabled: "true",
    });
    expect(replacement("$.list", "wrong-type")).toMatchObject({ list: {} });
    expect(replacement("$.object", "wrong-type")).toMatchObject({ object: [] });
    expect(replacement("$.text", "empty")).toMatchObject({ text: "" });
    expect(replacement("$.list", "empty")).toMatchObject({ list: [] });
    expect(replacement("$.object", "empty")).toMatchObject({ object: {} });
    expect(replacement("$.count", "numeric-boundary")).toMatchObject({
      count: 0,
    });
  });
});

describe("automatic mutations change their selected field", () => {
  const profiles: CheckProfile[] = ["quick", "negative", "security", "full"];

  function request(body: JsonObject): ParsedCurl {
    return {
      method: "POST",
      url: "https://api.example.test/items",
      headers: { "Content-Type": "application/json" },
      body,
    };
  }

  it.each(profiles)(
    "skips already-empty strings, arrays and objects in the %s profile while keeping removal",
    (profile) => {
      const body = { text: "", list: [], object: {}, nullable: null };
      const { cases } = generateChecks(request(body), {
        profile,
        maxCases: 200,
      });

      expect(cases.some((item) => item.kind === "empty")).toBe(false);
      for (const path of ["$.text", "$.list", "$.object", "$.nullable"]) {
        expect(
          cases.some((item) => item.kind === "remove" && item.path === path),
        ).toBe(true);
      }
      for (const item of cases.filter((item) => item.category !== "protocol")) {
        expect(item.body, item.id).not.toEqual(body);
      }
    },
  );

  it.each(profiles)(
    "skips matching boundary and injection values in the %s profile",
    (profile) => {
      const body = {
        whitespace: "   ",
        long: "A".repeat(1024),
        unicode: "BREAKCURL_тест_🚀_\u200B",
        maximumSafe: Number.MAX_SAFE_INTEGER,
        maximum: Number.MAX_VALUE,
        sql: "'BREAKCURL_PROBE",
        path: "../../BREAKCURL_NON_EXISTENT",
        markup: "<breakcurl-probe>",
        template: "$" + "{BREAKCURL_PROBE}",
        newline: "BREAKCURL\r\nPROBE",
      };
      const { cases } = generateChecks(request(body), {
        profile,
        maxCases: 200,
      });

      for (const item of cases.filter((item) => item.category !== "protocol")) {
        expect(item.body, item.id).not.toEqual(body);
      }
      for (const unchangedId of [
        "whitespace:$.whitespace",
        "long-string:$.long",
        "unicode:$.unicode",
        "large-number:$.maximumSafe",
        "fractional-number:$.maximum",
        "sql-probe:$.sql",
        "path-probe:$.path",
        "markup-probe:$.markup",
        "template-probe:$.template",
        "newline-probe:$.newline",
      ]) {
        expect(cases.map((item) => item.id)).not.toContain(unchangedId);
      }
    },
  );

  it("fills the budget with later useful cases instead of unchanged templates", () => {
    const body = { empty: "", name: "QA" };
    const { cases } = generateChecks(request(body), {
      profile: "quick",
      maxCases: 7,
    });

    expect(cases).toHaveLength(7);
    expect(cases.at(-1)).toMatchObject({
      id: "empty:$.name",
      body: { empty: "", name: "" },
    });
    expect(
      cases.every((item) => JSON.stringify(item.body) !== JSON.stringify(body)),
    ).toBe(true);
  });

  it("keeps an explicitly requested same-value custom case within its reserved budget", () => {
    const body = { list: [] };
    const { cases } = generateChecks(request(body), {
      profile: "full",
      maxCases: 1,
      customCases: [
        {
          name: "Explicit empty list",
          path: "$.list",
          operation: "set",
          value: [],
        },
      ],
    });

    expect(cases).toHaveLength(1);
    expect(cases[0]).toMatchObject({
      kind: "custom-set",
      source: "custom",
      body,
    });
  });

  it("keeps auth and protocol cases whose unchanged body accompanies changed headers", () => {
    const baseline = request({ text: "" });
    baseline.headers.Authorization = "Bearer synthetic-controlled-auth";
    const { cases } = generateChecks(baseline, {
      profile: "full",
      maxCases: 200,
    });
    const headerCases = cases.filter(
      (item) =>
        item.category === "authentication" || item.category === "protocol",
    );

    expect(headerCases.map((item) => item.kind)).toEqual([
      "auth-missing",
      "auth-invalid",
      "content-type-missing",
    ]);
    for (const item of headerCases) {
      expect(item.body).toEqual(baseline.body);
      expect(item.headers).not.toEqual(baseline.headers);
    }
  });

  it.each(["security", "full"] as const)(
    "does not repeat the complete baseline when Content-Type is already absent in %s",
    (profile) => {
      const baseline = { ...request({ text: "" }), headers: {} };
      const { cases } = generateChecks(baseline, { profile, maxCases: 200 });

      expect(
        cases.map((item) => requestForCase(baseline, item)),
      ).not.toContainEqual(baseline);
      expect(cases.some((item) => item.kind === "content-type-missing")).toBe(
        false,
      );
    },
  );

  it.each([
    ["security", "Content-Type"],
    ["security", "content-type"],
    ["security", "CONTENT-TYPE"],
    ["full", "Content-Type"],
    ["full", "content-type"],
    ["full", "CONTENT-TYPE"],
  ] as const)(
    "keeps %s header removal for %s regardless of casing",
    (profile, header) => {
      const baseline = {
        ...request({ text: "" }),
        headers: { [header]: "application/json", "X-Probe": "keep" },
      };
      const mutation = generateChecks(baseline, {
        profile,
        maxCases: 200,
      }).cases.find((item) => item.kind === "content-type-missing");
      expect(mutation).toBeDefined();
      if (!mutation) throw new Error("Content-Type removal was not generated");
      const changed = requestForCase(baseline, mutation);
      expect(changed).not.toEqual(baseline);
      expect(changed.body).toEqual(baseline.body);
      expect(changed.headers).toEqual({ "X-Probe": "keep" });
    },
  );
});
