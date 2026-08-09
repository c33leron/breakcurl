import { describe, expect, it } from "vitest";
import { generateMutations } from "../src/mutations.js";
import type { JsonObject } from "../src/types.js";

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
