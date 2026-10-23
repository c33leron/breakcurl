import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { englishText } from "../src/i18n.js";
import { generateChecks, requestForCase } from "../src/mutations.js";
import { sendRequest } from "../src/runner.js";
import type { CheckGenerationOptions, ParsedCurl } from "../src/types.js";

const header = Buffer.from(JSON.stringify({ alg: "HS256" })).toString(
  "base64url",
);
const payload = Buffer.from(
  JSON.stringify({ sub: "user", exp: 9999999999 }),
).toString("base64url");
const request: ParsedCurl = {
  method: "GET",
  url: "https://api.example.test/orders?access_token=query-fixture",
  headers: {
    Authorization: `Bearer ${header}.${payload}.signature-fixture`,
    Cookie: "session=cookie-fixture",
    "X-Ticket": "custom-fixture",
    "Content-Type": "application/json",
  },
  body: {},
};
const options: CheckGenerationOptions = {
  profile: "security",
  maxCases: 30,
  expectAuth: true,
};

describe("attack generation evidence boundaries", () => {
  it("keeps JWT probes observational when alternate declared credentials remain", () => {
    const original = structuredClone(request);
    const generated = generateChecks(request, {
      ...options,
      authContract: {
        complete: true,
        sources: [
          { in: "header", name: "Authorization" },
          { in: "header", name: "Cookie" },
          { in: "header", name: "X-Ticket" },
          { in: "query", name: "access_token" },
        ],
      },
    });
    const jwtCases = generated.cases.filter((item) =>
      item.kind.startsWith("jwt-"),
    );
    expect(jwtCases).toHaveLength(4);
    for (const item of jwtCases) {
      expect(item.expectation).toBe("observe");
      const replay = requestForCase(request, item);
      expect(replay.headers.Cookie).toBe(request.headers.Cookie);
      expect(replay.headers["X-Ticket"]).toBe(request.headers["X-Ticket"]);
      expect(replay.url).toBe(request.url);
    }
    expect(request).toEqual(original);
  });

  it("requires expectAuth and a sole Authorization source for strict JWT expectations", () => {
    const soleBearerRequest: ParsedCurl = {
      ...request,
      url: "https://api.example.test/orders",
      headers: { authorization: request.headers.Authorization ?? "" },
    };
    const authContract = {
      complete: true as const,
      sources: [{ in: "header" as const, name: "AUTHORIZATION" }],
    };
    for (const expectAuth of [true, false]) {
      const generated = generateChecks(soleBearerRequest, {
        ...options,
        expectAuth,
        authContract,
      });
      const jwtCases = generated.cases.filter((item) =>
        item.kind.startsWith("jwt-"),
      );
      expect(jwtCases).toHaveLength(4);
      expect(jwtCases.map((item) => item.expectation)).toEqual(
        Array(4).fill(expectAuth ? "auth-reject" : "observe"),
      );
      expect(generated.notes.map(englishText).join(" ")).toContain(
        "does not independently test expiry enforcement",
      );
    }
    const withoutContract = generateChecks(soleBearerRequest, options);
    expect(
      withoutContract.cases
        .filter((item) => item.kind.startsWith("jwt-"))
        .every((item) => item.expectation === "observe"),
    ).toBe(true);
  });

  it("rebuilds discovery headers without custom credentials or URL credentials", () => {
    const baseline: ParsedCurl = {
      ...request,
      url: "https://fixture-user:fixture-pass@api.example.test/orders?ticket=fixture-query#fragment",
    };
    const original = structuredClone(baseline);
    const generated = generateChecks(baseline, options);
    const discovery = generated.cases.filter(
      (item) => item.kind === "spec-probe",
    );
    expect(discovery).toHaveLength(4);
    for (const item of discovery) {
      const replay = requestForCase(baseline, item);
      expect(replay.headers).toEqual({ Accept: "application/json" });
      const url = new URL(replay.url);
      expect(url.origin).toBe("https://api.example.test");
      expect(url.username).toBe("");
      expect(url.password).toBe("");
      expect(url.search).toBe("");
      expect(url.hash).toBe("");
      expect(replay.method).toBe("GET");
      expect(replay.body).toEqual({});
    }
    expect(baseline).toEqual(original);
  });

  it("does not label a bodyless discovery-only run as having no checks", () => {
    const generated = generateChecks(
      { ...request, headers: {}, url: "https://api.example.test/orders" },
      { ...options, expectAuth: false },
    );
    expect(generated.cases).toHaveLength(4);
    expect(generated.notes.map(englishText).join(" ")).not.toContain(
      "No checks were generated",
    );
  });

  it("cannot use a custom baseline credential to discover a protected spec", async () => {
    const receivedTickets: Array<string | undefined> = [];
    const server = createServer((incoming, response) => {
      const ticket = incoming.headers["x-ticket"];
      receivedTickets.push(typeof ticket === "string" ? ticket : undefined);
      response.setHeader("Content-Type", "application/json");
      response.statusCode = ticket === "custom-fixture" ? 200 : 401;
      response.end('{"openapi":"3.1.0"}');
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("missing local fixture address");
      }
      const baseline = {
        ...request,
        url: `http://127.0.0.1:${address.port}/orders`,
      };
      expect((await sendRequest(baseline, 1000)).status).toBe(200);
      const discovery = generateChecks(baseline, options).cases.find(
        (item) => item.id === "spec-probe:/openapi.json",
      );
      if (!discovery) throw new Error("missing discovery probe");
      const result = await sendRequest(
        requestForCase(baseline, discovery),
        1000,
      );
      expect(result.status).toBe(401);
      expect(receivedTickets).toEqual(["custom-fixture", undefined]);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});
