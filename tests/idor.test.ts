import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { responseSchemaFingerprint } from "../src/classify.js";
import {
  executeIdorPlan,
  type IdorConfig,
  parseIdorConfig,
  prepareIdorPlan,
} from "../src/idor.js";
import { requestForCase } from "../src/mutations.js";
import { writeReport } from "../src/report.js";
import type { CaseResult, ParsedCurl } from "../src/types.js";

const TOKEN_A = "fixture-credential-A-7cf90325";
const TOKEN_B = "fixture-credential-B-e489b326";
const MARKER_A = "aX7tQ9mK2jL5nV8r";
const MARKER_B = "bS8uR2pW6yD4fH9z";
const servers: Server[] = [];

interface Scenario {
  cross?:
    | "protected"
    | "vulnerable"
    | "403-leak"
    | "404-leak"
    | "empty-200"
    | "envelope"
    | "wrong-marker"
    | "marker-only"
    | "misplaced-marker"
    | "truncated"
    | "401"
    | "500"
    | "500-leak";
  identity?: "same-principal" | "expired-a" | "expired-b" | "wrong-a";
  own?: "wrong-a" | "wrong-b";
  rateLimitAt?: number;
  redirectAt?: number;
}

async function fixture(scenario: Scenario = {}) {
  const requests: {
    path: string;
    token: string;
    method: string;
    body: string;
  }[] = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    requests.push({
      path: request.url ?? "",
      token: request.headers.authorization ?? "",
      method: request.method ?? "",
      body,
    });
    const stage = requests.length;
    response.setHeader("Content-Type", "application/json");
    // Deliberately hostile echoed values must never survive in result metadata.
    response.setHeader("X-Fixture-Echo", `${TOKEN_A}-${MARKER_B}`);
    if (stage === scenario.rateLimitAt) {
      response.writeHead(429);
      response.end(JSON.stringify({ error: "rate limited" }));
      return;
    }
    if (stage === scenario.redirectAt) {
      response.writeHead(302, { Location: "/unexpected-redirect" });
      response.end("{}");
      return;
    }
    const actor =
      request.headers.authorization === `Bearer ${TOKEN_A}`
        ? "actor-a"
        : "actor-b";
    if (request.url === "/me") {
      if (
        (scenario.identity === "expired-a" && actor === "actor-a") ||
        (scenario.identity === "expired-b" && actor === "actor-b")
      ) {
        response.writeHead(401);
        response.end(JSON.stringify({ error: "expired" }));
        return;
      }
      response.end(
        JSON.stringify({
          id:
            scenario.identity === "same-principal"
              ? "actor-a"
              : scenario.identity === "wrong-a" && actor === "actor-a"
                ? "actor-c"
                : actor,
        }),
      );
      return;
    }
    const id = request.url?.split("/").at(-1);
    const object = {
      id,
      privateMarker: id === "object-a" ? MARKER_A : MARKER_B,
    };
    if (stage === 3 || stage === 4) {
      if (
        (scenario.own === "wrong-a" && stage === 3) ||
        (scenario.own === "wrong-b" && stage === 4)
      )
        object.privateMarker = "wrong-independent-marker";
      response.end(JSON.stringify(object));
      return;
    }
    switch (scenario.cross) {
      case "vulnerable":
        response.end(JSON.stringify(object));
        return;
      case "403-leak":
        response.writeHead(403);
        response.end(JSON.stringify(object));
        return;
      case "404-leak":
        response.writeHead(404);
        response.end(JSON.stringify(object));
        return;
      case "empty-200":
        response.end("{}");
        return;
      case "envelope":
        response.end(JSON.stringify({ error: "forbidden" }));
        return;
      case "wrong-marker":
        response.end(JSON.stringify({ ...object, privateMarker: MARKER_A }));
        return;
      case "marker-only":
        response.end(JSON.stringify({ privateMarker: MARKER_B }));
        return;
      case "misplaced-marker":
        response.writeHead(403);
        response.end(JSON.stringify({ error: MARKER_B }));
        return;
      case "truncated":
        response.end(
          JSON.stringify({ ...object, padding: "x".repeat(20_000) }),
        );
        return;
      case "401":
        response.writeHead(401);
        response.end("{}");
        return;
      case "500":
        response.writeHead(500);
        response.end("{}");
        return;
      case "500-leak":
        response.writeHead(500);
        response.end(JSON.stringify(object));
        return;
      default:
        response.writeHead(403);
        response.end(JSON.stringify({ error: "denied" }));
    }
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Fixture server unavailable.");
  const origin = `http://127.0.0.1:${address.port}`;
  const config: IdorConfig = {
    authModel: "bearer-only",
    objectIdsGrantAccess: false,
    rule: "a-cannot-read-b",
    privateCanaries: true,
    identity: {
      url: `${origin}/me`,
      principalPointer: "/id",
      actorA: "actor-a",
      actorB: "actor-b",
    },
    objects: {
      pathTemplate: "/objects/{objectId}",
      idPointer: "/id",
      canaryPointer: "/privateMarker",
      objectA: { id: "object-a", canary: MARKER_A },
      objectB: { id: "object-b", canary: MARKER_B },
    },
  };
  const a: ParsedCurl = {
    method: "GET",
    url: `${origin}/objects/object-a`,
    headers: { Authorization: `Bearer ${TOKEN_A}` },
    body: {},
  };
  const b: ParsedCurl = {
    method: "GET",
    url: `${origin}/objects/object-b`,
    headers: { Authorization: `Bearer ${TOKEN_B}` },
    body: {},
  };
  return {
    requests,
    origin,
    config,
    a,
    b,
    plan: () => prepareIdorPlan(a, b, config),
  };
}

afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

describe("bounded IDOR fixture execution", () => {
  it("proves a protected pair with exactly five sequential GETs and accurate replay requests", async () => {
    const context = await fixture();
    const plan = context.plan();
    expect(context.requests).toHaveLength(0);
    const seen: [string, number][] = [];
    const result = await executeIdorPlan(plan, {
      timeoutMs: 1_000,
      onResult: (item, index) => seen.push([item.classification, index]),
    });
    expect(result).toMatchObject({
      mode: "idor",
      plannedRequests: 5,
      completedRequests: 5,
    });
    expect(result.baseline.assessment?.classification).toBe("PASS");
    expect(result.cases.map((item) => item.classification)).toEqual([
      "PASS",
      "PASS",
      "PASS",
      "PASS",
    ]);
    expect(seen).toEqual([
      ["PASS", 0],
      ["PASS", 1],
      ["PASS", 2],
      ["PASS", 3],
      ["PASS", 4],
    ]);
    expect(context.requests.map(({ path, token }) => [path, token])).toEqual([
      ["/me", `Bearer ${TOKEN_A}`],
      ["/me", `Bearer ${TOKEN_B}`],
      ["/objects/object-a", `Bearer ${TOKEN_A}`],
      ["/objects/object-b", `Bearer ${TOKEN_B}`],
      ["/objects/object-b", `Bearer ${TOKEN_A}`],
    ]);
    expect(
      context.requests.every(
        ({ method, body }) => method === "GET" && body === "",
      ),
    ).toBe(true);
    result.cases.forEach((item, index) => {
      const request = requestForCase(result.baseline.request, item.mutation);
      expect(request.url).toBe(plan.requests[index + 1]?.request.url);
      expect(request.headers.Authorization).toBe(
        plan.requests[index + 1]?.request.headers.Authorization,
      );
    });
  });

  it.each(["vulnerable", "403-leak", "404-leak", "500-leak"] as const)(
    "proves private object disclosure for %s",
    async (cross) => {
      const context = await fixture({ cross });
      const result = await executeIdorPlan(context.plan(), {
        timeoutMs: 1_000,
      });
      const last = result.cases.at(-1);
      expect(last).toMatchObject({
        classification: "FAIL",
        severity: "HIGH",
        confidence: "HIGH",
      });
      expect(JSON.stringify(last?.reason)).toContain(
        "objectIdMatch=true; privateCanaryMatch=true",
      );
      expect(last?.securitySignals?.[0]?.cwe).toBe("CWE-639");
    },
  );

  it.each([
    "empty-200",
    "envelope",
    "wrong-marker",
    "marker-only",
    "misplaced-marker",
    "truncated",
    "401",
    "500",
  ] as const)(
    "leaves %s inconclusive instead of claiming IDOR",
    async (cross) => {
      const context = await fixture({ cross });
      const result = await executeIdorPlan(context.plan(), {
        timeoutMs: 1_000,
      });
      expect(result.cases.at(-1)?.classification).toBe("ERROR");
      expect(result.cases.at(-1)?.securitySignals).toBeUndefined();
      expect(context.requests).toHaveLength(5);
    },
  );

  it.each([
    ["same-principal", 2],
    ["expired-a", 1],
    ["expired-b", 2],
    ["wrong-a", 1],
  ] as const)(
    "stops invalid identity control %s at request %i",
    async (identity, count) => {
      const context = await fixture({ identity });
      const result = await executeIdorPlan(context.plan(), {
        timeoutMs: 1_000,
      });
      expect(context.requests).toHaveLength(count);
      expect(result.completedRequests).toBe(count);
      expect(result.cases).toHaveLength(count - 1);
      expect(
        (result.cases.at(-1) ?? result.baseline.assessment)?.classification,
      ).toBe("ERROR");
    },
  );

  it.each([
    ["wrong-a", 3],
    ["wrong-b", 4],
  ] as const)(
    "stops wrong private fixture %s before the cross request",
    async (own, count) => {
      const context = await fixture({ own });
      const result = await executeIdorPlan(context.plan(), {
        timeoutMs: 1_000,
      });
      expect(context.requests).toHaveLength(count);
      expect(result.cases.at(-1)?.classification).toBe("ERROR");
    },
  );

  it.each([1, 2, 3, 4, 5])(
    "stops immediately without retries on 429 at stage %i",
    async (rateLimitAt) => {
      const context = await fixture({ rateLimitAt });
      const result = await executeIdorPlan(context.plan(), {
        timeoutMs: 1_000,
      });
      expect(context.requests).toHaveLength(rateLimitAt);
      expect(result.completedRequests).toBe(rateLimitAt);
      expect(
        (result.cases.at(-1) ?? result.baseline.assessment)?.classification,
      ).toBe("ERROR");
      expect(JSON.stringify(result.notes)).toContain("HTTP 429");
    },
  );

  it.each([1, 5])("never follows redirects at stage %i", async (redirectAt) => {
    const context = await fixture({ redirectAt });
    const result = await executeIdorPlan(context.plan(), { timeoutMs: 1_000 });
    expect(context.requests).toHaveLength(redirectAt);
    expect(
      context.requests.some(({ path }) => path === "/unexpected-redirect"),
    ).toBe(false);
    expect(
      (result.cases.at(-1) ?? result.baseline.assessment)?.classification,
    ).toBe("ERROR");
  });

  it("discards response bodies, headers and compared values from findings and every report format", async () => {
    const context = await fixture({ cross: "403-leak" });
    const plan = context.plan();
    const callbacks: CaseResult[] = [];
    const result = await executeIdorPlan(plan, {
      timeoutMs: 1_000,
      onResult: (item) => callbacks.push(item),
    });
    for (const item of callbacks) {
      expect(item.response.body).toBe("");
      expect(item.response.headers).toEqual({});
      expect(item.response.bodyOmitted).toBe(true);
      expect(responseSchemaFingerprint(item.response)).toBeNull();
      const metadata = JSON.stringify({
        reason: item.reason,
        description: item.mutation.description,
        notes: result.notes,
        assessment: result.baseline.assessment,
      });
      for (const secret of [
        TOKEN_A,
        TOKEN_B,
        MARKER_A,
        MARKER_B,
        "actor-a",
        "actor-b",
        "object-a",
        "object-b",
      ])
        expect(metadata).not.toContain(secret);
    }
    const directory = await mkdtemp(join(tmpdir(), "breakcurl-idor-"));
    try {
      await writeReport(result, directory, {
        knownSecrets: plan.knownSecrets,
        junitPath: join(directory, "junit.xml"),
        sarifPath: join(directory, "report.sarif"),
      });
      for (const entry of await readdir(directory, {
        recursive: true,
        withFileTypes: true,
      })) {
        if (!entry.isFile()) continue;
        const content = await readFile(
          join(entry.parentPath, entry.name),
          "utf8",
        );
        for (const secret of [TOKEN_A, TOKEN_B, MARKER_A, MARKER_B])
          expect(content).not.toContain(secret);
      }
      const json = JSON.parse(
        await readFile(join(directory, "report.json"), "utf8"),
      );
      expect(json.completedRequests).toBe(5);
      expect(json.cases.at(-1).classification).toBe("FAIL");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("IDOR preflight never sends traffic", () => {
  type Inputs = Awaited<ReturnType<typeof fixture>>;
  const invalid: [string, (input: Inputs) => void][] = [
    [
      "query capability",
      ({ b }) => {
        b.url += "?download=opaque-test-capability";
      },
    ],
    [
      "empty query",
      ({ b }) => {
        b.url += "?";
      },
    ],
    [
      "fragment",
      ({ a }) => {
        a.url += "#fragment";
      },
    ],
    [
      "userinfo",
      ({ b }) => {
        b.url = b.url.replace("http://", "http://user:pass@");
      },
    ],
    [
      "different origin",
      ({ b }) => {
        b.url = b.url.replace("127.0.0.1", "localhost");
      },
    ],
    [
      "identity query",
      ({ config }) => {
        config.identity.url += "?";
      },
    ],
    [
      "identity origin",
      ({ config }) => {
        config.identity.url = config.identity.url.replace(
          "127.0.0.1",
          "localhost",
        );
      },
    ],
    [
      "extra header",
      ({ a }) => {
        a.headers["X-Tenant"] = "other";
      },
    ],
    [
      "cookie",
      ({ a }) => {
        a.headers.Cookie = "session=opaque";
      },
    ],
    [
      "duplicate case header",
      ({ a }) => {
        a.headers.authorization = `Bearer ${TOKEN_A}`;
      },
    ],
    [
      "wrong Accept",
      ({ a, b }) => {
        a.headers.Accept = "*/*";
        b.headers.Accept = "*/*";
      },
    ],
    [
      "different Accept",
      ({ a }) => {
        a.headers.Accept = "application/json";
      },
    ],
    [
      "same token",
      ({ a, b }) => {
        b.headers.Authorization = a.headers.Authorization ?? "";
      },
    ],
    [
      "missing token",
      ({ a }) => {
        delete a.headers.Authorization;
      },
    ],
    [
      "non-GET",
      ({ a }) => {
        a.method = "POST";
      },
    ],
    [
      "GET body",
      ({ a }) => {
        a.body = { value: "body" };
      },
    ],
    [
      "different URL pattern",
      ({ b }) => {
        b.url = b.url.replace("/objects/", "/other/");
      },
    ],
    [
      "incorrect expected object",
      ({ config }) => {
        config.objects.objectB.id = "object-c";
      },
    ],
    [
      "same expected identity",
      ({ config }) => {
        config.identity.actorB = config.identity.actorA;
      },
    ],
    [
      "same canaries",
      ({ config }) => {
        config.objects.objectB.canary = config.objects.objectA.canary;
      },
    ],
    [
      "short marker",
      ({ config }) => {
        config.objects.objectB.canary = "short";
      },
    ],
    [
      "marker derived from ID",
      ({ config }) => {
        config.objects.objectB.id = "object-with-long-id";
        config.objects.objectB.canary = "object-with-long-id";
      },
    ],
    [
      "two ID placeholders",
      ({ config }) => {
        config.objects.pathTemplate = "/{objectId}/{objectId}";
      },
    ],
    [
      "partial ID placeholder",
      ({ config }) => {
        config.objects.pathTemplate = "/objects/prefix-{objectId}";
      },
    ],
    [
      "invalid JSON pointer",
      ({ config }) => {
        config.objects.canaryPointer = "$.privateMarker";
      },
    ],
    [
      "same ID and marker pointer",
      ({ config }) => {
        config.objects.canaryPointer = config.objects.idPointer;
      },
    ],
  ];
  it.each(invalid)("rejects %s before any request", async (_name, change) => {
    const context = await fixture();
    change(context);
    expect(() => context.plan()).toThrow();
    expect(context.requests).toHaveLength(0);
  });

  it.each(["authModel", "objectIdsGrantAccess", "rule", "privateCanaries"])(
    "requires explicit fixture declaration %s",
    async (key) => {
      const context = await fixture();
      const value = { ...context.config } as Record<string, unknown>;
      delete value[key];
      expect(() => parseIdorConfig(value)).toThrow();
      expect(context.requests).toHaveLength(0);
    },
  );

  it.each([
    ["plain", (value: string) => value],
    [
      "percent",
      (value: string) =>
        [...value]
          .map((character) => `%${character.charCodeAt(0).toString(16)}`)
          .join(""),
    ],
    ["base64", (value: string) => Buffer.from(value).toString("base64")],
    ["base64url", (value: string) => Buffer.from(value).toString("base64url")],
    [
      "nested base64url",
      (value: string) =>
        Buffer.from(JSON.stringify({ marker: value })).toString("base64url"),
    ],
  ] as const)(
    "rejects reflected %s canary in prepared URLs",
    async (_name, encode) => {
      const context = await fixture();
      const encoded = encode(MARKER_B);
      context.config.objects.pathTemplate = `/preview/${encoded}/{objectId}`;
      context.a.url = `${context.origin}/preview/${encoded}/object-a`;
      context.b.url = `${context.origin}/preview/${encoded}/object-b`;
      expect(() => context.plan()).toThrow();
      expect(context.requests).toHaveLength(0);
    },
  );

  it.each([
    MARKER_A,
    Buffer.from(MARKER_A).toString("base64"),
    Buffer.from(JSON.stringify({ marker: MARKER_A })).toString("base64url"),
  ])(
    "rejects canary in bearer inputs without echoing its value",
    async (secret) => {
      const context = await fixture();
      context.a.headers.Authorization = `Bearer ${secret}`;
      let error = "";
      try {
        context.plan();
      } catch (caught) {
        error = String(caught);
      }
      expect(error).toContain("canary");
      expect(error).not.toContain(MARKER_A);
      expect(error).not.toContain(secret);
      expect(context.requests).toHaveLength(0);
    },
  );

  it("locks validated input before execution and accepts no forged plans", async () => {
    const context = await fixture();
    const plan = context.plan();
    expect(() => {
      const first = plan.requests[0];
      if (first) first.request.url = `${context.origin}/unexpected`;
    }).toThrow();
    context.config.identity.actorA = "changed-after-validation";
    const result = await executeIdorPlan(plan, { timeoutMs: 1_000 });
    expect(result.baseline.assessment?.classification).toBe("PASS");
    const before = context.requests.length;
    await expect(
      executeIdorPlan({ ...plan }, { timeoutMs: 1_000 }),
    ).rejects.toThrow("validated plan");
    await expect(executeIdorPlan(plan, { timeoutMs: 0 })).rejects.toThrow(
      "timeout",
    );
    expect(context.requests).toHaveLength(before);
  });
});
