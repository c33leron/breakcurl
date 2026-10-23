import { beforeEach, describe, expect, it, vi } from "vitest";
import { englishText } from "../src/i18n.js";
import {
  executeIdorPlan,
  type IdorConfig,
  prepareIdorPlan,
} from "../src/idor.js";
import { owaspCoverage } from "../src/owasp.js";
import { sendRequest } from "../src/runner.js";
import type {
  CaseResult,
  HttpResult,
  MutationKind,
  OwaspApiItem,
  ParsedCurl,
  RunResult,
} from "../src/types.js";

vi.mock("../src/runner.js", () => ({ sendRequest: vi.fn() }));

const request: ParsedCurl = {
  method: "GET",
  url: "https://api.example.test/objects/object-a",
  headers: { Authorization: "Bearer fixture-token-a" },
  body: {},
};
const config: IdorConfig = {
  authModel: "bearer-only",
  objectIdsGrantAccess: false,
  rule: "a-cannot-read-b",
  privateCanaries: true,
  identity: {
    url: "https://api.example.test/me",
    principalPointer: "/id",
    actorA: "actor-a",
    actorB: "actor-b",
  },
  objects: {
    pathTemplate: "/objects/{objectId}",
    idPointer: "/id",
    canaryPointer: "/privateMarker",
    objectA: { id: "object-a", canary: "aX7tQ9mK2jL5nV8r" },
    objectB: { id: "object-b", canary: "bS8uR2pW6yD4fH9z" },
  },
};

function response(overrides: Partial<HttpResult> = {}): HttpResult {
  return {
    status: 200,
    latencyMs: 1,
    headers: { "content-type": "application/json" },
    body: "{}",
    bodyTruncated: false,
    timedOut: false,
    ...overrides,
  };
}

function probe(
  kind: MutationKind,
  overrides: Partial<CaseResult> = {},
): CaseResult {
  return {
    mutation: {
      id: `${kind}:test`,
      path: "$",
      kind,
      description: "test",
      body: {},
    },
    response: response(),
    classification: "INFO",
    reason: "test",
    ...overrides,
  };
}

function run(cases: CaseResult[] = []): RunResult {
  return {
    baseline: {
      request,
      response: response(),
      assessment: { classification: "INFO", reason: "Baseline assessed" },
    },
    cases,
    mode: "checks",
  };
}

function coverage(result: RunResult, item: OwaspApiItem) {
  const entry = owaspCoverage(result).find((entry) => entry.item === item);
  if (!entry) throw new Error(`Missing coverage entry: ${item}`);
  return { ...entry, detail: englishText(entry.detail) };
}

function idorPlan() {
  return prepareIdorPlan(
    request,
    {
      ...request,
      url: "https://api.example.test/objects/object-b",
      headers: { Authorization: "Bearer fixture-token-b" },
    },
    config,
  );
}

function successfulIdorControls() {
  for (const body of [
    { id: "actor-a" },
    { id: "actor-b" },
    {
      id: config.objects.objectA.id,
      privateMarker: config.objects.objectA.canary,
    },
    {
      id: config.objects.objectB.id,
      privateMarker: config.objects.objectB.canary,
    },
  ]) {
    vi.mocked(sendRequest).mockResolvedValueOnce(
      response({ body: JSON.stringify(body) }),
    );
  }
}

beforeEach(() => {
  vi.mocked(sendRequest).mockReset();
});

describe("OWASP coverage reflects evaluated requests", () => {
  it("does not claim BOLA or unrelated audits when IDOR stops on identity", async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce(response({ status: 401 }));
    const result = await executeIdorPlan(idorPlan(), { timeoutMs: 100 });

    expect(sendRequest).toHaveBeenCalledTimes(1);
    expect(result.cases).toHaveLength(0);
    expect(coverage(result, "API1:2023")).toMatchObject({
      status: "not-tested",
      detail: expect.stringContaining("was not reached"),
    });
    for (const item of ["API2:2023", "API3:2023", "API8:2023"] as const) {
      expect(coverage(result, item).status).toBe("not-tested");
    }
  });

  it.each(["denied", "disclosed"])(
    "counts the actual evaluated IDOR cross-read when it is %s",
    async (outcome) => {
      successfulIdorControls();
      vi.mocked(sendRequest).mockResolvedValueOnce(
        outcome === "denied"
          ? response({ status: 403 })
          : response({
              body: JSON.stringify({
                id: config.objects.objectB.id,
                privateMarker: config.objects.objectB.canary,
              }),
            }),
      );
      const result = await executeIdorPlan(idorPlan(), { timeoutMs: 100 });

      expect(sendRequest).toHaveBeenCalledTimes(5);
      expect(coverage(result, "API1:2023").status).toBe("tested");
      expect(coverage(result, "API2:2023").status).toBe("not-tested");
      expect(coverage(result, "API3:2023").status).toBe("not-tested");
      expect(coverage(result, "API8:2023").status).toBe("not-tested");
    },
  );

  it.each([
    response({ status: 429 }),
    response({ timedOut: true }),
    response({ bodyTruncated: true }),
    response(), // Complete HTTP 200, but neither a denial nor private disclosure.
  ])(
    "does not mark an inconclusive IDOR cross-read tested (%j)",
    async (cross) => {
      successfulIdorControls();
      vi.mocked(sendRequest).mockResolvedValueOnce(cross);
      const result = await executeIdorPlan(idorPlan(), { timeoutMs: 100 });

      expect(coverage(result, "API1:2023")).toMatchObject({
        status: "partial",
        detail: expect.stringContaining("could not be fully evaluated"),
      });
    },
  );

  it.each([
    response({ status: 429 }),
    response({ status: 0, timedOut: true }),
    response({ status: 0, connectionError: "ECONNRESET" }),
    response({ bodyTruncated: true }),
    response({ status: 500, timedOut: true }),
  ])(
    "does not count a failed or incomplete probe as evaluated (%j)",
    (failed) => {
      const result = run([
        probe("jwt-alg-none", { response: failed, classification: "ERROR" }),
        probe("spec-probe", { response: failed, classification: "ERROR" }),
      ]);

      for (const item of ["API2:2023", "API9:2023"] as const) {
        expect(coverage(result, item)).toMatchObject({
          status: "partial",
          detail: expect.stringContaining("could not be fully evaluated"),
        });
      }
    },
  );

  it("names only the JWT probe kinds actually evaluated", () => {
    const result = run([
      probe("jwt-alg-none"),
      probe("jwt-signature-strip", {
        response: response({ status: 429 }),
        classification: "ERROR",
      }),
    ]);
    const auth = coverage(result, "API2:2023");

    expect(auth.status).toBe("partial");
    expect(auth.detail).toContain("Evaluated 1 of 2 sent probes");
    expect(auth.detail).toContain("JWT alg=none");
    expect(auth.detail).not.toMatch(
      /credential removal|signature stripping|claim tampering|expiry/,
    );
  });

  it("does not call a modified exp token an expiry-enforcement test", () => {
    const auth = coverage(run([probe("jwt-expired")]), "API2:2023");

    expect(auth.status).toBe("tested");
    expect(auth.detail).toContain(
      "modified JWT exp with an invalidated signature",
    );
    expect(auth.detail).toContain("not expiry enforcement");
  });

  it("only claims passive audits for a completed assessed checks baseline", () => {
    const result = run();
    expect(coverage(result, "API3:2023").status).toBe("partial");
    expect(coverage(result, "API8:2023").status).toBe("partial");

    delete result.baseline.assessment;
    expect(coverage(result, "API3:2023").status).toBe("not-tested");
    expect(coverage(result, "API8:2023").status).toBe("not-tested");
  });

  it.each([
    response({ status: 429 }),
    response({ timedOut: true }),
    response({ bodyTruncated: true }),
    response({ bodyOmitted: true }),
  ])(
    "does not claim completed baseline audits for unusable responses (%j)",
    (baseline) => {
      const result = run();
      result.baseline.response = baseline;

      expect(coverage(result, "API3:2023").status).toBe("not-tested");
      expect(coverage(result, "API8:2023").status).toBe("not-tested");
    },
  );

  it("keeps mass-assignment and function-method probes within their scope", () => {
    const privilege = probe("privilege-field");
    privilege.mutation.category = "authorization";
    const result = run([privilege]);
    expect(coverage(result, "API3:2023")).toMatchObject({
      status: "partial",
      detail: expect.stringContaining(
        "field persistence and authorization effects were not verified",
      ),
    });
    expect(coverage(result, "API5:2023").status).toBe("not-tested");

    result.cases.push(probe("method-tamper"));
    expect(coverage(result, "API5:2023")).toMatchObject({
      status: "partial",
      detail: expect.stringContaining(
        "Role-specific function permissions were not verified",
      ),
    });
  });

  it("limits completed spec discovery coverage to the paths actually evaluated", () => {
    const inventory = coverage(run([probe("spec-probe")]), "API9:2023");

    expect(inventory.status).toBe("tested");
    expect(inventory.detail).toContain("1 of 1 sent");
    expect(inventory.detail).toContain("limited to those paths");
    expect(inventory.detail).not.toMatch(
      /openapi.json|swagger.json|graphql|api-docs/,
    );
  });
});
