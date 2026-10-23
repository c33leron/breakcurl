import { describe, expect, it } from "vitest";
import {
  auditResponseHeaders,
  classifyBaseline,
  classifyCase,
} from "../src/classify.js";
import { generateChecks, requestForCase } from "../src/mutations.js";
import { owaspCoverage } from "../src/owasp.js";
import { formatSarif } from "../src/sarif.js";
import type {
  HttpResult,
  MutationCase,
  ParsedCurl,
  RunResult,
} from "../src/types.js";

const request: ParsedCurl = {
  method: "POST",
  url: "https://api.example.test/orders",
  headers: {
    Authorization: "Bearer secret-header-token",
    "Content-Type": "application/json",
  },
  body: { itemId: 42, note: "gift" },
};

const jwtRequest: ParsedCurl = {
  method: "POST",
  url: "https://api.example.test/orders",
  headers: {
    Authorization: `Bearer ${Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url")}.${Buffer.from(JSON.stringify({ sub: "user-123", exp: 9999999999 })).toString("base64url")}.SflKxwRJSMeKKF2VT4fwpMJYgStvJCqiT5Uex0`,
    "Content-Type": "application/json",
  },
  body: { itemId: 42, note: "gift" },
};

function response(overrides: Partial<HttpResult>): HttpResult {
  return {
    status: 200,
    latencyMs: 10,
    headers: { "content-type": "application/json" },
    body: '{"ok":true}',
    timedOut: false,
    ...overrides,
  };
}

function caseOf(
  kind: MutationCase["kind"],
  extra: Partial<MutationCase> = {},
): MutationCase {
  return {
    id: `${kind}:test`,
    path: "$",
    description: "test",
    kind,
    body: {},
    category: "authorization",
    expectation: "auth-reject",
    ...extra,
  };
}

function runResult(cases: CaseItem[]): RunResult {
  return {
    baseline: {
      request,
      response: response({ status: 200 }),
    },
    cases,
    mode: "checks",
  };
}

interface CaseItem {
  mutation: MutationCase;
  response: HttpResult;
  classification: "FAIL" | "WARN" | "ERROR" | "INFO" | "PASS";
  reason: string;
  severity?: "LOW" | "MEDIUM" | "HIGH";
  confidence?: "LOW" | "MEDIUM" | "HIGH";
  securitySignals?: {
    id: string;
    title: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    cwe?: string;
    owasp?: string;
  }[];
}

describe("JWT oracles", () => {
  it("fails HIGH on an accepted broken-signature token", () => {
    const result = classifyCase(
      caseOf("jwt-alg-none"),
      response({ status: 200 }),
    );
    expect(result.classification).toBe("FAIL");
    expect(result.severity).toBe("HIGH");
    expect(result.securitySignals?.[0]).toMatchObject({
      id: "jwt-auth-rejection-missing",
      cwe: "CWE-347",
      owasp: "API2:2023",
    });
  });

  it("treats exp tampering as a signature probe, not evidence of expiry enforcement", () => {
    const result = classifyCase(
      caseOf("jwt-expired"),
      response({ status: 200 }),
    );
    expect(result.classification).toBe("FAIL");
    expect(result.securitySignals?.[0]).toMatchObject({
      id: "jwt-auth-rejection-missing",
      cwe: "CWE-347",
      owasp: "API2:2023",
    });
    const rejected = classifyCase(
      caseOf("jwt-expired"),
      response({ status: 401 }),
    );
    expect(rejected.classification).toBe("INFO");
    expect(JSON.stringify(rejected.reason)).toContain(
      "expiry enforcement was not assessed",
    );
  });

  it("keeps successful JWT requests as candidates without a sole-Bearer auth expectation", () => {
    const result = classifyCase(
      caseOf("jwt-alg-none", { expectation: "observe" }),
      response({ status: 200 }),
    );
    expect(result.classification).toBe("WARN");
    expect(result.confidence).toBe("MEDIUM");
    expect(JSON.stringify(result.reason)).toContain(
      "no signature bypass is proven",
    );
  });

  it("passes when the API rejects a tampered token with 401/403", () => {
    for (const status of [401, 403]) {
      expect(
        classifyCase(caseOf("jwt-claim-tamper"), response({ status }))
          .classification,
      ).toBe("PASS");
    }
  });
});

describe("method tampering", () => {
  it("warns with CWE-284 when an alternative method is accepted", () => {
    const result = classifyCase(
      caseOf("method-tamper", { method: "DELETE", expectation: "observe" }),
      response({ status: 200 }),
    );
    expect(result.classification).toBe("WARN");
    expect(result.securitySignals?.[0]).toMatchObject({
      id: "unexpected-method-accepted",
      cwe: "CWE-284",
      owasp: "API5:2023",
    });
  });

  it("passes when the alternative method is rejected", () => {
    const result = classifyCase(
      caseOf("method-tamper", { method: "DELETE", expectation: "observe" }),
      response({ status: 405 }),
    );
    expect(result.classification).toBe("PASS");
  });

  it("generates all non-baseline verbs only with attackMethods", () => {
    const off = generateChecks(request, { profile: "security", maxCases: 80 });
    expect(off.cases.some((item) => item.kind === "method-tamper")).toBe(false);
    const on = generateChecks(request, {
      profile: "security",
      maxCases: 80,
      attackMethods: true,
    });
    const methods = on.cases
      .filter((item) => item.kind === "method-tamper")
      .map((item) => item.method);
    expect(methods.sort()).toEqual(["DELETE", "GET", "PATCH", "PUT"]);
    expect(
      on.notes.some((note) =>
        typeof note === "string"
          ? note.includes("Method tampering")
          : note.en.includes("Method tampering"),
      ),
    ).toBe(true);
    const tamperCase = on.cases.find(
      (item) => item.kind === "method-tamper" && item.method === "GET",
    );
    if (!tamperCase)
      throw new Error("GET method-tamper case was not generated");
    const replayed = requestForCase(request, tamperCase);
    expect(replayed.method).toBe("GET");
  });
});

describe("API spec recon", () => {
  it("generates unauthenticated same-origin spec probes in the security profile", () => {
    const generated = generateChecks(request, {
      profile: "security",
      maxCases: 80,
    });
    const specs = generated.cases.filter((item) => item.kind === "spec-probe");
    expect(specs.map((item) => item.url).sort()).toEqual([
      "https://api.example.test/api-docs",
      "https://api.example.test/graphql",
      "https://api.example.test/openapi.json",
      "https://api.example.test/swagger.json",
    ]);
    expect(specs.every((item) => item.method === "GET")).toBe(true);
    expect(
      specs.every(
        (item) =>
          !Object.keys(item.headers ?? {}).some(
            (name) => name.toLowerCase() === "authorization",
          ),
      ),
    ).toBe(true);
  });

  it("warns on an exposed OpenAPI document and passes on denial", () => {
    const probe = caseOf("spec-probe", {
      id: "spec-probe:/openapi.json",
      path: "/openapi.json",
      expectation: "observe",
      category: "recon",
    });
    const exposed = classifyCase(
      probe,
      response({ body: '{"openapi":"3.0.1","paths":{}}' }),
    );
    expect(exposed.classification).toBe("WARN");
    expect(exposed.securitySignals?.[0]).toMatchObject({
      id: "api-spec-exposure",
      owasp: "API9:2023",
    });
    const denied = classifyCase(probe, response({ status: 404 }));
    expect(denied.classification).toBe("PASS");
  });

  it("does not mistake a GraphQL error for a published specification", () => {
    const result = classifyCase(
      caseOf("spec-probe", { expectation: "observe" }),
      response({ body: '{"error":"GraphQL query missing"}' }),
    );
    expect(result.classification).toBe("INFO");
    expect(result.securitySignals).toBeUndefined();
  });

  it("does not derive spec exposure from an incomplete body", () => {
    const result = classifyCase(
      caseOf("spec-probe", { expectation: "observe" }),
      response({ body: '{"openapi":"3.0.0","paths":{}}', bodyTruncated: true }),
    );
    expect(result.classification).toBe("ERROR");
  });
});

describe("mass assignment", () => {
  it("does not equate an accepted request with assignment of its privilege field", () => {
    const generated = generateChecks(request, {
      profile: "security",
      maxCases: 80,
    });
    const probe = generated.cases.find(
      (item) => item.kind === "privilege-field" && item.path === "$.isAdmin",
    );
    if (!probe) throw new Error("privilege-field case was not generated");
    expect(probe.body).toMatchObject({ isAdmin: true, itemId: 42 });
    const accepted = classifyCase(
      probe,
      response({ status: 201, body: '{"ignored":["isAdmin"]}' }),
    );
    expect(accepted.classification).toBe("INFO");
    expect(accepted.securitySignals).toBeUndefined();
    expect(JSON.stringify(accepted.reason)).toContain(
      "does not prove mass assignment",
    );
    const rejected = classifyCase(probe, response({ status: 400 }));
    expect(rejected.classification).not.toBe("WARN");
  });

  it("skips privilege probes when the body already carries the field", () => {
    const generated = generateChecks(
      { ...request, body: { itemId: 1, isAdmin: false } },
      { profile: "security", maxCases: 80 },
    );
    expect(
      generated.cases.filter((item) => item.kind === "privilege-field").length,
    ).toBe(1);
  });
});

describe("JWT cases in profile composition", () => {
  it("adds JWT attacks to security/full and not to quick/negative", () => {
    const security = generateChecks(jwtRequest, {
      profile: "security",
      maxCases: 80,
    });
    expect(
      security.cases.filter((item) => item.kind.startsWith("jwt-")).length,
    ).toBeGreaterThanOrEqual(3);
    const quick = generateChecks(jwtRequest, {
      profile: "quick",
      maxCases: 15,
    });
    expect(quick.cases.some((item) => item.kind.startsWith("jwt-"))).toBe(
      false,
    );
  });
});

describe("response header audit (API8)", () => {
  it("reports incompatible CORS headers as LOW configuration evidence", () => {
    const signals = auditResponseHeaders(
      { ...request, url: "https://api.example.test/x" },
      response({
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-credentials": "true",
        },
      }),
    );
    expect(signals).toContainEqual(
      expect.objectContaining({
        id: "cors-wildcard-credentials",
        severity: "LOW",
        cwe: "CWE-942",
        owasp: "API8:2023",
      }),
    );
  });

  it("flags missing cookie protections and missing HSTS once on the baseline", () => {
    const assessment = classifyBaseline(
      { ...request, url: "https://api.example.test/login" },
      response({
        headers: { "set-cookie": "sid=abc123; Path=/" },
      }),
    );
    const ids = assessment.securitySignals?.map((signal) => signal.id);
    expect(ids).toContain("cookie-flags-missing");
    expect(ids).toContain("hsts-missing");
    expect(assessment.classification).toBe("WARN");
  });

  it("flags a versioned Server header", () => {
    const signals = auditResponseHeaders(
      request,
      response({ headers: { server: "nginx/1.24.0" } }),
    );
    expect(signals.map((signal) => signal.id)).toContain(
      "server-version-header",
    );
  });

  it("stays silent on a well-configured response", () => {
    const signals = auditResponseHeaders(
      { ...request, url: "https://api.example.test/x" },
      response({
        headers: {
          "strict-transport-security": "max-age=63072000",
          server: "cloudfront",
        },
      }),
    );
    expect(signals).toHaveLength(0);
  });
});

describe("excessive data exposure scan (API3)", () => {
  it("flags bcrypt and argon2 hashes in any response", () => {
    const result = classifyCase(
      caseOf("custom-set", { expectation: "observe", category: "structure" }),
      response({
        body: '{"user":{"pwd_hash":"$2b$12$KIXQeQeJ8D5W0OZ9vJ3H7uZ2xY1aB2c3d4e5f6g7h8i9j0k"}}',
      }),
    );
    expect(result.securitySignals?.map((signal) => signal.id)).toContain(
      "password-hash-exposure",
    );
  });

  it("flags sensitive-named fields returning plaintext values", () => {
    const result = classifyCase(
      caseOf("custom-set", { expectation: "observe", category: "structure" }),
      response({
        body: '{"profile":{"password":"hunter2","note":"public text"}}',
      }),
    );
    expect(result.securitySignals?.map((signal) => signal.id)).toContain(
      "sensitive-field-response",
    );
  });

  it("does not flag empty or hashed sensitive fields twice", () => {
    const result = classifyCase(
      caseOf("custom-set", { expectation: "observe", category: "structure" }),
      response({
        body: '{"password":"","secret":"$2y$10$abcdef0123456789abcdef0123456789abcdef012"}',
      }),
    );
    const ids = result.securitySignals?.map((signal) => signal.id);
    expect(ids).toContain("password-hash-exposure");
    expect(ids).not.toContain("sensitive-field-response");
  });
});

describe("OWASP coverage matrix", () => {
  it("reflects what the run actually executed", () => {
    const coverage = owaspCoverage(runResult([]));
    const byItem = Object.fromEntries(
      coverage.map((entry) => [entry.item, entry.status]),
    );
    expect(byItem["API1:2023"]).toBe("not-tested");
    expect(byItem["API2:2023"]).toBe("not-tested");
    expect(byItem["API4:2023"]).toBe("out-of-scope");
    expect(byItem["API8:2023"]).toBe("not-tested");

    const attacked = owaspCoverage(
      runResult([
        {
          mutation: caseOf("jwt-alg-none"),
          response: response({ status: 200 }),
          classification: "FAIL",
          reason: "jwt accepted",
          severity: "HIGH",
          securitySignals: [
            {
              id: "jwt-signature-not-enforced",
              title: "Broken-signature JWT accepted by the endpoint",
              severity: "HIGH",
            },
          ],
        },
        {
          mutation: caseOf("spec-probe", {
            expectation: "observe",
            category: "recon",
          }),
          response: response({ status: 404 }),
          classification: "PASS",
          reason: "not exposed",
        },
      ]),
    );
    const attackedMap = Object.fromEntries(
      attacked.map((entry) => [entry.item, entry.status]),
    );
    expect(attackedMap["API2:2023"]).toBe("tested");
    expect(attackedMap["API9:2023"]).toBe("tested");
  });
});

describe("SARIF severity mapping", () => {
  it("derives security-severity from finding severity, not a CWE guess", () => {
    const sarif = JSON.parse(
      formatSarif(
        runResult([
          {
            mutation: caseOf("jwt-alg-none"),
            response: response({ status: 200 }),
            classification: "FAIL",
            reason: "jwt accepted",
            severity: "HIGH",
            confidence: "HIGH",
            securitySignals: [
              {
                id: "jwt-signature-not-enforced",
                title: "Broken-signature JWT accepted by the endpoint",
                severity: "HIGH",
                cwe: "CWE-347",
                owasp: "API2:2023",
              },
            ],
          },
        ]),
      ),
    );
    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.id).toBe("jwt-signature-not-enforced");
    expect(rule.properties["security-severity"]).toBe("8.1");
    const result = sarif.runs[0].results[0];
    expect(result.properties["breakcurl/owasp"]).toBe("API2:2023");
  });
});
