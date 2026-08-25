import { describe, expect, it } from "vitest";
import {
  classifyResponse,
  responseSchemaFingerprint,
} from "../src/classify.js";
import { englishText } from "../src/i18n.js";
import type { HttpResult, MutationCase } from "../src/types.js";

const mutation: MutationCase = {
  id: "wrong-type-age",
  path: "$.age",
  description: '$.age = "not-a-number"',
  kind: "wrong-type",
  body: { age: "not-a-number" },
};

function response(overrides: Partial<HttpResult>): HttpResult {
  return {
    status: 422,
    latencyMs: 12,
    headers: { "content-type": "application/json" },
    body: '{"error":"invalid"}',
    timedOut: false,
    ...overrides,
  };
}

describe("classifyResponse", () => {
  it("classifies controlled client errors as PASS", () => {
    expect(classifyResponse(mutation, response({ status: 422 }))).toMatchObject(
      { classification: "PASS" },
    );
  });

  it("classifies 5xx and invalid declared JSON as FAIL", () => {
    expect(classifyResponse(mutation, response({ status: 500 }))).toMatchObject(
      { classification: "FAIL" },
    );
    expect(
      classifyResponse(mutation, response({ body: "not json" })),
    ).toMatchObject({ classification: "FAIL" });
  });

  it("classifies accepted wrong types, connection errors, and timeouts as WARN", () => {
    expect(classifyResponse(mutation, response({ status: 200 }))).toMatchObject(
      { classification: "WARN" },
    );
    expect(
      classifyResponse(mutation, response({ status: 0, timedOut: true })),
    ).toMatchObject({ classification: "WARN" });
    expect(
      classifyResponse(
        mutation,
        response({ status: 0, connectionError: "Connection failed." }),
      ),
    ).toMatchObject({ classification: "WARN" });
  });

  it("classifies an unexpected status as ERROR", () => {
    expect(classifyResponse(mutation, response({ status: 302 }))).toMatchObject(
      { classification: "ERROR" },
    );
  });

  it("classifies rate limiting as ERROR instead of a false validation PASS", () => {
    const result = classifyResponse(mutation, response({ status: 429 }));

    expect(result.classification).toBe("ERROR");
    expect(englishText(result.reason)).toContain("rate limit");
  });

  it("warns when a removed field is accepted or internal paths are exposed", () => {
    const removed: MutationCase = { ...mutation, kind: "remove" };
    expect(
      classifyResponse(removed, response({ status: 204, body: "" })),
    ).toMatchObject({
      classification: "WARN",
    });
    expect(
      classifyResponse(
        mutation,
        response({
          status: 422,
          body: '{"error":"failed at /Users/service/app.ts:42"}',
        }),
      ),
    ).toMatchObject({ classification: "WARN" });
  });

  it.each([
    [401, false, "PASS"],
    [403, true, "PASS"],
    [422, true, "WARN"],
    [200, false, "WARN"],
    [200, true, "FAIL"],
  ] as const)(
    "classifies auth probe HTTP %s with expectAuth=%s as %s",
    (status, expectAuth, classification) => {
      const authMutation: MutationCase = {
        ...mutation,
        kind: "auth-missing",
        category: "authentication",
        expectation: expectAuth ? "auth-reject" : "observe",
      };
      expect(
        classifyResponse(
          authMutation,
          response({ status, body: '{"created":true}' }),
          {
            expectAuth,
            baseline: response({ status: 201, body: '{"created":true}' }),
          },
        ),
      ).toMatchObject({ classification });
    },
  );

  it("reports database errors, exposed credentials, and unsafe HTML reflection", () => {
    expect(
      classifyResponse(
        { ...mutation, kind: "sql-probe", category: "injection" },
        response({
          status: 400,
          headers: { "content-type": "text/plain" },
          body: "SQLSTATE syntax error at or near x",
        }),
      ),
    ).toMatchObject({
      classification: "WARN",
      securitySignals: [{ id: "database-error", cwe: "CWE-209" }],
    });
    expect(
      classifyResponse(
        { ...mutation, kind: "wrong-type" },
        response({
          status: 400,
          headers: { "content-type": "text/plain" },
          body: "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoicWEifQ.signatureABC",
        }),
      ),
    ).toMatchObject({ classification: "WARN", severity: "HIGH" });
    expect(
      classifyResponse(
        { ...mutation, kind: "markup-probe", category: "injection" },
        response({
          status: 200,
          headers: { "content-type": "text/html" },
          body: "<html><breakcurl-probe></html>",
        }),
      ),
    ).toMatchObject({
      classification: "WARN",
      securitySignals: [{ id: "html-reflection", cwe: "CWE-79" }],
    });
  });

  it("uses INFO for exploratory cases and fingerprints response shape, not values", () => {
    expect(
      classifyResponse(
        { ...mutation, expectation: "observe" },
        response({ status: 200 }),
      ),
    ).toMatchObject({ classification: "INFO" });
    expect(
      responseSchemaFingerprint(response({ status: 200, body: '{"id":1}' })),
    ).toBe(
      responseSchemaFingerprint(response({ status: 200, body: '{"id":999}' })),
    );
  });
});
