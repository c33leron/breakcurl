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

  it("warns for accepted wrong types but leaves transport failures unevaluated", () => {
    expect(classifyResponse(mutation, response({ status: 200 }))).toMatchObject(
      { classification: "WARN" },
    );
    expect(
      classifyResponse(mutation, response({ status: 0, timedOut: true })),
    ).toMatchObject({ classification: "ERROR" });
    expect(
      classifyResponse(
        mutation,
        response({ status: 0, connectionError: "Connection failed." }),
      ),
    ).toMatchObject({ classification: "ERROR" });
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

  it.each(["technology", "database"])(
    "does not let a %s signal downgrade strict auth failures or redirects",
    (signal) => {
      const authMutation: MutationCase = {
        ...mutation,
        kind: "auth-missing",
        category: "authentication",
        expectation: "auth-reject",
      };
      const detected =
        signal === "technology"
          ? { headers: { "x-powered-by": "Express" }, body: "ok" }
          : {
              headers: { "content-type": "text/plain" },
              body: "SQLSTATE syntax error at or near x",
            };
      const strict = classifyResponse(
        authMutation,
        response({ ...detected, status: 200 }),
      );
      expect(strict.classification).toBe("FAIL");
      expect(englishText(strict.reason)).toContain("required 401/403");
      expect(strict.securitySignals).toHaveLength(2);
      const redirect = classifyResponse(
        authMutation,
        response({ ...detected, status: 302 }),
      );
      expect(redirect.classification).toBe("ERROR");
      expect(englishText(redirect.reason)).toContain(
        "does not follow redirects",
      );
    },
  );

  it.each(["observe", "reject"] as const)(
    "records technology disclosure as INFO for an otherwise %s response",
    (expectation) => {
      const result = classifyResponse(
        { ...mutation, expectation },
        response({
          status: expectation === "observe" ? 200 : 400,
          headers: { "x-powered-by": "Express" },
        }),
      );
      expect(result).toMatchObject({
        classification: "INFO",
        securitySignals: [{ id: "technology-header" }],
      });
      const stronger = classifyResponse(
        { ...mutation, expectation },
        response({
          status: 400,
          headers: { "x-powered-by": "Express" },
          body: "SQLSTATE syntax error at or near x",
        }),
      );
      expect(stronger).toMatchObject({
        classification: "WARN",
        severity: "HIGH",
      });
    },
  );

  it("does not infer JSON validity or schema identity from incomplete bodies", () => {
    const truncated = response({
      body: '{"data":"unfinished',
      bodyTruncated: true,
    });
    const result = classifyResponse(mutation, truncated);
    expect(result.classification).toBe("ERROR");
    expect(englishText(result.reason)).toContain(
      "complete response contract could not be evaluated",
    );
    expect(englishText(result.reason)).not.toContain("invalid JSON");
    expect(responseSchemaFingerprint(truncated)).toBeNull();
    expect(
      responseSchemaFingerprint(
        response({ connectionError: "Connection failed." }),
      ),
    ).toBeNull();
    expect(responseSchemaFingerprint(response({ timedOut: true }))).toBeNull();
    expect(
      classifyResponse(mutation, { ...truncated, status: 503 }).classification,
    ).toBe("FAIL");
  });

  it.each([{ timedOut: true }, { connectionError: "Connection failed." }])(
    "keeps received 5xx evidence when its body fails: %j",
    (failure) => {
      expect(
        classifyResponse(mutation, response({ status: 503, ...failure })),
      ).toMatchObject({ classification: "FAIL" });
      expect(
        classifyResponse(mutation, response({ status: 200, ...failure })),
      ).toMatchObject({ classification: "ERROR" });
    },
  );

  it("bases auth confidence only on the explicit HTTP contract", () => {
    const authMutation: MutationCase = {
      ...mutation,
      kind: "auth-missing",
      category: "authentication",
      expectation: "observe",
    };
    const sameBody = response({ status: 200, body: '{"created":true}' });
    const observed = classifyResponse(authMutation, sameBody, {
      baseline: sameBody,
    });
    expect(observed).toMatchObject({
      classification: "WARN",
      confidence: "MEDIUM",
    });
    expect(englishText(observed.reason)).not.toContain("matched");
    const strict = classifyResponse(
      authMutation,
      { ...sameBody, bodyTruncated: true },
      { expectAuth: true, baseline: sameBody },
    );
    expect(strict).toMatchObject({
      classification: "FAIL",
      confidence: "HIGH",
    });
    expect(englishText(strict.reason)).toContain("required 401/403");
    expect(englishText(strict.reason)).toContain(
      "Resource access and side effects were not verified",
    );
  });

  it("honors auth-reject on explicitly configured custom cases", () => {
    const custom: MutationCase = {
      ...mutation,
      kind: "custom-set",
      category: "custom",
      expectation: "auth-reject",
    };
    expect(classifyResponse(custom, response({ status: 200 }))).toMatchObject({
      classification: "FAIL",
    });
    expect(classifyResponse(custom, response({ status: 401 }))).toMatchObject({
      classification: "PASS",
    });
    expect(classifyResponse(custom, response({ status: 422 }))).toMatchObject({
      classification: "WARN",
    });
  });
});
