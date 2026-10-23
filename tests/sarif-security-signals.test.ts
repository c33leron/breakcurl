import { describe, expect, it } from "vitest";
import { classifyBaseline, classifyCase } from "../src/classify.js";
import { formatSarif } from "../src/sarif.js";
import type { CaseResult, RunResult } from "../src/types.js";

function baselineOnly(): RunResult {
  return {
    baseline: {
      request: {
        method: "GET",
        url: "https://api.example.test/me",
        headers: {},
        body: {},
      },
      response: {
        status: 200,
        latencyMs: 1,
        headers: { "Content-Type": "application/json" },
        body: "{}",
        timedOut: false,
      },
    },
    cases: [],
  };
}

function caseWithResponse(
  response: Partial<CaseResult["response"]>,
): CaseResult {
  const mutation: CaseResult["mutation"] = {
    id: "null:$.name",
    path: "$.name",
    description: "Name set to null",
    kind: "null",
    category: "structure",
    expectation: "observe",
    body: { name: null },
  };
  const actualResponse: CaseResult["response"] = {
    status: 200,
    latencyMs: 1,
    headers: {},
    body: "",
    timedOut: false,
    ...response,
  };
  return {
    mutation,
    response: actualResponse,
    ...classifyCase(mutation, actualResponse),
  };
}

describe("SARIF baseline and independent security signals", () => {
  it("exports baseline-only HSTS, cookie and sensitive-field observations", () => {
    const result = baselineOnly();
    result.baseline.response.headers["set-cookie"] = "session=fixture";
    result.baseline.response.body = '{"password":"fixture-password"}';
    result.baseline.assessment = classifyBaseline(
      result.baseline.request,
      result.baseline.response,
    );

    const run = JSON.parse(formatSarif(result)).runs[0];
    expect(run.results).toHaveLength(3);
    expect(run.results.map((item: { ruleId: string }) => item.ruleId)).toEqual(
      expect.arrayContaining([
        "hsts-missing",
        "cookie-flags-missing",
        "sensitive-field-response",
      ]),
    );
    for (const finding of run.results) {
      expect(finding.level).toBe("warning");
      expect(finding.properties["breakcurl/source"]).toBe("baseline");
      expect(finding.partialFingerprints["breakcurlCaseId/v1"]).toBe(
        "baseline",
      );
      expect(finding.partialFingerprints["breakcurlFindingId/v1"]).toBe(
        `baseline:${finding.ruleId}`,
      );
      expect(finding.locations[0].physicalLocation.artifactLocation.uri).toBe(
        "https://api.example.test/me",
      );
    }
    expect(run.tool.driver.rules).toContainEqual(
      expect.objectContaining({
        id: "hsts-missing",
        properties: { "security-severity": "2.5" },
      }),
    );
  });

  it("assigns simultaneous medium and high signals their own rule severity", () => {
    const result = baselineOnly();
    result.cases = [
      caseWithResponse({ body: "Stack trace: /app/service.ts SQLSTATE[42]" }),
    ];
    expect(result.cases[0]?.severity).toBe("HIGH");

    const run = JSON.parse(formatSarif(result)).runs[0];
    expect(run.results).toHaveLength(2);
    expect(run.tool.driver.rules).toContainEqual(
      expect.objectContaining({
        id: "internal-details",
        properties: { "security-severity": "5.0" },
      }),
    );
    expect(run.tool.driver.rules).toContainEqual(
      expect.objectContaining({
        id: "database-error",
        properties: { "security-severity": "8.1" },
      }),
    );
    expect(run.results).toContainEqual(
      expect.objectContaining({
        ruleId: "internal-details",
        properties: expect.objectContaining({ "breakcurl/severity": "MEDIUM" }),
      }),
    );
    expect(run.results).toContainEqual(
      expect.objectContaining({
        ruleId: "database-error",
        properties: expect.objectContaining({ "breakcurl/severity": "HIGH" }),
      }),
    );
  });

  it("retains server failure separately from a response observation", () => {
    const result = baselineOnly();
    result.cases = [
      caseWithResponse({ status: 500, body: "Stack trace: /app/service.ts" }),
    ];

    const run = JSON.parse(formatSarif(result)).runs[0];
    expect(run.results).toHaveLength(2);
    expect(run.results).toContainEqual(
      expect.objectContaining({
        ruleId: "structure-finding",
        level: "error",
        properties: expect.objectContaining({
          "breakcurl/classification": "FAIL",
        }),
      }),
    );
    expect(run.results).toContainEqual(
      expect.objectContaining({
        ruleId: "internal-details",
        level: "warning",
        properties: expect.objectContaining({ "breakcurl/severity": "MEDIUM" }),
      }),
    );
  });

  it("exports baseline transport errors and an unsuccessful invocation", () => {
    const result = baselineOnly();
    result.baseline.request.url = "http://api.example.test/me";
    result.baseline.response.status = 0;
    result.baseline.response.timedOut = true;
    result.baseline.assessment = classifyBaseline(
      result.baseline.request,
      result.baseline.response,
    );

    const run = JSON.parse(formatSarif(result)).runs[0];
    expect(run.invocations[0].executionSuccessful).toBe(false);
    expect(run.results).toHaveLength(1);
    expect(run.results[0]).toMatchObject({
      ruleId: "baseline-finding",
      level: "error",
      properties: {
        "breakcurl/classification": "ERROR",
        "breakcurl/source": "baseline",
      },
    });
    expect(run.results[0].message.text).toContain("timed out");
  });

  it("does not promote a technology header to a failed security rule", () => {
    const result = baselineOnly();
    result.cases = [
      caseWithResponse({
        status: 500,
        headers: { "X-Powered-By": "fixture-server" },
      }),
    ];

    const run = JSON.parse(formatSarif(result)).runs[0];
    expect(run.results).toHaveLength(1);
    expect(run.results[0].ruleId).toBe("structure-finding");
    expect(run.tool.driver.rules).toEqual([
      expect.objectContaining({ id: "structure-finding" }),
    ]);
    expect(formatSarif(result)).not.toContain("technology-header");
  });

  it("redacts baseline and case metadata including signal rules and fingerprints", () => {
    const secret = "fixture credential / value";
    const result = baselineOnly();
    result.baseline.request.url = `https://api.example.test/${encodeURIComponent(secret)}`;
    result.baseline.assessment = {
      classification: "WARN",
      reason: `Baseline ${secret}`,
      securitySignals: [
        {
          id: `baseline-signal-${secret}`,
          title: `Baseline title ${secret}`,
          severity: "MEDIUM",
          cwe: `CWE-${secret}`,
          owasp: `API-${secret}`,
        },
      ],
    };
    const item = caseWithResponse({ status: 500 });
    item.mutation.id = `case-${secret}`;
    item.mutation.description = `Case description ${secret}`;
    item.reason = `Case reason ${secret}`;
    item.securitySignals = [
      {
        id: `case-signal-${secret}`,
        title: `Case title ${secret}`,
        severity: "LOW",
        cwe: `CWE-${secret}`,
        owasp: `API-${secret}`,
      },
    ];
    result.cases = [item];

    const output = formatSarif(result, [secret]);
    expect(output).not.toContain(secret);
    expect(output).not.toContain(encodeURIComponent(secret));
    expect(output).toContain("<REDACTED>");
    const run = JSON.parse(output).runs[0];
    expect(run.results).toHaveLength(3);
    expect(run.tool.driver.rules[0].shortDescription.text).toBe(
      "Baseline title <REDACTED>",
    );
  });

  it.each(["json", "runs", "https", "structure-finding"])(
    "preserves SARIF structure when a credential equals %s",
    (secret) => {
      const result = baselineOnly();
      const observed = caseWithResponse({ status: 200 });
      observed.classification = "WARN";
      observed.mutation.id = `observed-${secret}`;
      observed.mutation.description = `Description ${secret}`;
      observed.securitySignals = [
        {
          id: `custom-${secret}`,
          title: `Signal ${secret}`,
          severity: "MEDIUM",
          cwe: `CWE-${secret}`,
          owasp: `API-${secret}`,
        },
      ];
      const failure = caseWithResponse({ status: 500 });
      failure.mutation.id = `failure-${secret}`;
      failure.mutation.description = `Failure ${secret}`;
      failure.reason = `Reason ${secret}`;
      result.cases = [observed, failure];

      const sarif = JSON.parse(formatSarif(result, [secret]));
      expect(sarif.$schema).toBe(
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      );
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs).toHaveLength(1);
      const run = sarif.runs[0];
      expect(run.tool.driver.informationUri).toBe(
        "https://github.com/c33leron/BreakCurl",
      );
      expect(run.tool.driver.name).toBe("BreakCurl");
      expect(run.tool.driver.rules[0]).toMatchObject({
        id: "custom-<REDACTED>",
        shortDescription: { text: "Signal <REDACTED>" },
      });
      expect(run.results[0]).toMatchObject({
        ruleId: "custom-<REDACTED>",
        message: { text: "Description <REDACTED>: Signal <REDACTED>" },
        partialFingerprints: {
          "breakcurlCaseId/v1": "observed-<REDACTED>",
          "breakcurlFindingId/v1": "observed-<REDACTED>:custom-<REDACTED>",
        },
        properties: {
          "breakcurl/cwe": "CWE-<REDACTED>",
          "breakcurl/owasp": "API-<REDACTED>",
        },
      });
      expect(run.tool.driver.rules[1].id).toBe("structure-finding");
      expect(run.results[1]).toMatchObject({
        ruleId: "structure-finding",
        message: { text: "Failure <REDACTED>: Reason <REDACTED>" },
      });
      expect(
        run.results[0].locations[0].physicalLocation.artifactLocation.uri,
      ).toBe("https://api.example.test/me");
    },
  );
});
