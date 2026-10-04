import { describe, expect, it } from "vitest";
import { exitCodeForRun } from "../src/execute.js";
import { summarizeRun } from "../src/run-summary.js";
import type { Classification, RunResult } from "../src/types.js";

function fixture(classification?: Classification): RunResult {
  const response = {
    status: 200,
    latencyMs: 1,
    headers: {},
    body: "{}",
    timedOut: false,
  };
  return {
    baseline: {
      request: {
        method: "GET",
        url: "http://example.test/object",
        headers: {},
        body: {},
      },
      response,
    },
    cases: classification
      ? [
          {
            mutation: {
              id: "check",
              path: "$",
              description: "Controlled check",
              kind: "custom-set",
              body: {},
            },
            response: { ...response },
            classification,
            reason: "Fixture evidence",
          },
        ]
      : [],
    completedRequests: classification ? 2 : 1,
    plannedRequests: classification ? 2 : 1,
  };
}

describe("one outcome across CLI and reports", () => {
  it("does not present a baseline-only GET as a completed security assessment", () => {
    const outcome = summarizeRun(fixture());
    expect(outcome).toMatchObject({
      status: "complete",
      exitCode: 0,
      checksRun: 0,
      requestsAttempted: 1,
    });
    expect(outcome.title.en).toContain("Only the original request");
    expect(outcome.explanation.en).toContain(
      "does not establish authentication",
    );
  });

  it("keeps a failed baseline visible even when no checks have a FAIL", () => {
    const result = fixture();
    result.baseline.response.status = 500;
    result.plannedRequests = 16;
    expect(summarizeRun(result)).toMatchObject({
      status: "incomplete",
      exitCode: 2,
      checksRun: 0,
      requestsAttempted: 1,
      requestsPlanned: 16,
    });
    expect(exitCodeForRun(result)).toBe(2);
  });

  it.each(["FAIL", "PASS"] as const)(
    "prioritizes a broken final response over a %s classification",
    (classification) => {
      const result = fixture(classification);
      const item = result.cases[0];
      if (!item) throw new Error("Missing case");
      item.response.status = 503;
      item.response.connectionError = "Connection failed.";
      expect(summarizeRun(result)).toMatchObject({
        status: "incomplete",
        exitCode: 2,
        requestsAttempted: 2,
        requestsPlanned: 2,
      });
    },
  );

  it("distinguishes a warning from a passed run without making warnings a CI failure", () => {
    const result = fixture("WARN");
    expect(summarizeRun(result)).toMatchObject({
      status: "review",
      exitCode: 0,
    });
    expect(exitCodeForRun(result)).toBe(0);
  });

  it("includes a baseline warning even if every additional check passed", () => {
    const result = fixture("PASS");
    result.baseline.assessment = {
      classification: "WARN",
      reason: "Potential disclosure",
    };
    expect(summarizeRun(result).status).toBe("review");
  });

  it("does not count an unsent request as a successful check", () => {
    const result = fixture("PASS");
    result.plannedRequests = 3;
    expect(summarizeRun(result)).toMatchObject({
      status: "incomplete",
      exitCode: 2,
      requestsAttempted: 2,
    });
  });

  it.each([
    ["FAIL", "findings", 1],
    ["ERROR", "incomplete", 2],
    ["INFO", "complete", 0],
    ["PASS", "complete", 0],
  ] as const)(
    "uses the same outcome and exit code for %s",
    (classification, status, code) => {
      const result = fixture(classification);
      expect(summarizeRun(result)).toMatchObject({ status, exitCode: code });
      expect(exitCodeForRun(result)).toBe(code);
    },
  );
});
