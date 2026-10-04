import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { executeChecks, exitCodeForRun } from "../src/execute.js";
import { englishText } from "../src/i18n.js";
import type { MutationCase, ParsedCurl } from "../src/types.js";

describe("execution failure boundaries", () => {
  const requests = new Map<string, string[]>();
  let origin = "";
  const server = createServer(async (request, response) => {
    let raw = "";
    for await (const chunk of request) raw += chunk;
    const phase = (JSON.parse(raw) as { phase: string }).phase;
    const path = request.url ?? "/";
    const log = requests.get(path) ?? [];
    log.push(phase);
    requests.set(path, log);
    response.setHeader("Content-Type", "application/json");
    if (phase === "baseline") {
      response.end('{"ok":true}');
      return;
    }
    if (phase === "after") {
      response.statusCode = 422;
      response.end('{"error":"rejected"}');
      return;
    }
    response.statusCode = 503;
    if (path === "/stalled") {
      response.write('{"error":"');
      // The client must time out while consuming a received 503 response.
      return;
    }
    if (path === "/broken" || path === "/broken-final") {
      // Deliberately end the connection before the declared body is complete.
      response.setHeader("Content-Length", "256");
      response.setHeader("Connection", "close");
      response.end('{"error":"broken');
      return;
    }
    if (path === "/truncated") {
      response.end(JSON.stringify({ error: "x".repeat(17_000) }));
      return;
    }
    response.end('{"error":"service unavailable"}');
  });

  beforeAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("No fixture address");
    origin = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  const mutation = (phase: string): MutationCase => ({
    id: phase,
    path: "$.phase",
    description: phase,
    kind: "custom-set",
    category: "custom",
    expectation: "observe",
    body: { phase },
  });
  const baseline = (path: string): ParsedCurl => ({
    method: "POST",
    url: `${origin}${path}`,
    headers: { "Content-Type": "application/json" },
    body: { phase: "baseline" },
  });

  it.each(["stalled", "broken"] as const)(
    "preserves 503 evidence and exits 2 after a %s body stops the plan",
    async (mode) => {
      const onStop = vi.fn();
      const result = await executeChecks(
        baseline(`/${mode}`),
        [mutation("failure"), mutation("after")],
        { timeoutMs: 200, profile: "quick", language: "en", onStop },
      );
      expect(result.baseline.response.status).toBe(200);
      expect(result.cases).toHaveLength(1);
      expect(result.cases[0]).toMatchObject({
        classification: "FAIL",
        response: { status: 503, timedOut: mode === "stalled" },
      });
      expect(result.cases[0]?.response.connectionError).toBe(
        mode === "stalled" ? "Request timed out." : "Connection failed.",
      );
      const firstCase = result.cases[0];
      if (!firstCase) throw new Error("No recorded 503 case");
      expect(englishText(firstCase.reason)).toContain("HTTP 503");
      expect(result.completedRequests).toBe(2);
      expect(result.plannedRequests).toBe(3);
      expect(requests.get(`/${mode}`)).toEqual(["baseline", "failure"]);
      expect(onStop).toHaveBeenCalledOnce();
      expect(result.notes?.map(englishText).join(" ")).toContain(
        "Safety stop: transport failure; skipped checks: 1",
      );
      expect(exitCodeForRun(result)).toBe(2);
    },
  );

  it("returns exit 1 for a complete 503 response and executes the remaining planned check", async () => {
    const onStop = vi.fn();
    const result = await executeChecks(
      baseline("/complete"),
      [mutation("failure"), mutation("after")],
      { timeoutMs: 1_000, profile: "quick", language: "en", onStop },
    );
    expect(result.cases[0]).toMatchObject({
      classification: "FAIL",
      response: { status: 503, timedOut: false, bodyTruncated: false },
    });
    expect(result.cases[0]?.response.connectionError).toBeUndefined();
    expect(result.completedRequests).toBe(3);
    expect(result.plannedRequests).toBe(3);
    expect(requests.get("/complete")).toEqual(["baseline", "failure", "after"]);
    expect(onStop).not.toHaveBeenCalled();
    expect(exitCodeForRun(result)).toBe(1);
  });

  it("returns exit 2 for a broken final response even when every planned request was sent", async () => {
    const result = await executeChecks(
      baseline("/broken-final"),
      [mutation("failure")],
      { timeoutMs: 1_000, profile: "quick", language: "en" },
    );
    expect(result.cases[0]).toMatchObject({
      classification: "FAIL",
      response: { status: 503, connectionError: "Connection failed." },
    });
    expect(result.completedRequests).toBe(2);
    expect(result.plannedRequests).toBe(2);
    expect(requests.get("/broken-final")).toEqual(["baseline", "failure"]);
    expect(exitCodeForRun(result)).toBe(2);
  });

  it("returns exit 2 for truncated 503 evidence even if its classification stays FAIL", async () => {
    const result = await executeChecks(
      baseline("/truncated"),
      [mutation("failure")],
      { timeoutMs: 1_000, profile: "quick", language: "en" },
    );
    expect(result.cases[0]).toMatchObject({
      classification: "FAIL",
      response: { status: 503, bodyTruncated: true, timedOut: false },
    });
    expect(result.completedRequests).toBe(result.plannedRequests);
    expect(requests.get("/truncated")).toEqual(["baseline", "failure"]);
    expect(exitCodeForRun(result)).toBe(2);
  });
});
