import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseCurl } from "../src/curl.js";
import { sendRequest } from "../src/runner.js";

describe("vertical flow", () => {
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const payload = JSON.parse(body) as { age: number | null };
      response.statusCode = payload.age === null ? 500 : 201;
      response.end(JSON.stringify({ ok: payload.age !== null }));
    });
  });

  let url = "";

  beforeAll(async () => {
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Demo server did not start.");
    url = `http://127.0.0.1:${address.port}/users`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  it("runs a successful baseline and observes a 500 for age=null", async () => {
    const parsed = parseCurl(
      `curl -X POST '${url}' -H 'Content-Type: application/json' -d '{"email":"qa@example.com","age":30}'`,
    );
    const baseline = await sendRequest(parsed, 1_000);
    expect(baseline.status).toBe(201);

    const mutation = structuredClone(parsed);
    mutation.body.age = null;
    const negative = await sendRequest(mutation, 1_000);
    expect(negative.status).toBe(500);
  });
});
