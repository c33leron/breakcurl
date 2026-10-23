import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { executeChecks } from "../src/execute.js";
import { englishText } from "../src/i18n.js";
import { generateChecks } from "../src/mutations.js";
import { sendRequest } from "../src/runner.js";
import type { ParsedCurl } from "../src/types.js";

const KEY = "synthetic-jwt-regression-signing-key";
const COOKIE = "sid=synthetic-jwt-regression-session";
const servers: Server[] = [];

function sign(payload: Record<string, unknown>): string {
  const input = [{ alg: "HS256", typ: "JWT" }, payload]
    .map((part) => Buffer.from(JSON.stringify(part)).toString("base64url"))
    .join(".");
  return `${input}.${createHmac("sha256", KEY).update(input).digest("base64url")}`;
}

function validSignature(token: string): boolean {
  const [header, payload, signature] = token.split(".");
  if (!header || !payload || !signature) return false;
  return (
    signature ===
    createHmac("sha256", KEY).update(`${header}.${payload}`).digest("base64url")
  );
}

async function fixture(allowCookie: boolean) {
  const acceptedVia: string[] = [];
  const server = createServer(async (request, response) => {
    for await (const _chunk of request) {
      /* drain the bounded fixture body */
    }
    const token = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
    // This fixture deliberately verifies signatures but ignores expiry.
    const signatureOk = validSignature(token);
    const cookieOk = allowCookie && request.headers.cookie === COOKIE;
    const ok = signatureOk || cookieOk;
    acceptedVia.push(
      signatureOk ? "signature" : cookieOk ? "cookie" : "denied",
    );
    response.writeHead(ok ? 200 : 401, { "Content-Type": "application/json" });
    response.end(
      JSON.stringify(ok ? { accepted: true } : { error: "unauthorized" }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("No fixture address");
  const request: ParsedCurl = {
    method: "POST",
    url: `http://127.0.0.1:${address.port}/orders`,
    headers: {
      Authorization: `Bearer ${sign({ sub: "fixture-user", role: "user", exp: 9999999999 })}`,
      "Content-Type": "application/json",
      ...(allowCookie ? { Cookie: COOKIE } : {}),
    },
    body: { itemId: 42 },
  };
  return { request, acceptedVia };
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => {
      server.closeAllConnections();
      return new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }),
  );
});

describe("JWT controls over real HTTP", () => {
  it("does not report a signature bypass when a valid alternate session explains success", async () => {
    const { request, acceptedVia } = await fixture(true);
    const plan = generateChecks(request, {
      profile: "security",
      maxCases: 6,
      expectAuth: true,
      authContract: {
        complete: true,
        sources: [
          { in: "header", name: "Authorization" },
          { in: "header", name: "Cookie" },
        ],
      },
    });
    const result = await executeChecks(request, plan.cases, {
      profile: "security",
      language: "en",
      timeoutMs: 1000,
    });
    const jwtCases = result.cases.filter((item) =>
      item.mutation.kind.startsWith("jwt-"),
    );
    expect(jwtCases).toHaveLength(4);
    expect(
      jwtCases.every(
        (item) =>
          item.classification === "WARN" && item.confidence === "MEDIUM",
      ),
    ).toBe(true);
    expect(result.cases.slice(0, 2).map((item) => item.classification)).toEqual(
      ["PASS", "PASS"],
    );
    expect(acceptedVia).toEqual([
      "signature",
      "denied",
      "denied",
      "cookie",
      "cookie",
      "cookie",
      "cookie",
    ]);
  });

  it("does not call expiry enforced when an expiry-ignoring verifier rejects the broken signature", async () => {
    const { request } = await fixture(false);
    const plan = generateChecks(request, {
      profile: "security",
      maxCases: 6,
      expectAuth: true,
      authContract: {
        complete: true,
        sources: [{ in: "header", name: "Authorization" }],
      },
    });
    const result = await executeChecks(request, plan.cases, {
      profile: "security",
      language: "en",
      timeoutMs: 1000,
    });
    const expiry = result.cases.find(
      (item) => item.mutation.kind === "jwt-expired",
    );
    expect(expiry?.response.status).toBe(401);
    expect(expiry?.classification).toBe("INFO");
    expect(englishText(expiry?.reason ?? "")).toContain(
      "expiry enforcement was not assessed",
    );
    const control = await sendRequest(
      {
        ...request,
        headers: {
          ...request.headers,
          Authorization: `Bearer ${sign({ sub: "fixture-user", exp: 1 })}`,
        },
      },
      1000,
    );
    expect(control.status).toBe(200);
  });
});
