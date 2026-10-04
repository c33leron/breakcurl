import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildDeclaredAuthProbes,
  collectAuthContractSecrets,
  parseAuthContract,
} from "../src/auth-contract.js";
import { classifyCase } from "../src/classify.js";
import { loadConfig } from "../src/config.js";
import { executeChecks } from "../src/execute.js";
import { generateChecks, requestForCase } from "../src/mutations.js";
import { sendRequest } from "../src/runner.js";
import type { ParsedCurl } from "../src/types.js";

const ticket = "opaque-fixture-credential";
const request: ParsedCurl = {
  method: "POST",
  url: "https://api.example.test/items",
  headers: {
    Authorization: "Bearer header-fixture",
    "Content-Type": "application/json",
  },
  body: { ticket, amount: 1 },
};
const contract = parseAuthContract({
  complete: true,
  sources: [
    { in: "header", name: "Authorization" },
    { in: "json", pointer: "/ticket" },
  ],
});

describe("complete auth source contract", () => {
  it("removes and invalidates every declared source together without changing the original", () => {
    const result = buildDeclaredAuthProbes(request, contract);
    expect(result.missing.headers).not.toHaveProperty("Authorization");
    expect(result.missing.body).toEqual({ amount: 1 });
    expect(result.invalid.headers.Authorization).toBe(
      "Bearer BREAKCURL_INVALID_CREDENTIAL",
    );
    expect(result.invalid.body).toEqual({
      ticket: "BREAKCURL_INVALID_CREDENTIAL",
      amount: 1,
    });
    expect(request.headers.Authorization).toBe("Bearer header-fixture");
    expect(request.body.ticket).toBe(ticket);
    expect(result.sources).toEqual(["header:Authorization", "json:/ticket"]);
  });

  it("supports opaque body-only auth and escaped object-property pointers", () => {
    const bodyOnly = {
      ...request,
      headers: {},
      body: { "opaque/key": { "~ticket": ticket }, amount: 1 },
    };
    const result = buildDeclaredAuthProbes(
      bodyOnly,
      parseAuthContract({
        complete: true,
        sources: [{ in: "json", pointer: "/opaque~1key/~0ticket" }],
      }),
    );
    expect(result.missing.body).toEqual({ "opaque/key": {}, amount: 1 });
    expect(result.invalid.body).toEqual({
      "opaque/key": { "~ticket": "BREAKCURL_INVALID_CREDENTIAL" },
      amount: 1,
    });
  });

  it("handles arbitrary query and header source names, and whole Cookie headers", () => {
    const result = buildDeclaredAuthProbes(
      {
        ...request,
        url: `${request.url}?ticket=query-fixture&mode=test`,
        headers: {
          "X-Ticket": "header-fixture",
          Cookie: "session=cookie-fixture; tenant=tenant-fixture",
        },
        body: { amount: 1 },
      },
      parseAuthContract({
        complete: true,
        sources: [
          { in: "header", name: "x-ticket" },
          { in: "header", name: "COOKIE" },
          { in: "query", name: "ticket" },
        ],
      }),
    );
    expect(result.missing.headers).toEqual({});
    expect(result.missing.url).toBe(`${request.url}?mode=test`);
    expect(result.invalid.headers).toEqual({
      "X-Ticket": "BREAKCURL_INVALID_CREDENTIAL",
      Cookie: "breakcurl_invalid=1",
    });
    expect(new URL(result.invalid.url).searchParams.get("ticket")).toBe(
      "BREAKCURL_INVALID_CREDENTIAL",
    );
    expect(result.knownSecrets).toEqual(
      expect.arrayContaining([
        "query-fixture",
        "header-fixture",
        "cookie-fixture",
        "tenant-fixture",
      ]),
    );
  });

  it("collects declared opaque credentials including short values for every output channel", () => {
    expect(collectAuthContractSecrets(request, contract)).toEqual(
      expect.arrayContaining([
        ticket,
        "Bearer header-fixture",
        "header-fixture",
      ]),
    );
    expect(
      collectAuthContractSecrets(
        { ...request, headers: {}, body: { ticket: "xy" } },
        parseAuthContract({
          complete: true,
          sources: [{ in: "json", pointer: "/ticket" }],
        }),
      ),
    ).toEqual(["xy"]);
  });

  it.each([
    { complete: false, sources: [{ in: "header", name: "Authorization" }] },
    { complete: true, sources: [] },
    { complete: true, sources: [{ in: "path", name: "ticket" }] },
    {
      complete: true,
      sources: [{ in: "header", name: "Authorization", value: ticket }],
    },
    { complete: true, sources: [{ in: "header", name: "Content-Length" }] },
    { complete: true, sources: [{ in: "json", pointer: "ticket" }] },
    { complete: true, sources: [{ in: "json", pointer: "/bad~2pointer" }] },
    { complete: true, sources: [{ in: "json", pointer: "/__proto__/ticket" }] },
    {
      complete: true,
      sources: [{ in: "json", pointer: "/constructor/ticket" }],
    },
  ])(
    "rejects unsupported declarations before request processing: %j",
    (value) => {
      expect(() => parseAuthContract(value)).toThrow();
    },
  );

  it.each([
    [
      { in: "header", name: "Authorization" },
      { in: "header", name: "authorization" },
    ],
    [
      { in: "query", name: "ticket" },
      { in: "query", name: "ticket" },
    ],
    [
      { in: "json", pointer: "/ticket" },
      { in: "json", pointer: "/ticket" },
    ],
    [
      { in: "json", pointer: "/opaque" },
      { in: "json", pointer: "/opaque/ticket" },
    ],
    [
      { in: "json", pointer: "/opaque~1key" },
      { in: "json", pointer: "/opaque~1key/ticket" },
    ],
  ])("rejects duplicate and overlapping sources: %j", (...sources) => {
    expect(() => parseAuthContract({ complete: true, sources })).toThrow(
      /Duplicate|Overlapping/,
    );
  });

  it("rejects absent and ambiguous actual request sources", () => {
    expect(() =>
      buildDeclaredAuthProbes({ ...request, body: { amount: 1 } }, contract),
    ).toThrow("missing");
    expect(() =>
      buildDeclaredAuthProbes(
        {
          ...request,
          headers: { Authorization: "Bearer a", authorization: "Bearer b" },
        },
        contract,
      ),
    ).toThrow("duplicated");
    const queryContract = parseAuthContract({
      complete: true,
      sources: [{ in: "query", name: "ticket" }],
    });
    expect(() =>
      buildDeclaredAuthProbes(
        {
          ...request,
          headers: {},
          body: {},
          url: `${request.url}?ticket=a&ticket=b`,
        },
        queryContract,
      ),
    ).toThrow("duplicated");
  });

  it.each([null, 1, false, "", [], { value: "opaque" }])(
    "rejects non-string or empty JSON credentials: %j",
    (value) => {
      expect(() =>
        buildDeclaredAuthProbes(
          { ...request, body: { ticket: value } },
          contract,
        ),
      ).toThrow("non-empty strings");
    },
  );

  it("rejects array traversal and undeclared obvious credentials", () => {
    expect(() =>
      buildDeclaredAuthProbes(
        { ...request, headers: {}, body: { tickets: [ticket] } },
        parseAuthContract({
          complete: true,
          sources: [{ in: "json", pointer: "/tickets/0" }],
        }),
      ),
    ).toThrow("non-object");
    expect(() =>
      buildDeclaredAuthProbes(
        { ...request, body: { ticket, access_token: "another-secret" } },
        contract,
      ),
    ).toThrow("undeclared");
    expect(() =>
      buildDeclaredAuthProbes(
        request,
        parseAuthContract({
          complete: true,
          sources: [{ in: "json", pointer: "/ticket" }],
        }),
      ),
    ).toThrow("undeclared");
    const nested = buildDeclaredAuthProbes(
      { ...request, headers: {}, body: { auth: { token: ticket } } },
      parseAuthContract({
        complete: true,
        sources: [{ in: "json", pointer: "/auth/token" }],
      }),
    );
    expect(nested.missing.body).toEqual({ auth: {} });
  });

  it.each(["header", "query", "json"] as const)(
    "rejects undeclared opaque %s alternatives containing known credential representations",
    (channel) => {
      const credential = 'opaque-fixture+/"credential';
      const representations = [
        credential,
        encodeURIComponent(credential),
        [...Buffer.from(credential)]
          .map((byte) => `%${byte.toString(16)}`)
          .join(""),
        JSON.stringify(credential).slice(1, -1),
        Buffer.from(credential).toString("base64"),
        Buffer.from(credential).toString("base64url"),
      ];
      const headerOnly = parseAuthContract({
        complete: true,
        sources: [{ in: "header", name: "Authorization" }],
      });
      for (const value of representations) {
        const alternate: ParsedCurl = {
          ...request,
          headers: { Authorization: `Bearer ${credential}` },
          body: { amount: 1 },
        };
        if (channel === "header") alternate.headers["X-Ticket"] = value;
        if (channel === "json") alternate.body.opaque = value;
        if (channel === "query") {
          const url = new URL(alternate.url);
          url.searchParams.set("ticket", value);
          alternate.url = url.toString();
        }
        let failure: unknown;
        try {
          buildDeclaredAuthProbes(alternate, headerOnly);
        } catch (error) {
          failure = error;
        }
        expect(failure).toBeInstanceOf(Error);
        expect((failure as Error).message).toContain("undeclared");
        expect((failure as Error).message).not.toContain(credential);
        expect((failure as Error).message).not.toContain(value);
      }
    },
  );

  it("rejects partially declared alternate channels before traffic and evaluates fully declared alternatives", async () => {
    let count = 0;
    const server = createServer(async (req, res) => {
      count += 1;
      for await (const _chunk of req) {
        /* consume the synthetic request */
      }
      const url = new URL(req.url ?? "/", "http://localhost");
      const authorized =
        req.headers.authorization === `Bearer ${ticket}` ||
        req.headers["x-ticket"] === ticket ||
        url.searchParams.get("ticket") === ticket;
      res.setHeader("Content-Type", "application/json");
      res.statusCode = authorized ? 200 : 401;
      res.end(JSON.stringify({ authorized }));
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    try {
      const address = server.address();
      if (!address || typeof address === "string")
        throw new Error("No local address");
      const local: ParsedCurl = {
        ...request,
        url: `http://127.0.0.1:${address.port}/items?ticket=${ticket}`,
        headers: { Authorization: `Bearer ${ticket}`, "X-Ticket": ticket },
        body: { amount: 1 },
      };
      const sources = [
        { in: "header", name: "Authorization" },
        { in: "header", name: "X-Ticket" },
        { in: "query", name: "ticket" },
      ];
      for (const subset of [
        sources.slice(0, 1),
        sources.slice(0, 2),
        [sources[0], sources[2]],
      ]) {
        const run = async () => {
          const checks = generateChecks(local, {
            profile: "quick",
            maxCases: 2,
            expectAuth: true,
            authContract: parseAuthContract({
              complete: true,
              sources: subset,
            }),
          });
          return executeChecks(local, checks.cases, {
            timeoutMs: 1_000,
            profile: "quick",
            language: "en",
          });
        };
        await expect(run()).rejects.toThrow("undeclared");
        expect(count).toBe(0);
      }
      const checks = generateChecks(local, {
        profile: "quick",
        maxCases: 2,
        expectAuth: true,
        authContract: parseAuthContract({ complete: true, sources }),
      });
      const result = await executeChecks(local, checks.cases, {
        timeoutMs: 1_000,
        profile: "quick",
        language: "en",
      });
      expect(result.baseline.response.status).toBe(200);
      expect(
        result.cases.map((item) => [item.response.status, item.classification]),
      ).toEqual([
        [401, "PASS"],
        [401, "PASS"],
      ]);
      expect(count).toBe(3);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("changes sources even when the working credential equals the invalid marker", () => {
    const result = buildDeclaredAuthProbes(
      {
        ...request,
        headers: { Authorization: "Bearer BREAKCURL_INVALID_CREDENTIAL" },
        body: { ticket: "BREAKCURL_INVALID_CREDENTIAL" },
      },
      contract,
    );
    expect(result.invalid.headers.Authorization).not.toBe(
      "Bearer BREAKCURL_INVALID_CREDENTIAL",
    );
    expect(result.invalid.body.ticket).not.toBe("BREAKCURL_INVALID_CREDENTIAL");
  });

  it("loads an inline contract and ships a locations-only example", async () => {
    const directory = await mkdtemp(join(tmpdir(), "breakcurl-auth-config-"));
    try {
      const filename = join(directory, "config.json");
      await writeFile(filename, JSON.stringify({ authContract: contract }));
      expect((await loadConfig(filename)).authContract).toEqual(contract);
      const example = JSON.parse(
        await readFile(
          new URL("../breakcurl.auth.example.json", import.meta.url),
          "utf8",
        ),
      );
      expect(parseAuthContract(example)).toEqual(contract);
      expect(JSON.stringify(example)).not.toContain(ticket);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("makes both probes unauthenticated against an endpoint with alternate header/body authority", async () => {
    let count = 0;
    const server = createServer(async (req, res) => {
      count += 1;
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw);
      res.setHeader("Content-Type", "application/json");
      res.statusCode =
        req.headers.authorization === request.headers.Authorization ||
        body.ticket === ticket
          ? 200
          : 401;
      res.end(JSON.stringify({ ok: res.statusCode === 200 }));
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    try {
      const address = server.address();
      if (!address || typeof address === "string")
        throw new Error("No local address");
      const local = {
        ...request,
        url: `http://127.0.0.1:${address.port}/items`,
      };
      expect((await sendRequest(local, 1000)).status).toBe(200);
      const checks = generateChecks(local, {
        profile: "quick",
        maxCases: 2,
        expectAuth: true,
        authContract: contract,
      }).cases;
      expect(checks).toHaveLength(2);
      for (const mutation of checks) {
        const response = await sendRequest(
          requestForCase(local, mutation),
          1000,
        );
        expect(response.status).toBe(401);
        expect(classifyCase(mutation, response).classification).toBe("PASS");
      }
      expect(count).toBe(3);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
