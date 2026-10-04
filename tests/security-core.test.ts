import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { parseCurl } from "../src/curl.js";
import {
  redactHeaders,
  redactJson,
  redactUrl,
  sanitizeRequest,
} from "../src/redact.js";
import { sendRequest } from "../src/runner.js";

const CANARY = "CANARY_SUPER_SECRET_123";

describe("safe cURL parser", () => {
  it("parses the supported multiline subset as data", () => {
    const parsed = parseCurl(`curl \\
      -X PATCH \\
      'https://api.example.test/users/42' \\
      -H 'Content-Type: application/json' \\
      -H 'X-Trace: test' \\
      --data-raw '{"profile":{"name":"Ada"}}'`);

    expect(parsed).toEqual({
      method: "PATCH",
      url: "https://api.example.test/users/42",
      headers: { "Content-Type": "application/json", "X-Trace": "test" },
      body: { profile: { name: "Ada" } },
    });
  });

  it.each([
    "curl https://api.example.test -d '{}' | touch /tmp/breakcurl-should-not-run",
    "curl https://api.example.test -d '{}' > /tmp/breakcurl-should-not-run",
    "curl $(echo https://api.example.test) -d '{}'",
    "curl $TARGET_URL -d '{}'",
    "curl https://api.example.test -d '{}' --form 'a=b'",
    "curl https://api.example.test -d @payload.json",
    "curl https://api.example.test -H 'X-Test: ok\r\nX-Evil: yes' -d '{}'",
    "curl 'https://api.example.test/items#access_token=FRAGMENT_SECRET_1234'",
    "curl 'https://api.example.test/items#'",
    "curl https://api.example.test -H 'Authorization: Bearer one' -H 'authorization: Bearer two'",
    "curl -X GET https://api.example.test -d '{}'",
  ])("rejects unsupported or shell input: %s", (input) => {
    expect(() => parseCurl(input)).toThrow();
  });

  it("does not execute rejected pipe, redirect, or substitution input", async () => {
    const directory = await mkdtemp(join(tmpdir(), "breakcurl-parser-"));
    try {
      const inputs = [
        `curl https://api.example.test -d '{}' | touch ${join(directory, "pipe")}`,
        `curl https://api.example.test -d '{}' > ${join(directory, "redirect")}`,
        `curl $(touch ${join(directory, "substitution")}) -d '{}'`,
      ];
      for (const unsafeInput of inputs) {
        expect(() => parseCurl(unsafeInput)).toThrow();
      }
      for (const marker of ["pipe", "redirect", "substitution"]) {
        await expect(access(join(directory, marker))).rejects.toThrow();
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("redaction", () => {
  it("drops URL fragments defensively, including percent-encoded values", () => {
    for (const fragment of [
      CANARY,
      `access_token=${CANARY}`,
      encodeURIComponent(CANARY),
    ]) {
      expect(redactUrl(`https://example.test/items#${fragment}`)).not.toContain(
        CANARY,
      );
    }
  });
  it("removes the canary from query, headers, and nested JSON without mutating input", async () => {
    const request = parseCurl(
      `curl -X POST 'https://api.example.test/users?access_token=${CANARY}&page=1' -H 'Authorization: Bearer ${CANARY}' -H 'X-Request-ID: safe' -d '{"password":"${CANARY}","profile":{"api_key":"${CANARY}"}}'`,
    );
    const sanitized = sanitizeRequest(request);
    const rendered = JSON.stringify({
      url: sanitized.url,
      headers: sanitized.headers,
      body: sanitized.body,
    });

    expect(rendered).not.toContain(CANARY);
    expect(sanitized.headers.Authorization).toBe("Bearer <REDACTED>");
    expect(sanitized.url).toContain("access_token=%3CREDACTED%3E");
    expect(sanitized.body).toEqual({
      password: "<REDACTED>",
      profile: { api_key: "<REDACTED>" },
    });
    expect(JSON.stringify(request)).toContain(CANARY);

    const directory = await mkdtemp(join(tmpdir(), "breakcurl-redaction-"));
    const output = join(directory, "sanitized-request.json");
    try {
      await writeFile(output, rendered, "utf8");
      expect(await readFile(output, "utf8")).not.toContain(CANARY);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("preserves safe quoted shell characters as request data", () => {
    const parsed = parseCurl(
      "curl 'https://api.example.test/items?filter=a|b' -d '{\"note\":\"price > 0; `$VALUE`\"}'",
    );
    expect(parsed.url).toContain("filter=a|b");
    expect(parsed.body).toEqual({ note: "price > 0; `$VALUE`" });
  });

  it("supports long options, double quotes, and an unquoted query URL", () => {
    const parsed = parseCurl(
      'curl --request PUT https://api.example.test/items?q=one --header "Content-Type: application/json" --data "{\\"count\\":1}"',
    );
    expect(parsed).toMatchObject({
      method: "PUT",
      url: "https://api.example.test/items?q=one",
      headers: { "Content-Type": "application/json" },
      body: { count: 1 },
    });
  });

  it("accepts typical Copy as cURL options without executing them", () => {
    const parsed = parseCurl(
      `curl --location --compressed --url='https://api.example.test/users' --request=PATCH --cookie='session=abc; tenant=qa' --header='Content-Type: application/json' --data-binary='{"name":"Ada"}'`,
    );

    expect(parsed).toEqual({
      method: "PATCH",
      url: "https://api.example.test/users",
      headers: {
        Cookie: "session=abc; tenant=qa",
        "Content-Type": "application/json",
      },
      body: { name: "Ada" },
    });
  });

  it("applies JSON headers for the cURL --json option", () => {
    const parsed = parseCurl(
      `curl 'https://api.example.test/users' --json '{"name":"Ada"}'`,
    );

    expect(parsed.headers).toEqual({
      "Content-Type": "application/json",
      Accept: "application/json",
    });
    expect(parsed.body).toEqual({ name: "Ada" });
  });

  it("redacts URL credentials and keeps an authorization scheme", () => {
    expect(
      redactUrl(`https://user:${CANARY}@api.example.test/users`),
    ).not.toContain(CANARY);
    expect(redactHeaders({ Authorization: `Bearer ${CANARY}` })).toEqual({
      Authorization: "Bearer <REDACTED>",
    });
  });

  it("redacts case-insensitive headers and leaves safe values intact", () => {
    expect(
      redactHeaders({
        Cookie: CANARY,
        "x-api-key": CANARY,
        Accept: "application/json",
      }),
    ).toEqual({
      Cookie: "<REDACTED>",
      "x-api-key": "<REDACTED>",
      Accept: "application/json",
    });
    expect(redactJson({ nested: [{ sessionToken: CANARY }] })).toEqual({
      nested: [{ sessionToken: "<REDACTED>" }],
    });
    expect(redactUrl(`not a url?secret=${CANARY}`)).not.toContain(CANARY);
  });

  it("tracks an auth secret when it is repeated under a neutral JSON key", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoicWEifQ.signatureABC";
    const sanitized = sanitizeRequest({
      method: "POST",
      url: `https://api.example.test/items?value=${encodeURIComponent(jwt)}`,
      headers: { Authorization: `Bearer ${jwt}` },
      body: { value: jwt, nested: { data: `prefix-${jwt}-suffix` } },
    });
    const rendered = JSON.stringify(sanitized);

    expect(rendered).not.toContain(jwt);
    expect(rendered).toContain("<REDACTED>");
    expect(sanitized.body.value).toBe("<REDACTED>");

    const nestedSecret = sanitizeRequest({
      method: "POST",
      url: "https://api.example.test/items",
      headers: {},
      body: {
        tokens: ["nested-secret-value"],
        neutral: "nested-secret-value",
      },
    });
    expect(nestedSecret.body).toEqual({
      tokens: "<REDACTED>",
      neutral: "<REDACTED>",
    });
  });
});

describe("request runner", () => {
  const requests = new Map<string, number>();
  const server = createServer((request, response) => {
    const path = request.url ?? "/";
    requests.set(path, (requests.get(path) ?? 0) + 1);
    const size = /^\/bytes\/(\d+)$/.exec(path)?.[1];
    if (size) {
      response.writeHead(400, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ data: "x".repeat(Number(size) - 11) }));
      return;
    }
    if (path === "/redirect") {
      response.writeHead(302, { Location: "/destination" });
      response.end("redirect");
      return;
    }
    if (path === "/slow-body") {
      response.writeHead(503, { "Content-Type": "application/json" });
      response.write('{"error":"');
      return;
    }
    if (request.url === "/slow") {
      setTimeout(() => response.end("too late"), 100);
      return;
    }
    response.end("x".repeat(20_000));
  });
  let url = "";

  beforeAll(async () => {
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Test server did not start.");
    url = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  it("enforces the timeout and does not write request data to console", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const result = await sendRequest(
      {
        method: "POST",
        url: `${url}/slow`,
        headers: { Authorization: CANARY },
        body: { secret: CANARY },
      },
      10,
    );

    expect(result).toMatchObject({
      status: 0,
      timedOut: true,
      connectionError: "Request timed out.",
    });
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it("caps the stored response body", async () => {
    const result = await sendRequest(
      { method: "POST", url, headers: {}, body: {} },
      1_000,
    );
    expect(result.status).toBe(200);
    expect(Buffer.byteLength(result.body)).toBe(16_384);
    expect(result.bodyTruncated).toBe(true);
  });

  it.each([16_383, 16_384, 16_385])(
    "distinguishes complete and truncated responses at %i bytes",
    async (bytes) => {
      const result = await sendRequest(
        { method: "POST", url: `${url}/bytes/${bytes}`, headers: {}, body: {} },
        1_000,
      );
      expect(result.status).toBe(400);
      expect(Buffer.byteLength(result.body)).toBe(Math.min(bytes, 16_384));
      expect(result.bodyTruncated).toBe(bytes > 16_384);
      if (!result.bodyTruncated)
        expect(() => JSON.parse(result.body)).not.toThrow();
    },
  );

  it("does not follow redirects or retry requests", async () => {
    const before = requests.get("/redirect") ?? 0;
    const result = await sendRequest(
      { method: "POST", url: `${url}/redirect`, headers: {}, body: {} },
      1_000,
    );
    expect(result.status).toBe(302);
    expect(result.headers.location).toBe("/destination");
    expect((requests.get("/redirect") ?? 0) - before).toBe(1);
    expect(requests.get("/destination") ?? 0).toBe(0);
  });

  it("preserves a received 5xx status when its body times out", async () => {
    const result = await sendRequest(
      { method: "POST", url: `${url}/slow-body`, headers: {}, body: {} },
      100,
    );
    expect(result).toMatchObject({
      status: 503,
      timedOut: true,
      connectionError: "Request timed out.",
    });
    expect(result.headers["content-type"]).toBe("application/json");
    expect(result.bodyTruncated).toBeUndefined();
    expect(requests.get("/slow-body")).toBe(1);
  });

  it("preserves received status on stream errors and does not retry", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error("synthetic stream failure"));
          },
        }),
        { status: 503, headers: { "Content-Type": "application/json" } },
      ),
    );
    try {
      const result = await sendRequest(
        { method: "POST", url: `${url}/stream-error`, headers: {}, body: {} },
        1_000,
      );
      expect(result).toMatchObject({
        status: 503,
        timedOut: false,
        connectionError: "Connection failed.",
      });
      expect(result.bodyTruncated).toBeUndefined();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("cancels immediately after observing bytes past the cap", async () => {
    const cancel = vi.fn();
    let reads = 0;
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        new ReadableStream(
          {
            pull(controller) {
              reads += 1;
              controller.enqueue(
                new Uint8Array(reads === 1 ? 16_384 : 1).fill(120),
              );
            },
            cancel,
          },
          { highWaterMark: 0 },
        ),
      ),
    );
    try {
      const result = await sendRequest(
        {
          method: "POST",
          url: `${url}/infinite-stream`,
          headers: {},
          body: {},
        },
        1_000,
      );
      expect(result.bodyTruncated).toBe(true);
      expect(Buffer.byteLength(result.body)).toBe(16_384);
      expect(reads).toBe(2);
      expect(cancel).toHaveBeenCalledOnce();
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("recalculates content length for a changed JSON body", async () => {
    const result = await sendRequest(
      {
        method: "POST",
        url,
        headers: { "Content-Length": "1" },
        body: { value: "longer mutation" },
      },
      1_000,
    );
    expect(result.status).toBe(200);
  });

  it("drops request-smuggling transport headers before fetch", async () => {
    const result = await sendRequest(
      {
        method: "POST",
        url,
        headers: {
          Host: "evil.example.test",
          "Transfer-Encoding": "chunked",
          "Content-Type": "application/json",
        },
        body: { value: "safe" },
      },
      1_000,
    );
    expect(result.status).toBe(200);
  });
});
