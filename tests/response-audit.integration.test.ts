import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { auditResponseHeaders } from "../src/classify.js";
import { sendRequest } from "../src/runner.js";
import type { HttpResult, ParsedCurl } from "../src/types.js";

const servers: Server[] = [];
const request: ParsedCurl = {
  method: "GET",
  url: "https://example.test/",
  headers: {},
  body: {},
};
const response: HttpResult = {
  status: 200,
  headers: {},
  body: "{}",
  latencyMs: 1,
  timedOut: false,
};

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

describe("response configuration evidence", () => {
  it.each([false, true])(
    "checks every Set-Cookie when insecure cookie is last: %s",
    async (unsafeLast) => {
      const cookies = [
        "unsafe=synthetic; Path=/",
        "safe=synthetic; Secure; HttpOnly",
      ];
      const server = createServer((_request, response) => {
        response.writeHead(200, {
          "Set-Cookie": unsafeLast ? [...cookies].reverse() : cookies,
        });
        response.end("{}");
      });
      servers.push(server);
      await new Promise<void>((resolve) =>
        server.listen(0, "127.0.0.1", resolve),
      );
      const address = server.address();
      if (!address || typeof address === "string")
        throw new Error("No fixture address");
      const actualRequest = {
        ...request,
        url: `http://127.0.0.1:${address.port}/`,
      };
      const actualResponse = await sendRequest(actualRequest, 1000);
      expect(actualResponse.headers["set-cookie"]?.split("\n")).toHaveLength(2);
      expect(
        auditResponseHeaders(actualRequest, actualResponse),
      ).toContainEqual(expect.objectContaining({ id: "cookie-flags-missing" }));
    },
  );

  it.each([
    "",
    "max-age=0",
    "max-age=invalid",
    "includeSubDomains",
    "max-age=1; max-age=0",
  ])("does not treat %j as an enabled HSTS policy", (hsts) => {
    expect(
      auditResponseHeaders(request, {
        ...response,
        headers: { "strict-transport-security": hsts },
      }),
    ).toContainEqual(
      expect.objectContaining({ id: "hsts-missing", severity: "LOW" }),
    );
  });

  it.each(["max-age=31536000; includeSubDomains", 'max-age="60"'])(
    "accepts positive HSTS policy %j",
    (hsts) => {
      expect(
        auditResponseHeaders(request, {
          ...response,
          headers: { "strict-transport-security": hsts },
        }),
      ).toEqual([]);
    },
  );
});
