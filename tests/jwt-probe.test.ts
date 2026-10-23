import { describe, expect, it } from "vitest";
import { createJwtCases, extractBearerJwt } from "../src/jwt-probe.js";
import type { ParsedCurl } from "../src/types.js";

const encodedHeader = Buffer.from(
  JSON.stringify({ alg: "HS256", typ: "JWT" }),
).toString("base64url");
const encodedPayload = Buffer.from(
  JSON.stringify({ sub: "user-123", role: "user", exp: 9999999999 }),
).toString("base64url");
const signature = "SflKxwRJSMeKKF2VT4fwpMJYgStvJCqiT5Uex0";
const validToken = `${encodedHeader}.${encodedPayload}.${signature}`;

const request: ParsedCurl = {
  method: "POST",
  url: "https://api.example.test/orders",
  headers: {
    Authorization: `Bearer ${validToken}`,
    "Content-Type": "application/json",
  },
  body: { itemId: 42 },
};

function decodePayload(token: string): Record<string, unknown> {
  return JSON.parse(
    Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
  );
}

function bearerToken(item: { headers?: Record<string, string> }): string {
  const value = item.headers?.Authorization ?? "";
  return value.slice("Bearer ".length);
}

function require<T>(value: T | undefined, label: string): T {
  if (value === undefined) throw new Error(`missing ${label}`);
  return value;
}

describe("JWT attack probes", () => {
  it("extracts a Bearer JWT from the request headers", () => {
    expect(extractBearerJwt(request)).toEqual({
      headerName: "Authorization",
      token: validToken,
    });
  });

  it("ignores plain bearer credentials that are not JWTs", () => {
    expect(
      extractBearerJwt({
        ...request,
        headers: { Authorization: "Bearer opaque-secret-token" },
      }),
    ).toBeUndefined();
    expect(
      createJwtCases({
        ...request,
        headers: { Authorization: "Bearer opaque-secret-token" },
      }),
    ).toHaveLength(0);
  });

  it("builds alg=none, signature-strip, claim-tamper, and expired variants", () => {
    const cases = createJwtCases(request);
    expect(cases.map((item) => item.kind)).toEqual([
      "jwt-alg-none",
      "jwt-signature-strip",
      "jwt-claim-tamper",
      "jwt-expired",
    ]);
    expect(cases.every((item) => item.category === "authorization")).toBe(true);
    expect(cases.every((item) => item.expectation === "observe")).toBe(true);

    const algNone = require(cases[0], "jwt-alg-none");
    const noneHeader = JSON.parse(
      Buffer.from(
        bearerToken(algNone).split(".")[0] ?? "",
        "base64url",
      ).toString("utf8"),
    );
    expect(noneHeader.alg).toBe("none");
    expect(bearerToken(algNone).endsWith(".")).toBe(true);

    const strip = require(cases[1], "jwt-signature-strip");
    expect(bearerToken(strip)).toBe(`${encodedHeader}.${encodedPayload}.`);

    const tamper = require(cases[2], "jwt-claim-tamper");
    const tamperedPayload = decodePayload(bearerToken(tamper));
    expect(tamperedPayload.sub).toBe("admin");
    expect(tamperedPayload.role).toBe("admin");
    expect(tamperedPayload.exp).toBe(9999999999);
    expect(bearerToken(tamper).endsWith(signature)).toBe(true);

    const expired = require(cases[3], "jwt-expired");
    const expiredPayload = decodePayload(bearerToken(expired));
    expect(expiredPayload.exp).toBe(1);
  });

  it("uses a strict HTTP rejection expectation only when explicitly requested", () => {
    expect(
      createJwtCases(request, true).every(
        (item) => item.expectation === "auth-reject",
      ),
    ).toBe(true);
  });

  it("skips unsigned baselines because payload edits do not invalidate a signature", () => {
    const noneHeader = Buffer.from(
      JSON.stringify({ alg: "none", typ: "JWT" }),
    ).toString("base64url");
    const cases = createJwtCases({
      ...request,
      headers: {
        Authorization: `Bearer ${noneHeader}.${encodedPayload}.`,
      },
    });
    expect(cases).toEqual([]);
  });

  it("does not replay unchanged privileged claims or an unchanged past exp", () => {
    const payload = Buffer.from(
      JSON.stringify({ sub: "admin", role: "admin", roles: ["admin"], exp: 1 }),
    ).toString("base64url");
    const cases = createJwtCases({
      ...request,
      headers: {
        Authorization: `Bearer ${encodedHeader}.${payload}.${signature}`,
      },
    });
    expect(cases.map((item) => item.kind)).toEqual([
      "jwt-alg-none",
      "jwt-signature-strip",
    ]);
  });

  it("does not generate an unchanged signature-strip probe", () => {
    const cases = createJwtCases({
      ...request,
      headers: { Authorization: `Bearer ${encodedHeader}.${encodedPayload}.` },
    });
    expect(cases.some((item) => item.kind === "jwt-signature-strip")).toBe(
      false,
    );
  });

  it("drops claim-tamper when no privileged claim exists and expired when exp is absent", () => {
    const minimalPayload = Buffer.from(
      JSON.stringify({ iss: "issuer" }),
    ).toString("base64url");
    const cases = createJwtCases({
      ...request,
      headers: {
        Authorization: `Bearer ${encodedHeader}.${minimalPayload}.${signature}`,
      },
    });
    expect(cases.map((item) => item.kind)).toEqual([
      "jwt-alg-none",
      "jwt-signature-strip",
    ]);
  });

  it("never mutates the original request", () => {
    createJwtCases(request);
    expect(request.headers.Authorization).toBe(`Bearer ${validToken}`);
    expect(request.body).toEqual({ itemId: 42 });
  });
});
