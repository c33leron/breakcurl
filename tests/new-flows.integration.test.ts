import { spawn } from "node:child_process";
import {
  access,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const TOKEN_A = "integration-fixture-bearer-a-293847";
const TOKEN_B = "integration-fixture-bearer-b-829473";
const ACTOR_A = "fixture-principal-alpha";
const ACTOR_B = "fixture-principal-beta";
const CANARY_A = "H4jk8vPa2mxD6yQz9tNs5bCe";
const CANARY_B = "K9rL2eSf6wTy4pXv8qMz3aNd";
const PRIVATE_VALUES = [TOKEN_A, TOKEN_B, ACTOR_A, ACTOR_B, CANARY_A, CANARY_B];
const directories: string[] = [];
interface ReceivedRequest {
  path: string;
  method: string | undefined;
  body: string;
  authorization: string | undefined;
}
const received: ReceivedRequest[] = [];

describe("new installed-style flows", () => {
  let origin = "";
  const server = createServer(async (request, response) => {
    let raw = "";
    for await (const chunk of request) raw += chunk;
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    received.push({
      path,
      method: request.method,
      body: raw,
      authorization: request.headers.authorization,
    });
    response.setHeader("Content-Type", "application/json");
    const actor =
      request.headers.authorization === `Bearer ${TOKEN_A}`
        ? ACTOR_A
        : request.headers.authorization === `Bearer ${TOKEN_B}`
          ? ACTOR_B
          : undefined;
    if (path === "/quick" || path === "/get") {
      response.statusCode = actor ? 200 : 401;
      response.end(
        JSON.stringify(actor ? { accepted: true } : { error: "unauthorized" }),
      );
      return;
    }
    if (!actor) {
      response.statusCode = 401;
      response.end('{"error":"unauthorized"}');
      return;
    }
    const [, scenario, resource, objectId] = path.split("/");
    if (resource === "me") {
      if (scenario === "rate-limit" && actor === ACTOR_B) {
        response.statusCode = 429;
        response.setHeader("Retry-After", "60");
        response.end('{"error":"rate limited"}');
      } else {
        response.end(
          JSON.stringify({
            id: scenario === "bad-principal" ? "different-principal" : actor,
          }),
        );
      }
      return;
    }
    if (
      resource === "objects" &&
      (objectId === "alpha" || objectId === "beta")
    ) {
      const owns =
        actor === ACTOR_A ? objectId === "alpha" : objectId === "beta";
      if (scenario !== "vulnerable" && !owns) {
        response.statusCode = 403;
        response.end('{"error":"forbidden"}');
      } else {
        response.end(
          JSON.stringify({
            id: objectId,
            privateMarker: objectId === "alpha" ? CANARY_A : CANARY_B,
          }),
        );
      }
      return;
    }
    response.statusCode = 404;
    response.end('{"error":"not found"}');
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
    await Promise.all(
      directories.map((directory) =>
        rm(directory, { recursive: true, force: true }),
      ),
    );
  });

  it("runs auth probes in default quick and reserves the remaining 15-case budget for body checks", async () => {
    const fixture = await writeQuickFixture(origin);
    const before = received.length;
    const result = await runCli(
      [
        fixture.input,
        "--allow-mutation",
        "--no-color",
        "--output",
        fixture.output,
      ],
      fixture.directory,
    );
    expect(result.code).toBe(0);
    const requests = received.slice(before);
    expect(requests).toHaveLength(16);
    expect(requests[0]?.authorization).toBe(`Bearer ${TOKEN_A}`);
    expect(requests[1]?.authorization).toBeUndefined();
    expect(requests[2]?.authorization).toBe(
      "Bearer BREAKCURL_INVALID_CREDENTIAL",
    );
    expect(
      requests
        .slice(3)
        .every((item) => item.authorization === `Bearer ${TOKEN_A}`),
    ).toBe(true);
    expect(
      requests.slice(3).some((item) => item.body !== requests[0]?.body),
    ).toBe(true);
    const report = JSON.parse(
      await readFile(join(fixture.output, "report.json"), "utf8"),
    );
    expect(report.cases).toHaveLength(15);
    expect(
      report.cases
        .slice(0, 2)
        .map((item: { category: string }) => item.category),
    ).toEqual(["authentication", "authentication"]);
    expect(report.completedRequests).toBe(16);
    expect(await outputText(result, fixture.output)).not.toContain(TOKEN_A);
  });

  it("sends GET without a request body in both baseline and auth probes", async () => {
    const directory = await temporaryDirectory();
    const input = join(directory, "get.curl");
    const output = join(directory, "output");
    await writeFile(input, getCurl(`${origin}/get`, TOKEN_A));
    const before = received.length;
    const result = await runCli(
      [input, "--allow-mutation", "--no-color", "--output", output],
      directory,
    );
    expect(result.code).toBe(0);
    expect(received.slice(before)).toHaveLength(3);
    expect(
      received
        .slice(before)
        .every((item) => item.method === "GET" && item.body === ""),
    ).toBe(true);
  });

  it("requires authorization before noninteractive ordinary and IDOR traffic", async () => {
    const quick = await writeQuickFixture(origin);
    const idor = await writeIdorFixture(origin, "protected");
    const before = received.length;
    for (const fixture of [
      {
        args: [quick.input, "--no-color", "--output", quick.output],
        directory: quick.directory,
        output: quick.output,
      },
      {
        args: [...idor.args, "--no-color"],
        directory: idor.directory,
        output: idor.output,
      },
    ]) {
      const result = await runCli(fixture.args, fixture.directory);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("--allow-mutation");
      await expect(access(fixture.output)).rejects.toThrow();
    }
    expect(received.length).toBe(before);
  });

  it("validates and shows an IDOR dry-run without requests or output files", async () => {
    const fixture = await writeIdorFixture(origin, "protected");
    const before = received.length;
    const result = await runCli(
      [...fixture.args, "--dry-run", "--no-color"],
      fixture.directory,
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("0 requests");
    expect(received.length).toBe(before);
    await expect(access(fixture.output)).rejects.toThrow();
    for (const value of PRIVATE_VALUES)
      expect(`${result.stdout}\n${result.stderr}`).not.toContain(value);
  });

  it.each([
    ["protected", 0, "PASS"],
    ["vulnerable", 1, "FAIL"],
  ] as const)(
    "runs the %s IDOR fixture with exactly five ordered requests",
    async (scenario, code, verdict) => {
      const fixture = await writeIdorFixture(origin, scenario);
      const before = received.length;
      const result = await runCli(
        [
          ...fixture.args,
          "--allow-mutation",
          "--junit",
          "--sarif",
          "--no-color",
        ],
        fixture.directory,
      );
      expect(result.code).toBe(code);
      expect(
        received.slice(before).map((item) => [item.path, item.authorization]),
      ).toEqual([
        [`/${scenario}/me`, `Bearer ${TOKEN_A}`],
        [`/${scenario}/me`, `Bearer ${TOKEN_B}`],
        [`/${scenario}/objects/alpha`, `Bearer ${TOKEN_A}`],
        [`/${scenario}/objects/beta`, `Bearer ${TOKEN_B}`],
        [`/${scenario}/objects/beta`, `Bearer ${TOKEN_A}`],
      ]);
      expect(
        received
          .slice(before)
          .every((item) => item.method === "GET" && item.body === ""),
      ).toBe(true);
      const report = JSON.parse(
        await readFile(join(fixture.output, "report.json"), "utf8"),
      );
      expect(report.mode).toBe("idor");
      expect(report.completedRequests).toBe(5);
      expect(report.cases.at(-1).classification).toBe(verdict);
      if (scenario === "vulnerable") {
        expect(report.cases.at(-1).securitySignals).toEqual(
          expect.arrayContaining([expect.objectContaining({ cwe: "CWE-639" })]),
        );
        const sarif = JSON.parse(
          await readFile(join(fixture.output, "sarif.json"), "utf8"),
        );
        expect(JSON.stringify(sarif)).toContain("CWE-639");
      }
      const text = await outputText(result, fixture.output);
      for (const value of PRIVATE_VALUES) expect(text).not.toContain(value);
      for (const filename of [
        "report.html",
        "report.md",
        "report.json",
        "junit.xml",
        "sarif.json",
      ])
        await expect(
          access(join(fixture.output, filename)),
        ).resolves.toBeUndefined();
    },
  );

  it.each([
    ["bad-principal", 1],
    ["rate-limit", 2],
  ] as const)(
    "stops after the %s control without sending the cross-account request",
    async (scenario, count) => {
      const fixture = await writeIdorFixture(origin, scenario);
      const before = received.length;
      const result = await runCli(
        [...fixture.args, "--allow-mutation", "--no-color"],
        fixture.directory,
      );
      expect(result.code).toBe(2);
      expect(received.slice(before)).toHaveLength(count);
      expect(
        received.slice(before).every((item) => item.path === `/${scenario}/me`),
      ).toBe(true);
      const report = JSON.parse(
        await readFile(join(fixture.output, "report.json"), "utf8"),
      );
      expect(report.completedRequests).toBe(count);
      expect(JSON.stringify(report)).toContain("ERROR");
      expect(
        report.cases.some(
          (item: { id: string }) => item.id === "idor-cross-a-to-b",
        ),
      ).toBe(false);
      if (scenario === "rate-limit")
        expect(JSON.stringify(report)).toContain("429");
      const text = await outputText(result, fixture.output);
      for (const value of PRIVATE_VALUES) expect(text).not.toContain(value);
    },
  );

  it("rejects an inapplicable generic IDOR request budget before network traffic", async () => {
    const fixture = await writeIdorFixture(origin, "protected");
    const before = received.length;
    const result = await runCli(
      [...fixture.args, "--max-cases", "1", "--allow-mutation", "--no-color"],
      fixture.directory,
    );
    expect(result.code).toBe(2);
    expect(`${result.stdout}\n${result.stderr}`).toContain("max-cases");
    expect(received.length).toBe(before);
    await expect(access(fixture.output)).rejects.toThrow();
  });

  it("does not create any output directory for demo --dry-run", async () => {
    const directory = await temporaryDirectory();
    const output = join(directory, "demo-output");
    const result = await runCli(
      ["demo", "--dry-run", "--output", output, "--no-color"],
      directory,
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("0 requests");
    await expect(access(output)).rejects.toThrow();
    expect(await readdir(directory)).toEqual([]);
  });
});

function getCurl(url: string, token: string): string {
  return `curl '${url}' -H 'Authorization: Bearer ${token}' -H 'Accept: application/json'`;
}

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "breakcurl-new-flows-"));
  directories.push(directory);
  return directory;
}

async function writeQuickFixture(origin: string) {
  const directory = await temporaryDirectory();
  const input = join(directory, "request.curl");
  const output = join(directory, "output");
  await writeFile(
    input,
    `curl '${origin}/quick' -H 'Authorization: Bearer ${TOKEN_A}' -H 'Content-Type: application/json' --data-raw '{"name":"Fixture","amount":3,"active":true,"description":"Synthetic data"}'`,
  );
  return { directory, input, output };
}

async function writeIdorFixture(origin: string, scenario: string) {
  const directory = await temporaryDirectory();
  const a = join(directory, "actor-a.curl");
  const b = join(directory, "actor-b.curl");
  const config = join(directory, "idor.json");
  const output = join(directory, "output");
  await Promise.all([
    writeFile(a, getCurl(`${origin}/${scenario}/objects/alpha`, TOKEN_A)),
    writeFile(b, getCurl(`${origin}/${scenario}/objects/beta`, TOKEN_B)),
    writeFile(
      config,
      JSON.stringify({
        authModel: "bearer-only",
        objectIdsGrantAccess: false,
        rule: "a-cannot-read-b",
        privateCanaries: true,
        identity: {
          url: `${origin}/${scenario}/me`,
          principalPointer: "/id",
          actorA: ACTOR_A,
          actorB: ACTOR_B,
        },
        objects: {
          pathTemplate: `/${scenario}/objects/{objectId}`,
          idPointer: "/id",
          canaryPointer: "/privateMarker",
          objectA: { id: "alpha", canary: CANARY_A },
          objectB: { id: "beta", canary: CANARY_B },
        },
      }),
    ),
  ]);
  return {
    directory,
    output,
    args: ["idor", a, b, "--config", config, "--output", output],
  };
}

function runCli(
  args: string[],
  cwd: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, BREAKCURL_LANG: "en" },
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end();
  });
}

async function outputText(
  result: { stdout: string; stderr: string },
  output: string,
): Promise<string> {
  return `${result.stdout}\n${result.stderr}\n${await readFiles(output)}`;
}

async function readFiles(directory: string): Promise<string> {
  const entries = await readdir(directory, { withFileTypes: true });
  const text = await Promise.all(
    entries.map(async (entry) =>
      entry.isDirectory()
        ? readFiles(join(directory, entry.name))
        : `${entry.name}\n${await readFile(join(directory, entry.name), "utf8")}`,
    ),
  );
  return text.join("\n");
}
