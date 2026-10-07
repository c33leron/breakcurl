import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const TEST_TOKEN = "user-journey-owned-bearer-83746";
const PRIVATE_RECEIPT = "response-only-private-receipt-72918";
const ACTOR_ID = "synthetic-owner-alpha";
const PAYLOAD = { title: "Disposable acceptance record", quantity: 1 };
const temporaryDirectories: string[] = [];

interface StoredRecord {
  id: string;
  ownerId: string | null;
  body: unknown;
}

interface RequestEvidence {
  method: string | undefined;
  authorization: string | undefined;
  body: unknown;
  status: number;
  recordsBefore: number;
  recordsAfter: number;
}

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

describe("first-user CLI acceptance against a stateful API", () => {
  const users = new Map([[TEST_TOKEN, { id: ACTOR_ID }]]);
  const records = new Map<string, StoredRecord[]>();
  const requests = new Map<string, RequestEvidence[]>();
  let origin = "";

  const server = createServer(async (request, response) => {
    let rawBody = "";
    for await (const chunk of request) rawBody += chunk;
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    const state = records.get(path) ?? [];
    const evidence = requests.get(path) ?? [];
    records.set(path, state);
    requests.set(path, evidence);
    let body: unknown;
    try {
      body = JSON.parse(rawBody);
    } catch {
      body = null;
    }
    const authorization = request.headers.authorization;
    const token = authorization?.startsWith("Bearer ")
      ? authorization.slice("Bearer ".length)
      : undefined;
    const actor = token ? users.get(token) : undefined;
    const recordsBefore = state.length;
    response.setHeader("Content-Type", "application/json");

    if (request.method !== "POST") {
      response.statusCode = 405;
      response.end('{"error":"method not allowed"}');
    } else if (path === "/broken/records") {
      response.statusCode = 500;
      response.end('{"error":"fixture unavailable"}');
    } else if (path === "/protected/records" && !actor) {
      response.statusCode = 401;
      response.end('{"error":"authentication required"}');
    } else if (
      ["/protected/records", "/vulnerable/records", "/public/records"].includes(
        path,
      )
    ) {
      const record = {
        id: `record-${state.length + 1}`,
        ownerId: actor?.id ?? null,
        body,
      };
      state.push(record);
      response.statusCode = 201;
      response.end(
        JSON.stringify({
          id: record.id,
          ownerId: record.ownerId,
          receipt: PRIVATE_RECEIPT,
        }),
      );
    } else {
      response.statusCode = 404;
      response.end('{"error":"not found"}');
    }
    evidence.push({
      method: request.method,
      authorization,
      body,
      status: response.statusCode,
      recordsBefore,
      recordsAfter: state.length,
    });
  });

  beforeAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("The stateful localhost fixture did not start.");
    origin = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    await Promise.all(
      temporaryDirectories.map((directory) =>
        rm(directory, { recursive: true, force: true }),
      ),
    );
  });

  async function runJourney(path: string, expectAuth = true) {
    const directory = await mkdtemp(join(tmpdir(), "breakcurl-journey-"));
    temporaryDirectories.push(directory);
    const input = join(directory, "request.curl");
    const contract = join(directory, "auth.json");
    const output = join(directory, "report");
    await Promise.all([
      writeFile(
        input,
        `curl '${origin}${path}' -H 'Authorization: Bearer ${TEST_TOKEN}' -H 'Content-Type: application/json' --data-raw '${JSON.stringify(PAYLOAD)}'`,
      ),
      writeFile(
        contract,
        JSON.stringify({
          complete: true,
          sources: [{ in: "header", name: "Authorization" }],
        }),
      ),
    ]);
    const result = await runCli(
      [
        input,
        "--max-cases",
        "2",
        "--auth-contract",
        contract,
        ...(expectAuth ? ["--expect-auth"] : []),
        "--allow-mutation",
        "--no-color",
        "--lang",
        "en",
        "--output",
        output,
        "--junit",
        "--sarif",
      ],
      directory,
    );
    const [json, html, markdown, junit, sarifText, outputFiles] =
      await Promise.all([
        readFile(join(output, "report.json"), "utf8"),
        readFile(join(output, "report.html"), "utf8"),
        readFile(join(output, "report.md"), "utf8"),
        readFile(join(output, "junit.xml"), "utf8"),
        readFile(join(output, "sarif.json"), "utf8"),
        readOutputFiles(output),
      ]);
    for (const value of [TEST_TOKEN, PRIVATE_RECEIPT]) {
      expect(
        `${result.stdout}\n${result.stderr}\n${outputFiles}`,
      ).not.toContain(value);
    }
    expect(result.stdout).toContain(join(output, "report.html"));
    const report = JSON.parse(json);
    expect(report.profile).toBe("quick");
    expect(report.outcome.exitCode).toBe(result.code);
    expect(report.outcome.requestsAttempted).toBe(requests.get(path)?.length);
    expect(report.outcome.requestsPlanned).toBe(3);
    for (const field of ["title", "explanation", "nextAction"]) {
      expect(report.outcome[field]).toEqual(expect.any(String));
      expect(report.outcome[field].trim().length).toBeGreaterThan(0);
    }
    expect(html).toContain(`data-outcome="${report.outcome.status}"`);
    expect(html).toContain(report.outcome.title);
    expect(markdown).toContain(report.outcome.title);
    return { ...result, report, html, junit, sarif: JSON.parse(sarifText) };
  }

  it("creates one owned record and proves missing or invalid credentials cannot create another", async () => {
    const path = "/protected/records";
    const result = await runJourney(path);

    expect(result.code).toBe(0);
    expect(result.report.outcome.status).toBe("complete");
    expect(result.report.outcome.checksRun).toBe(2);
    expect(result.report.baseline.status).toBe(201);
    expect(result.report.cases).toEqual([
      expect.objectContaining({
        category: "authentication",
        expectation: "auth-reject",
        classification: "PASS",
        status: 401,
      }),
      expect.objectContaining({
        category: "authentication",
        expectation: "auth-reject",
        classification: "PASS",
        status: 401,
      }),
    ]);
    expect(requests.get(path)).toEqual([
      {
        method: "POST",
        authorization: `Bearer ${TEST_TOKEN}`,
        body: PAYLOAD,
        status: 201,
        recordsBefore: 0,
        recordsAfter: 1,
      },
      {
        method: "POST",
        authorization: undefined,
        body: PAYLOAD,
        status: 401,
        recordsBefore: 1,
        recordsAfter: 1,
      },
      {
        method: "POST",
        authorization: "Bearer BREAKCURL_INVALID_CREDENTIAL",
        body: PAYLOAD,
        status: 401,
        recordsBefore: 1,
        recordsAfter: 1,
      },
    ]);
    expect(records.get(path)).toEqual([
      { id: "record-1", ownerId: ACTOR_ID, body: PAYLOAD },
    ]);
    expect(result.junit).toContain('tests="2" failures="0" errors="0"');
    expect(result.sarif.runs[0].results).toEqual([]);
  });

  it("reports the auth contract violation and independently proves two unauthorized writes", async () => {
    const path = "/vulnerable/records";
    const result = await runJourney(path);

    expect(result.code).toBe(1);
    expect(result.report.outcome.status).toBe("findings");
    expect(result.report.outcome.checksRun).toBe(2);
    expect(
      result.report.cases.map(
        (item: { classification: string }) => item.classification,
      ),
    ).toEqual(["FAIL", "FAIL"]);
    expect(requests.get(path)).toHaveLength(3);
    expect(requests.get(path)?.map((item) => item.status)).toEqual([
      201, 201, 201,
    ]);
    expect(
      requests
        .get(path)
        ?.map((item) => [item.recordsBefore, item.recordsAfter]),
    ).toEqual([
      [0, 1],
      [1, 2],
      [2, 3],
    ]);
    expect(records.get(path)).toEqual([
      { id: "record-1", ownerId: ACTOR_ID, body: PAYLOAD },
      { id: "record-2", ownerId: null, body: PAYLOAD },
      { id: "record-3", ownerId: null, body: PAYLOAD },
    ]);
    expect(result.junit).toContain('tests="2" failures="2" errors="0"');
    expect(result.sarif.runs[0].results).toEqual([
      expect.objectContaining({
        ruleId: "authentication-not-enforced",
        level: "error",
      }),
      expect.objectContaining({
        ruleId: "authentication-not-enforced",
        level: "error",
      }),
    ]);
  });

  it("stops after a failed baseline and makes the incomplete result explicit", async () => {
    const path = "/broken/records";
    const result = await runJourney(path);

    expect(result.code).toBe(2);
    expect(result.report.outcome).toMatchObject({
      status: "incomplete",
      exitCode: 2,
      requestsAttempted: 1,
      requestsPlanned: 3,
      checksRun: 0,
    });
    expect(result.report.baseline.status).toBe(500);
    expect(result.report.cases).toEqual([]);
    expect(requests.get(path)).toEqual([
      {
        method: "POST",
        authorization: `Bearer ${TEST_TOKEN}`,
        body: PAYLOAD,
        status: 500,
        recordsBefore: 0,
        recordsAfter: 0,
      },
    ]);
    expect(records.get(path)).toEqual([]);
    expect(result.html).toContain("Check incomplete");
    expect(result.html).toContain("0 checks executed");
    expect(result.html).not.toContain('data-outcome="complete"');
    expect(result.junit).toContain('tests="1" failures="0" errors="1"');
    expect(result.junit).toContain("Run prerequisites and completion");
    expect(result.sarif.runs[0].invocations[0]).toMatchObject({
      executionSuccessful: false,
      toolExecutionNotifications: [expect.objectContaining({ level: "error" })],
    });
    expect(result.sarif.runs[0].results).toEqual([]);
  });

  it("keeps public unauthenticated writes as reviewable observations without an auth expectation", async () => {
    const path = "/public/records";
    const result = await runJourney(path, false);

    expect(result.code).toBe(0);
    expect(result.report.outcome).toMatchObject({
      status: "review",
      exitCode: 0,
      requestsAttempted: 3,
      requestsPlanned: 3,
      checksRun: 2,
    });
    expect(result.report.cases).toEqual([
      expect.objectContaining({ classification: "WARN", status: 201 }),
      expect.objectContaining({ classification: "WARN", status: 201 }),
    ]);
    expect(records.get(path)).toHaveLength(3);
    expect(
      records
        .get(path)
        ?.slice(1)
        .every((item) => item.ownerId === null),
    ).toBe(true);
    expect(result.html).toContain("Signals need review");
    expect(result.html).toContain(
      "Exit code 0 does not turn a warning into a passed security check.",
    );
    expect(result.junit).toContain(
      'tests="2" failures="0" errors="0" skipped="2"',
    );
    expect(result.sarif.runs[0].results).toHaveLength(2);
    expect(
      result.sarif.runs[0].results.every(
        (item: { level: string }) => item.level === "warning",
      ),
    ).toBe(true);
  });
});

function runCli(args: string[], cwd: string): Promise<CliResult> {
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

async function readOutputFiles(directory: string): Promise<string> {
  const entries = await readdir(directory, { withFileTypes: true });
  const contents = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory()
        ? readOutputFiles(path)
        : `${entry.name}\n${await readFile(path, "utf8")}`;
    }),
  );
  return contents.join("\n");
}
