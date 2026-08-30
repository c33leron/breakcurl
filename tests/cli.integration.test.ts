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
import { VERSION } from "../src/version.js";

const CANARY = "CANARY_SUPER_SECRET_123";
const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const temporaryDirectories: string[] = [];

describe("installed-style CLI flow", () => {
  const requests = new Map<string, number>();
  const server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    requests.set(path, (requests.get(path) ?? 0) + 1);
    let rawBody = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      rawBody += chunk;
    });
    request.on("end", () => {
      response.setHeader("Content-Type", "application/json");
      if (path === "/auth-protected") {
        if (request.headers.authorization !== `Bearer ${CANARY}`) {
          response.statusCode = 401;
          response.end('{"error":"unauthorized"}');
          return;
        }
        response.statusCode = 201;
        response.end('{"created":true}');
        return;
      }
      if (path === "/auth-bypass") {
        response.statusCode = 201;
        response.end('{"created":true}');
        return;
      }
      if (path === "/baseline-fail") {
        response.statusCode = 500;
        response.end('{"error":"baseline failed"}');
        return;
      }
      if (path === "/baseline-client-fail") {
        response.statusCode = 422;
        response.end('{"error":"baseline rejected"}');
        return;
      }
      const body = JSON.parse(rawBody) as Record<string, unknown>;
      if (path === "/rate-limit") {
        const isBaseline = body.email === "qa@example.com" && body.age === 30;
        response.statusCode = isBaseline ? 201 : 429;
        if (!isBaseline) response.setHeader("Retry-After", "30");
        response.end(JSON.stringify({ status: response.statusCode }));
        return;
      }
      if (path === "/mutation-error") {
        response.statusCode =
          body.email === "qa@example.com" && body.age === 30 ? 201 : 302;
        response.end(JSON.stringify({ status: response.statusCode }));
        return;
      }
      if (!("email" in body)) {
        response.statusCode = 422;
      } else if (body.age === null) {
        response.statusCode = 500;
      } else if (typeof body.age === "string") {
        response.statusCode = 200;
      } else if (body.email === "qa@example.com" && body.age === 30) {
        response.statusCode = 201;
      } else {
        response.statusCode = 422;
      }
      response.end(JSON.stringify({ status: response.statusCode }));
    });
  });

  let origin = "";

  beforeAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Test server did not start.");
    origin = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    await Promise.all(
      temporaryDirectories.map((directory) =>
        rm(directory, { recursive: true, force: true }),
      ),
    );
  });

  it("runs from a file, returns 1 for FAIL, and never exposes the canary", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "request.curl");
    const outputDirectory = join(directory, "output");
    await writeFile(
      inputFile,
      workingCurl(`${origin}/ok?token=${CANARY}`),
      "utf8",
    );

    const result = await runCli([
      inputFile,
      "--allow-mutation",
      "--no-color",
      "--output",
      outputDirectory,
    ]);
    const artifacts = await readFilesRecursively(outputDirectory);

    expect(result.code).toBe(1);
    expect(result.stdout).toContain("RUN PLAN");
    expect(result.stdout).toContain("PASS");
    expect(result.stdout).toContain("WARN");
    expect(result.stdout).toContain("FAIL");
    expect(`${result.stdout}\n${result.stderr}\n${artifacts}`).not.toContain(
      CANARY,
    );
    expect(artifacts).toContain("<REDACTED>");
  });

  it("accepts stdin and honors max-cases with a zero exit", async () => {
    const before = requests.get("/ok") ?? 0;
    const directory = await temporaryDirectory();
    const result = await runCli(
      [
        "--allow-mutation",
        "--max-cases",
        "1",
        "--no-color",
        "--output",
        join(directory, "output"),
      ],
      workingCurl(`${origin}/ok`),
    );

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("profile     QUICK");
    expect(result.stdout).toContain(
      "PASS 1   INFO 0   WARN 0   FAIL 0   ERROR 0",
    );
    expect((requests.get("/ok") ?? 0) - before).toBe(2);
  });

  it("reports the current package version", async () => {
    const result = await runCli(["--version"]);
    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe(VERSION);
  });

  it("stops after a failed baseline and sends no mutations", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "failed.curl");
    const outputDirectory = join(directory, "output");
    const before = requests.get("/baseline-fail") ?? 0;
    await writeFile(inputFile, workingCurl(`${origin}/baseline-fail`), "utf8");

    const result = await runCli([
      inputFile,
      "--allow-mutation",
      "--no-color",
      "--output",
      outputDirectory,
    ]);

    expect(result.code).toBe(2);
    expect(result.stderr).toContain("No mutations were sent");
    expect((requests.get("/baseline-fail") ?? 0) - before).toBe(1);
    await expect(access(outputDirectory)).rejects.toThrow();
  });

  it("also stops after a 4xx baseline", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "rejected.curl");
    const before = requests.get("/baseline-client-fail") ?? 0;
    await writeFile(
      inputFile,
      workingCurl(`${origin}/baseline-client-fail`),
      "utf8",
    );

    const result = await runCli([inputFile, "--allow-mutation", "--no-color"]);

    expect(result.code).toBe(2);
    expect(result.stderr).toContain("The baseline request returned 422");
    expect((requests.get("/baseline-client-fail") ?? 0) - before).toBe(1);
  });

  it("returns 2 when a mutation produces an ERROR classification", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "unexpected-status.curl");
    await writeFile(inputFile, workingCurl(`${origin}/mutation-error`), "utf8");

    const result = await runCli([
      inputFile,
      "--allow-mutation",
      "--max-cases",
      "1",
      "--no-color",
      "--output",
      join(directory, "output"),
    ]);

    expect(result.code).toBe(2);
    expect(result.stdout).toContain("ERROR");
    expect(result.stdout).toMatch(/\[1\/1\] ERROR\s+STRUCTURE\s+302/);
  });

  it("shows live progress and stops the run after HTTP 429", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "rate-limit.curl");
    const outputDirectory = join(directory, "output");
    const before = requests.get("/rate-limit") ?? 0;
    await writeFile(inputFile, workingCurl(`${origin}/rate-limit`), "utf8");

    const result = await runCli([
      inputFile,
      "--allow-mutation",
      "--max-cases",
      "5",
      "--no-color",
      "--output",
      outputDirectory,
    ]);
    const artifacts = await readFilesRecursively(outputDirectory);

    expect(result.code).toBe(2);
    expect(result.stdout).toContain("CHECKS");
    expect(result.stdout).toContain("[1/5] ERROR");
    expect(result.stdout).toContain("SAFETY STOP");
    expect(result.stdout).toContain("Retry-After: 30");
    expect(result.stdout).toContain("skipped checks: 4");
    expect(artifacts).toContain("Safety stop: received HTTP 429");
    expect((requests.get("/rate-limit") ?? 0) - before).toBe(2);
  });

  it("requires authorization before any requests in a non-interactive run", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "request.curl");
    const before = requests.get("/ok") ?? 0;
    await writeFile(inputFile, workingCurl(`${origin}/ok`), "utf8");

    const result = await runCli([inputFile, "--no-color"]);

    expect(result.code).toBe(2);
    expect(result.stderr).toContain("require --allow-mutation");
    expect((requests.get("/ok") ?? 0) - before).toBe(0);
  });

  it("rejects shell input without execution or an HTTP request", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "dangerous.curl");
    const marker = join(directory, "must-not-exist");
    const before = requests.get("/ok") ?? 0;
    await writeFile(
      inputFile,
      `${workingCurl(`${origin}/ok`)} | touch ${marker}`,
      "utf8",
    );

    const result = await runCli([inputFile, "--allow-mutation", "--no-color"]);

    expect(result.code).toBe(2);
    await expect(access(marker)).rejects.toThrow();
    expect(requests.get("/ok") ?? 0).toBe(before);
  });

  it("dry-run prints a full plan and sends zero requests", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "request.curl");
    const before = requests.get("/ok") ?? 0;
    await writeFile(inputFile, workingCurl(`${origin}/ok`), "utf8");

    const result = await runCli([
      inputFile,
      "--profile",
      "full",
      "--max-cases",
      "100",
      "--dry-run",
      "--no-color",
    ]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("budget      0 requests");
    expect(result.stdout).toContain("no HTTP requests were sent");
    expect(result.stdout).toContain("[authentication]");
    expect((requests.get("/ok") ?? 0) - before).toBe(0);
  });

  it("passes explicit auth contract when missing and invalid credentials return 401", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "auth.curl");
    const before = requests.get("/auth-protected") ?? 0;
    await writeFile(inputFile, workingCurl(`${origin}/auth-protected`), "utf8");

    const result = await runCli([
      inputFile,
      "--profile",
      "security",
      "--expect-auth",
      "--max-cases",
      "2",
      "--allow-mutation",
      "--no-color",
      "--output",
      join(directory, "output"),
    ]);

    expect(result.code).toBe(0);
    expect(result.stdout).toMatch(
      /PASS\s+AUTH\s+401\s+\d+ms\s+all credentials removed/,
    );
    expect(result.stdout).toMatch(
      /PASS\s+AUTH\s+401\s+\d+ms\s+credentials replaced with invalid values/,
    );
    expect((requests.get("/auth-protected") ?? 0) - before).toBe(3);
  });

  it("fails an explicit auth contract when unauthenticated responses match baseline", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "auth-bypass.curl");
    await writeFile(inputFile, workingCurl(`${origin}/auth-bypass`), "utf8");

    const result = await runCli([
      inputFile,
      "--security",
      "--expect-auth",
      "--max-cases",
      "2",
      "--allow-mutation",
      "--no-color",
      "--output",
      join(directory, "output"),
    ]);

    expect(result.code).toBe(1);
    expect(result.stdout).toMatch(
      /FAIL\s+AUTH\s+201\s+\d+ms\s+all credentials removed/,
    );
    expect(result.stdout).toContain("FAIL 2");
  });

  it("runs an explicit custom value before generated checks", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "custom.curl");
    await writeFile(inputFile, workingCurl(`${origin}/ok`), "utf8");

    const result = await runCli([
      inputFile,
      "--profile",
      "negative",
      "--max-cases",
      "1",
      "--set",
      '$.age="wrong"',
      "--allow-mutation",
      "--no-color",
      "--output",
      join(directory, "output"),
    ]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("Custom value for $.age");
    expect(result.stdout).toContain("WARN");
  });

  it("runs custom expectations from a JSON config end to end", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "configured.curl");
    const configFile = join(directory, "breakcurl.config.json");
    await writeFile(inputFile, workingCurl(`${origin}/ok`), "utf8");
    await writeFile(
      configFile,
      JSON.stringify({
        profile: "negative",
        maxCases: 1,
        customCases: [
          {
            name: "String age must be rejected",
            path: "$.age",
            operation: "set",
            value: "wrong",
            expect: "reject",
          },
        ],
      }),
      "utf8",
    );

    const result = await runCli([
      inputFile,
      "--config",
      configFile,
      "--allow-mutation",
      "--no-color",
      "--output",
      join(directory, "output"),
    ]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("String age must be rejected");
    expect(result.stdout).toContain("WARN");
  });

  it("switches the human interface to Russian with --lang ru", async () => {
    const directory = await temporaryDirectory();
    const inputFile = join(directory, "request.curl");
    const before = requests.get("/ok") ?? 0;
    await writeFile(inputFile, workingCurl(`${origin}/ok`), "utf8");

    const result = await runCli([
      inputFile,
      "--lang",
      "ru",
      "--dry-run",
      "--max-cases",
      "1",
      "--no-color",
    ]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("ПЛАН ЗАПУСКА");
    expect(result.stdout).toContain("HTTP-запросы не отправлены");
    expect((requests.get("/ok") ?? 0) - before).toBe(0);
  });
});

function workingCurl(url: string): string {
  return `curl -X POST '${url}' -H 'Authorization: Bearer ${CANARY}' -H 'Content-Type: application/json' -H 'Connection: close' --data-raw '{"email":"qa@example.com","age":30,"password":"${CANARY}"}'`;
}

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "breakcurl-cli-"));
  temporaryDirectories.push(directory);
  return directory;
}

async function runCli(
  args: string[],
  stdin: string | undefined = undefined,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
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
    child.stdin.end(stdin);
  });
}

async function readFilesRecursively(directory: string): Promise<string> {
  const entries = await readdir(directory, { withFileTypes: true });
  const content: string[] = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) content.push(await readFilesRecursively(path));
    else content.push(await readFile(path, "utf8"));
  }
  return content.join("\n");
}
