import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseCurl } from "../src/curl.js";
import type { ParsedCurl } from "../src/types.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const directories: string[] = [];
const received: {
  path: string;
  method: string | undefined;
  headers: IncomingHttpHeaders;
  body: unknown;
}[] = [];

async function fixture(
  kind: string,
): Promise<{ source: string; expected: ParsedCurl }> {
  const base = new URL("./fixtures/browser-curl/", import.meta.url);
  return {
    source: await readFile(new URL(`${kind}.curl`, base), "utf8"),
    expected: JSON.parse(
      await readFile(new URL(`${kind}.expected.json`, base), "utf8"),
    ) as ParsedCurl,
  };
}

describe("browser Copy as cURL end to end", () => {
  const server = createServer(async (request, response) => {
    let raw = "";
    for await (const chunk of request) raw += chunk;
    received.push({
      path: request.url ?? "",
      method: request.method,
      headers: request.headers,
      body: JSON.parse(raw),
    });
    response.setHeader("Content-Type", "application/json");
    response.statusCode = request.headers.authorization ? 200 : 401;
    response.end(JSON.stringify({ accepted: response.statusCode === 200 }));
  });
  let origin = "";

  beforeAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("No local fixture address");
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

  it.each(["vacancies", "candidates"])(
    "preserves every parsed field in the %s fixture",
    async (kind) => {
      const { source, expected } = await fixture(kind);
      expect(parseCurl(source)).toEqual(expected);
    },
  );

  for (const kind of ["vacancies", "candidates"]) {
    it.each(["file", "stdin"])(
      `sends the ${kind} fixture through %s with exact JSON and browser headers`,
      async (input) => {
        const { source, expected } = await fixture(kind);
        const curl = source.replaceAll("https://api.example.test", origin);
        const directory = await mkdtemp(join(tmpdir(), "breakcurl-browser-"));
        directories.push(directory);
        const path = join(directory, "request.curl");
        await writeFile(path, curl);
        const output = join(directory, "output");
        const before = received.length;
        const result = await runCli(
          [
            ...(input === "file" ? [path] : []),
            "--allow-mutation",
            "--max-cases",
            "1",
            "--output",
            output,
            "--no-color",
          ],
          input === "stdin" ? curl : undefined,
        );
        expect(result.code, result.stderr).toBe(0);
        const calls = received.slice(before);
        expect(calls).toHaveLength(2);
        expect(calls[0]?.method).toBe("PUT");
        expect(calls[0]?.path).toBe(new URL(expected.url).pathname);
        expect(calls[0]?.body).toEqual(expected.body);
        for (const [name, value] of Object.entries(expected.headers)) {
          expect(calls[0]?.headers[name]).toBe(
            value.replaceAll("https://api.example.test", origin),
          );
        }
        expect(calls[1]?.headers.authorization).toBeUndefined();
        expect(calls[1]?.body).toEqual(expected.body);
        const report = await readFile(join(output, "report.json"), "utf8");
        expect(report).not.toContain("BREAKCURL_SYNTHETIC_TOKEN");
        expect(result.stdout + result.stderr).not.toContain(
          "BREAKCURL_SYNTHETIC_TOKEN",
        );
        expect(result.stdout).toContain("file://");
      },
    );
  }

  it("sends no requests for the ANSI-C fixture in dry-run", async () => {
    const { source } = await fixture("candidates");
    const before = received.length;
    const result = await runCli(
      ["--dry-run", "--no-color"],
      source.replaceAll("https://api.example.test", origin),
    );
    expect(result.code, result.stderr).toBe(0);
    expect(result.stdout).toContain("0 requests (dry-run)");
    expect(received.length).toBe(before);
  });

  it("rejects shell operations outside an ANSI-C literal before any request", async () => {
    const { source } = await fixture("candidates");
    const before = received.length;
    const result = await runCli(
      ["--allow-mutation", "--no-color"],
      `${source.replaceAll("https://api.example.test", origin).trimEnd()} | echo SHOULD_NOT_EXECUTE`,
    );
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("Shell operators");
    expect(received.length).toBe(before);
  });
});

function runCli(
  args: string[],
  input?: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, BREAKCURL_LANG: "en" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
  });
}
