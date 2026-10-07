import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const OWNED_TOKEN = "synthetic-open-report-fixture";
const directories: string[] = [];
const PRELOAD = String.raw`
import childProcess from "node:child_process";
import { appendFileSync, existsSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath } from "node:url";

Object.defineProperty(process.stdin, "isTTY", {
  value: process.env.BREAKCURL_TEST_STDIN_TTY === "true",
});
Object.defineProperty(process.stdout, "isTTY", {
  value: process.env.BREAKCURL_TEST_STDOUT_TTY === "true",
});

childProcess.execFile = (command, args, options, callback) => {
  const url = options.env?.BREAKCURL_REPORT_URL
    ?? args.find((argument) => argument.startsWith("file://"));
  appendFileSync(process.env.BREAKCURL_TEST_OPENER_LOG, JSON.stringify({
    command,
    args,
    url,
    fileExisted: url ? existsSync(fileURLToPath(url)) : false,
  }) + "\n");
  const failure = url && process.env.BREAKCURL_TEST_OPENER_FAIL === "true";
  queueMicrotask(() => callback(
    failure ? new Error("Controlled browser launch failure") : null,
    command === "/usr/bin/osascript" ? "com.apple.Safari\n" : "",
    "",
  ));
  return { kill: () => false, unref() { return this; } };
};

// Any unexpected subprocess path fails safely instead of opening a real browser.
for (const name of ["exec", "spawn", "execFileSync", "execSync", "spawnSync", "fork"]) {
  childProcess[name] = () => {
    appendFileSync(process.env.BREAKCURL_TEST_OPENER_LOG, JSON.stringify({
      command: "unexpected subprocess API: " + name,
      args: [],
      fileExisted: false,
    }) + "\n");
    throw new Error("Unexpected subprocess API: " + name);
  };
}
syncBuiltinESMExports();
`;

interface OpenerCall {
  command: string;
  args: string[];
  url?: string;
  fileExisted: boolean;
}

interface Fixture {
  directory: string;
  output: string;
  preload: string;
  log: string;
  input: string;
}

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
  calls: OpenerCall[];
}

async function fixture(origin: string, endpoint = "/ok"): Promise<Fixture> {
  const directory = await mkdtemp(join(tmpdir(), "breakcurl-open-report-"));
  directories.push(directory);
  const preload = join(directory, "mock-opener.mjs");
  const input = join(directory, "request.curl");
  await writeFile(preload, PRELOAD);
  await writeFile(
    input,
    `curl '${origin}${endpoint}' -H 'Authorization: Bearer ${OWNED_TOKEN}'`,
  );
  return {
    directory,
    output: join(directory, "reports with spaces"),
    preload,
    log: join(directory, "opener-calls.jsonl"),
    input,
  };
}

async function runCli(
  context: Fixture,
  args: string[],
  options: {
    stdinIsTTY?: boolean;
    stdoutIsTTY?: boolean;
    ci?: string;
    openerFails?: boolean;
  } = {},
): Promise<CliResult> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    BREAKCURL_LANG: "en",
    XDG_CONFIG_HOME: context.directory,
    APPDATA: context.directory,
    NO_COLOR: "1",
    BREAKCURL_TEST_STDIN_TTY: String(options.stdinIsTTY ?? true),
    BREAKCURL_TEST_STDOUT_TTY: String(options.stdoutIsTTY ?? true),
    BREAKCURL_TEST_OPENER_FAIL: String(options.openerFails ?? false),
    BREAKCURL_TEST_OPENER_LOG: context.log,
  };
  delete env.CI;
  delete env.FORCE_COLOR;
  delete env.BREAKCURL_REPORT_URL;
  if (options.ci !== undefined) env.CI = options.ci;
  const result = await new Promise<Omit<CliResult, "calls">>(
    (resolve, reject) => {
      const child = spawn(
        process.execPath,
        [
          "--import",
          pathToFileURL(context.preload).href,
          CLI,
          ...args,
          "--output",
          context.output,
          "--allow-mutation",
          "--no-color",
        ],
        {
          cwd: context.directory,
          env,
          stdio: ["pipe", "pipe", "pipe"],
          timeout: 15_000,
        },
      );
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
    },
  );
  let log = "";
  try {
    log = await readFile(context.log, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return {
    ...result,
    calls: log.trim()
      ? log
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line))
      : [],
  };
}

describe("opening reports after a CLI run", () => {
  let origin = "";
  let requests = 0;
  const server = createServer((request, response) => {
    requests += 1;
    const authorized =
      request.headers.authorization === `Bearer ${OWNED_TOKEN}`;
    response.statusCode = authorized
      ? 200
      : request.url === "/fail"
        ? 500
        : 401;
    response.setHeader("Content-Type", "application/json");
    response.end(
      JSON.stringify(
        authorized ? { ok: true } : { error: "fixture rejection" },
      ),
    );
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

  it("opens one existing demo index instead of each of its four reports", async () => {
    const context = await fixture(origin);
    const result = await runCli(context, ["demo"]);
    const target = join(context.output, "demo.html");
    const launches = result.calls.filter((call) => call.url !== undefined);

    expect(result.code, result.stderr).toBe(0);
    expect(launches).toEqual([
      expect.objectContaining({
        url: pathToFileURL(target).href,
        fileExisted: true,
      }),
    ]);
    const html = await readFile(target, "utf8");
    expect(html.match(/<article>/g)).toHaveLength(4);
  }, 15_000);

  it("opens the completed report for a normal local GET run", async () => {
    const context = await fixture(origin);
    const result = await runCli(context, [context.input]);
    const target = join(context.output, "report.html");

    expect(result.code, result.stderr).toBe(0);
    expect(result.calls.filter((call) => call.url !== undefined)).toEqual([
      expect.objectContaining({
        url: pathToFileURL(target).href,
        fileExisted: true,
      }),
    ]);
    expect(await readFile(target, "utf8")).toContain("<!doctype html>");
  });

  it.each([
    { label: "--no-open", args: ["--no-open"], options: {} },
    { label: "CI", args: [], options: { ci: "true" } },
    { label: "piped input", args: [], options: { stdinIsTTY: false } },
    { label: "piped output", args: [], options: { stdoutIsTTY: false } },
  ])(
    "saves reports without invoking the opener for $label",
    async ({ args, options }) => {
      const context = await fixture(origin);
      const result = await runCli(context, [context.input, ...args], options);

      expect(result.code, result.stderr).toBe(0);
      expect(result.calls).toEqual([]);
      await access(join(context.output, "report.html"));
    },
  );

  it.each(["demo", "normal"])(
    "does not open a browser or send requests for %s dry-run",
    async (command) => {
      const context = await fixture(origin);
      const before = requests;
      const result = await runCli(context, [
        command === "demo" ? "demo" : context.input,
        "--dry-run",
      ]);

      expect(result.code, result.stderr).toBe(0);
      expect(result.calls).toEqual([]);
      expect(requests).toBe(before);
      await expect(access(context.output)).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

  it.each([
    { endpoint: "/ok", code: 0 },
    { endpoint: "/fail", code: 1 },
  ])(
    "preserves exit $code and the report link when the opener fails",
    async ({ endpoint, code }) => {
      const context = await fixture(origin, endpoint);
      const result = await runCli(context, [context.input], {
        openerFails: true,
      });
      const target = join(context.output, "report.html");

      expect(result.code, result.stderr).toBe(code);
      expect(
        result.calls.filter((call) => call.url !== undefined),
      ).toHaveLength(1);
      expect(result.stdout).toContain(
        "Could not open the browser. Use the report link above.",
      );
      expect(result.stdout).toContain(pathToFileURL(target).href);
      await access(target);
    },
  );
});
