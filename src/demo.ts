import { createServer } from "node:http";
import { createColors } from "picocolors";
import { classifyCase } from "./classify.js";
import { generateChecks, requestForCase } from "./mutations.js";
import { redactUrl } from "./redact.js";
import { writeReport } from "./report.js";
import { sendRequest } from "./runner.js";
import type { CaseResult, ParsedCurl, RunResult } from "./types.js";

interface DemoOptions {
  timeoutMs: number;
  outputDirectory: string;
  color: boolean;
}

const CANARY = "CANARY_SUPER_SECRET_123";

export async function runDemo(options: DemoOptions): Promise<boolean> {
  const server = createServer((request, response) => {
    let rawBody = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      rawBody += chunk;
    });
    request.on("end", () => {
      response.setHeader("Content-Type", "application/json");
      if (request.headers.authorization !== `Bearer ${CANARY}`) {
        response.statusCode = 401;
        response.end('{"error":"unauthorized"}');
        return;
      }
      try {
        const body = JSON.parse(rawBody) as Record<string, unknown>;
        if (!("email" in body)) {
          response.statusCode = 422;
          response.end('{"error":"email is required"}');
        } else if (body.age === null) {
          response.statusCode = 500;
          response.end('{"error":"internal error"}');
        } else if (typeof body.age === "string") {
          response.statusCode = 200;
          response.end('{"accepted":true}');
        } else if (body.email === "qa@example.com" && body.age === 30) {
          response.statusCode = 201;
          response.end('{"created":true}');
        } else {
          response.statusCode = 422;
          response.end('{"error":"invalid input"}');
        }
      } catch {
        response.statusCode = 400;
        response.end('{"error":"invalid json"}');
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  try {
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Demo server did not start.");
    const request: ParsedCurl = {
      method: "POST",
      url: `http://127.0.0.1:${address.port}/api/users?token=${CANARY}`,
      headers: {
        Authorization: `Bearer ${CANARY}`,
        Connection: "close",
        "Content-Type": "application/json",
      },
      body: {
        email: "qa@example.com",
        age: 30,
        token: CANARY,
      },
    };

    console.log("BreakCurl v0.1.0 — demo\n\nИсходный запрос");
    const baselineResponse = await sendRequest(request, options.timeoutMs);
    console.log(
      `  ${request.method} ${redactUrl(request.url)} → ${baselineResponse.status} (${baselineResponse.latencyMs} ms)`,
    );
    if (baselineResponse.status < 200 || baselineResponse.status >= 300)
      return false;

    const generatedChecks = generateChecks(request, {
      profile: "full",
      maxCases: 30,
      expectAuth: true,
    });
    const cases: CaseResult[] = [];
    for (const mutation of generatedChecks.cases) {
      const response = await sendRequest(
        requestForCase(request, mutation),
        options.timeoutMs,
      );
      cases.push({
        mutation,
        response,
        ...classifyCase(mutation, response, {
          baseline: baselineResponse,
          expectAuth: true,
        }),
      });
    }
    const result: RunResult = {
      baseline: { request, response: baselineResponse },
      cases,
      profile: "full",
      notes: generatedChecks.notes,
    };
    const generated = await writeReport(result, options.outputDirectory);
    printDemo(
      result,
      generated.reportPath,
      generated.jsonReportPath,
      generated.findingPaths,
      options.color,
    );

    const classes = new Set(cases.map((item) => item.classification));
    return classes.has("PASS") && classes.has("WARN") && classes.has("FAIL");
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function printDemo(
  result: RunResult,
  reportPath: string,
  jsonReportPath: string,
  findingPaths: string[],
  colorEnabled: boolean,
): void {
  const colors = createColors(colorEnabled);
  console.log("\nНегативные проверки");
  for (const item of result.cases) {
    const label =
      item.classification === "FAIL"
        ? colors.red("FAIL")
        : item.classification === "WARN"
          ? colors.yellow("WARN")
          : item.classification === "INFO"
            ? colors.cyan("INFO")
            : colors.green("PASS");
    console.log(
      `  ${label.padEnd(5)} ${item.mutation.description} → ${item.response.status}`,
    );
  }
  const failed = result.cases.filter(
    (item) => item.classification === "FAIL",
  ).length;
  const warned = result.cases.filter(
    (item) => item.classification === "WARN",
  ).length;
  const passed = result.cases.filter(
    (item) => item.classification === "PASS",
  ).length;
  const informed = result.cases.filter(
    (item) => item.classification === "INFO",
  ).length;
  console.log("\nИтог");
  console.log(
    `  Проверок: ${result.cases.length}; FAIL: ${failed}; WARN: ${warned}; INFO: ${informed}; PASS: ${passed}`,
  );
  console.log("\nСоздано");
  console.log(`  ${reportPath}`);
  console.log(`  ${jsonReportPath}`);
  for (const path of findingPaths) console.log(`  ${path}`);
  console.log("\nСекреты были скрыты до записи файлов.");
}
