import { createServer } from "node:http";
import { classifyCase } from "./classify.js";
import { message } from "./i18n.js";
import { generateChecks, requestForCase } from "./mutations.js";
import { redactUrl } from "./redact.js";
import { writeReport } from "./report.js";
import { sendRequest } from "./runner.js";
import {
  printBanner,
  printBaseline,
  printCaseLine,
  printKeyValue,
  printResultSummary,
  printSection,
} from "./terminal.js";
import type { CaseResult, Language, ParsedCurl, RunResult } from "./types.js";

interface DemoOptions {
  timeoutMs: number;
  outputDirectory: string;
  color: boolean;
  language: Language;
  junitPath?: string | undefined;
  sarifPath?: string | undefined;
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

    printBanner(
      message(options.language, "LOCAL DEMO", "ЛОКАЛЬНАЯ ДЕМО"),
      options.color,
    );
    printSection(
      message(options.language, "BASELINE", "ИСХОДНЫЙ ЗАПРОС"),
      options.color,
    );
    const baselineResponse = await sendRequest(request, options.timeoutMs);
    printBaseline(
      request.method,
      redactUrl(request.url),
      baselineResponse.status,
      baselineResponse.latencyMs,
      options.color,
    );
    if (baselineResponse.status < 200 || baselineResponse.status >= 300)
      return false;

    const generatedChecks = generateChecks(request, {
      profile: "full",
      maxCases: 30,
      expectAuth: true,
      language: options.language,
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
      language: options.language,
    };
    const generated = await writeReport(result, options.outputDirectory, {
      junitPath: options.junitPath,
      sarifPath: options.sarifPath,
    });
    printDemo(
      result,
      generated.reportPath,
      generated.jsonReportPath,
      generated.findingPaths,
      generated.junitPath,
      generated.sarifPath,
      options.color,
      options.language,
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
  junitPath: string | undefined,
  sarifPath: string | undefined,
  colorEnabled: boolean,
  language: Language,
): void {
  printSection(message(language, "CHECKS", "ПРОВЕРКИ"), colorEnabled);
  for (const [index, item] of result.cases.entries()) {
    printCaseLine(item, index, result.cases.length, colorEnabled, language);
  }
  printSection(message(language, "RUN SUMMARY", "ИТОГ"), colorEnabled);
  printResultSummary(result.cases, colorEnabled);
  printSection(message(language, "ARTIFACTS", "АРТЕФАКТЫ"), colorEnabled);
  printKeyValue(message(language, "report", "отчёт"), reportPath, colorEnabled);
  printKeyValue("json", jsonReportPath, colorEnabled);
  if (junitPath) printKeyValue("junit", junitPath, colorEnabled);
  if (sarifPath) printKeyValue("sarif", sarifPath, colorEnabled);
  for (const path of findingPaths) {
    printKeyValue(message(language, "finding", "находка"), path, colorEnabled);
  }
  printKeyValue(
    message(language, "privacy", "приватность"),
    message(
      language,
      "Secrets redacted before writing",
      "Секреты скрыты до записи",
    ),
    colorEnabled,
  );
}
