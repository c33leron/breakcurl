import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";
import { executeChecks } from "./execute.js";
import { message } from "./i18n.js";
import { executeIdorPlan, parseIdorConfig, prepareIdorPlan } from "./idor.js";
import { generateChecks } from "./mutations.js";
import { collectSensitiveValues, redactUrl } from "./redact.js";
import { type ReportFiles, writeReport } from "./report.js";
import {
  printBanner,
  printBaseline,
  printCaseLine,
  printFileLink,
  printKeyValue,
  printResultSummary,
  printRunOutcome,
  printSection,
} from "./terminal.js";
import type { Language, ParsedCurl, RunResult } from "./types.js";

interface DemoOptions {
  timeoutMs: number;
  outputDirectory: string;
  color: boolean;
  language: Language;
  junitPath?: string | undefined;
  sarifPath?: string | undefined;
}

const CANARY = "CANARY_SUPER_SECRET_123";
const TOKEN_A = "CANARY_DEMO_ACTOR_A_TOKEN";
const TOKEN_B = "CANARY_DEMO_ACTOR_B_TOKEN";

/** Disposable fixture owns all data and intentionally includes vulnerable routes. */
export async function runDemo(options: DemoOptions): Promise<boolean> {
  const objects = {
    alpha: { id: "alpha", canary: randomBytes(16).toString("hex") },
    beta: { id: "beta", canary: randomBytes(16).toString("hex") },
  };
  const server = createServer((request, response) => {
    let rawBody = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      rawBody += chunk;
    });
    request.on("end", () => {
      response.setHeader("Content-Type", "application/json");
      const path = new URL(request.url ?? "/", "http://localhost").pathname;
      const actor =
        request.headers.authorization === `Bearer ${TOKEN_A}`
          ? "actor-a"
          : request.headers.authorization === `Bearer ${TOKEN_B}`
            ? "actor-b"
            : undefined;
      if (path === "/me" || /\/(protected|vulnerable)\/objects\//.test(path)) {
        if (!actor) {
          response.statusCode = 401;
          response.end('{"error":"unauthorized"}');
          return;
        }
        if (path === "/me") {
          response.end(JSON.stringify({ id: actor }));
          return;
        }
        const id = path.split("/").at(-1);
        if (id !== "alpha" && id !== "beta") {
          response.statusCode = 404;
          response.end('{"error":"missing"}');
          return;
        }
        if (
          path.startsWith("/protected/") &&
          (actor === "actor-a" ? id !== "alpha" : id !== "beta")
        ) {
          response.statusCode = 403;
          response.end('{"error":"forbidden"}');
          return;
        }
        response.end(JSON.stringify(objects[id]));
        return;
      }
      if (
        path !== "/api/auth-bypass" &&
        request.headers.authorization !== `Bearer ${CANARY}`
      ) {
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
    const origin = `http://127.0.0.1:${address.port}`;
    const request: ParsedCurl = {
      method: "POST",
      url: `${origin}/api/users?token=${CANARY}`,
      headers: {
        Authorization: `Bearer ${CANARY}`,
        "Content-Type": "application/json",
      },
      body: { email: "qa@example.com", age: 30, token: CANARY },
    };
    const knownSecrets = [
      CANARY,
      TOKEN_A,
      TOKEN_B,
      objects.alpha.canary,
      objects.beta.canary,
    ];
    printBanner(
      message(
        options.language,
        "LOCAL DEMO · DISPOSABLE FIXTURES",
        "ЛОКАЛЬНОЕ ДЕМО · ОДНОРАЗОВЫЕ ДАННЫЕ",
      ),
      options.color,
    );
    const checks = generateChecks(request, {
      profile: "full",
      maxCases: 30,
      expectAuth: true,
      language: options.language,
      authContract: {
        complete: true,
        sources: [
          { in: "header", name: "Authorization" },
          { in: "query", name: "token" },
          { in: "json", pointer: "/token" },
        ],
      },
    });
    const result = await executeChecks(request, checks.cases, {
      timeoutMs: options.timeoutMs,
      profile: "full",
      language: options.language,
      notes: checks.notes,
    });
    const generated = await writeReport(result, options.outputDirectory, {
      knownSecrets,
      junitPath: options.junitPath,
      sarifPath: options.sarifPath,
    });
    printDemo(result, generated, options, knownSecrets);
    const bypassRequest = {
      ...request,
      url: `${origin}/api/auth-bypass?token=${CANARY}`,
    };
    const bypassChecks = generateChecks(bypassRequest, {
      profile: "quick",
      maxCases: 2,
      expectAuth: true,
      authContract: {
        complete: true,
        sources: [
          { in: "header", name: "Authorization" },
          { in: "query", name: "token" },
          { in: "json", pointer: "/token" },
        ],
      },
    });
    const bypass = await executeChecks(bypassRequest, bypassChecks.cases, {
      timeoutMs: options.timeoutMs,
      profile: "quick",
      language: options.language,
    });
    const bypassFiles = await writeReport(
      bypass,
      join(options.outputDirectory, "auth-bypass"),
      { knownSecrets },
    );
    printDemo(bypass, bypassFiles, options, knownSecrets);
    let idorMatches = true;
    for (const mode of ["protected", "vulnerable"] as const) {
      const config = parseIdorConfig(
        {
          authModel: "bearer-only",
          objectIdsGrantAccess: false,
          rule: "a-cannot-read-b",
          privateCanaries: true,
          identity: {
            url: `${origin}/me`,
            principalPointer: "/id",
            actorA: "actor-a",
            actorB: "actor-b",
          },
          objects: {
            pathTemplate: `/${mode}/objects/{objectId}`,
            idPointer: "/id",
            canaryPointer: "/canary",
            objectA: objects.alpha,
            objectB: objects.beta,
          },
        },
        options.language,
      );
      const objectRequest = (id: string, token: string): ParsedCurl => ({
        method: "GET",
        url: `${origin}/${mode}/objects/${id}`,
        headers: { Authorization: `Bearer ${token}` },
        body: {},
      });
      const plan = prepareIdorPlan(
        objectRequest("alpha", TOKEN_A),
        objectRequest("beta", TOKEN_B),
        config,
        options.language,
      );
      const idor = await executeIdorPlan(plan, {
        timeoutMs: options.timeoutMs,
        language: options.language,
      });
      const files = await writeReport(
        idor,
        join(options.outputDirectory, `idor-${mode}`),
        { knownSecrets: [...knownSecrets, ...plan.knownSecrets] },
      );
      printSection(`IDOR · ${mode}`, options.color);
      printDemo(idor, files, options, knownSecrets);
      idorMatches &&=
        idor.completedRequests === 5 &&
        idor.cases.at(-1)?.classification ===
          (mode === "protected" ? "PASS" : "FAIL");
    }
    const ru = options.language === "ru";
    const title = ru
      ? "BreakCurl: локальная демонстрация"
      : "BreakCurl: local demonstration";
    const examples = [
      [
        "report.html",
        ru ? "Ошибки обработки JSON" : "JSON handling",
        ru
          ? "Сервер возвращает 500 на age=null; неверный тип дает кандидата."
          : "age=null returns 500; an accepted wrong type remains a candidate.",
      ],
      [
        "auth-bypass/report.html",
        ru ? "Нарушение auth-контракта" : "Auth contract violation",
        ru
          ? "Все объявленные credentials удалены, но операция возвращает 201."
          : "All declared credentials are removed, yet the operation returns 201.",
      ],
      [
        "idor-protected/report.html",
        ru ? "IDOR: защита сработала" : "IDOR: access denied",
        ru
          ? "Два пользователя подтверждены. Чужой объект не раскрыт, ответ 403."
          : "Both identities are verified. Cross-object access returns 403 without the private marker.",
      ],
      [
        "idor-vulnerable/report.html",
        ru ? "IDOR: подтверждено раскрытие" : "IDOR: disclosure confirmed",
        ru
          ? "После четырех контролей пользователь A получил ID и приватный маркер объекта B."
          : "After four controls, A receives B’s object ID and private marker.",
      ],
    ];
    const demoPath = join(options.outputDirectory, "demo.html");
    await writeFile(
      demoPath,
      `<!doctype html><html lang="${ru ? "ru" : "en"}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${title}</title><style>body{font:17px/1.6 system-ui;background:#f4f6f8;color:#162436;max-width:920px;margin:60px auto;padding:0 24px}h1{line-height:1.2}article{background:white;border:1px solid #d9e1e8;border-radius:14px;padding:24px;margin:18px 0}a{color:#07559a;font-size:22px;font-weight:650}p{max-width:75ch}.label{font-size:13px;letter-spacing:.12em;color:#537080}</style><p class="label">BREAKCURL / LOCAL DEMO</p><h1>${title}</h1><p>${ru ? "Четыре реальных прогона на одноразовом сервере. Уязвимости внесены намеренно, данные синтетические. Сервер уже остановлен; отчеты открываются без сети." : "Four real runs against a disposable server. Vulnerabilities are intentional; all data is synthetic. The server has stopped; reports work offline."}</p>${examples.map(([url, name, explanation]) => `<article><a href="${url}">${name}</a><p>${explanation}</p></article>`).join("")}<p>${ru ? "Это учебный стенд, а не проверка вашего API. Для своего запроса запустите npx breakcurl." : "This is a fixture demonstration, not an assessment of your API. Run npx breakcurl with your own request."}</p></html>`,
      "utf8",
    );
    printFileLink(
      message(options.language, "open demo", "открыть демо"),
      demoPath,
      options.color,
    );
    const classes = new Set(result.cases.map((item) => item.classification));
    return (
      classes.has("PASS") &&
      classes.has("WARN") &&
      classes.has("FAIL") &&
      bypass.cases.every((item) => item.classification === "FAIL") &&
      bypass.cases.length === 2 &&
      idorMatches
    );
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function printDemo(
  result: RunResult,
  files: ReportFiles,
  options: DemoOptions,
  knownSecrets: string[],
): void {
  printBaseline(
    result.baseline.request.method,
    redactUrl(result.baseline.request.url, [
      ...knownSecrets,
      ...collectSensitiveValues(result.baseline.request),
    ]),
    result.baseline.response.status,
    result.baseline.response.latencyMs,
    options.color,
  );
  for (const [index, item] of result.cases.entries())
    printCaseLine(
      item,
      index,
      result.cases.length,
      options.color,
      options.language,
      knownSecrets,
    );
  printRunOutcome(result, options.color, options.language);
  printResultSummary(result.cases, options.color);
  printFileLink(
    message(options.language, "browser", "браузер"),
    files.htmlReportPath,
    options.color,
  );
  printKeyValue("json", files.jsonReportPath, options.color);
  if (files.junitPath) printKeyValue("junit", files.junitPath, options.color);
  if (files.sarifPath) printKeyValue("sarif", files.sarifPath, options.color);
}
