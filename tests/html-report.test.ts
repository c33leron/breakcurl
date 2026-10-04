import { describe, expect, it } from "vitest";
import { formatHtmlReport } from "../src/html-report.js";
import { localized } from "../src/i18n.js";
import type { Classification, RunResult } from "../src/types.js";

function fixture(): RunResult {
  const response = {
    status: 200,
    latencyMs: 4,
    headers: {},
    body: '{"private":"RESPONSE_BODY_CANARY"}',
    bodyTruncated: false,
    timedOut: false,
  };
  return {
    baseline: {
      request: {
        method: "POST",
        url: "https://example.test/objects",
        headers: { Authorization: "Bearer PRIMARY_CREDENTIAL_CANARY" },
        body: { password: "REQUEST_SECRET_CANARY" },
      },
      response,
    },
    cases: (["FAIL", "WARN", "ERROR", "INFO", "PASS"] as Classification[]).map(
      (classification) => ({
        classification,
        reason: localized(
          `Evidence ${classification}`,
          `Причина ${classification}`,
        ),
        mutation: {
          id: classification,
          path: "$.name",
          kind: "null",
          body: { name: null },
          description: localized(
            `Check ${classification}`,
            `Проверка ${classification}`,
          ),
          expectation: "reject",
        },
        response,
      }),
    ),
  };
}

describe("standalone HTML report", () => {
  it("puts actionable findings before all checks and explains scope", () => {
    const result = fixture();
    const first = result.cases[0];
    if (!first) throw new Error("Missing fixture case");
    const html = formatHtmlReport(result, {
      replayByCase: new Map([[first, "findings/fail-name-null.curl"]]),
    });

    expect(html).toContain("5 checks executed");
    expect(html.indexOf('id="verdict-title"')).toBeLessThan(
      html.indexOf('id="target-title"'),
    );
    expect(html).toContain('href="findings/fail-name-null.curl"');
    expect(html.indexOf('id="findings-title"')).toBeLessThan(
      html.indexOf('id="checks-title"'),
    );
    const findings = html.slice(
      html.indexOf('id="findings-title"'),
      html.indexOf('id="checks-title"'),
    );
    expect(findings).toContain("Check FAIL");
    expect(findings).toContain("Check WARN");
    expect(findings).toContain("Check ERROR");
    expect(findings).not.toContain("Check INFO");
    expect(findings).not.toContain("Check PASS");
    expect(html).toContain("All checks and observations");
    expect(html).toContain("Next action");
    expect(html).toContain("not an assessment of the entire API");
    expect(html).toContain("<details");
    expect(html).not.toContain("RESPONSE_BODY_CANARY");
    expect(html).not.toContain("REQUEST_SECRET_CANARY");
  });

  it("redacts both identities and neutralizes malicious text without active resources", () => {
    const result = fixture();
    const first = result.cases[0];
    if (!first) throw new Error("Missing fixture case");
    const attack =
      '</script><img src="https://evil.test/pixel" onerror="alert(1)"> `code` ![image](https://evil.test/image)';
    first.mutation.description = `${attack} PRIMARY_CREDENTIAL_CANARY SECONDARY_CREDENTIAL_CANARY PRIVATE_MARKER_CANARY`;
    first.mutation.id = attack;
    first.mutation.path = attack;
    first.mutation.headers = {
      Authorization: "Bearer SECONDARY_CREDENTIAL_CANARY",
    };
    first.reason = attack;
    first.securitySignals = [
      { id: "signal", title: attack, severity: "HIGH", cwe: attack },
    ];
    result.notes = [attack];
    result.baseline.assessment = {
      classification: "WARN",
      reason: attack,
      securitySignals: first.securitySignals,
    };
    const html = formatHtmlReport(result, {
      knownSecrets: ["PRIVATE_MARKER_CANARY"],
      replayByCase: new Map([
        [first, 'javascript:alert(1)" onclick="alert(1)'],
      ]),
    });

    for (const secret of [
      "PRIMARY_CREDENTIAL_CANARY",
      "SECONDARY_CREDENTIAL_CANARY",
      "PRIVATE_MARKER_CANARY",
      "RESPONSE_BODY_CANARY",
    ])
      expect(html).not.toContain(secret);
    expect(html).toContain("&lt;/script&gt;&lt;img");
    expect(html).toContain("&quot;alert(1)&quot;");
    expect(html).not.toMatch(
      /<(?:script|img|iframe|object|embed|base|form|link)\b/i,
    );
    expect(html).not.toContain("javascript:");
    expect(html).not.toMatch(/href="https?:/);
    expect(html).toContain("default-src 'none'");
    expect(html).toContain("style-src 'unsafe-inline'");
    for (const directive of [
      "script-src",
      "connect-src",
      "object-src",
      "base-uri",
      "form-action",
    ])
      expect(html).toContain(`${directive} 'none'`);
  });

  it("localizes explanations and records incomplete evidence", () => {
    const result = fixture();
    result.language = "ru";
    result.baseline.response.bodyTruncated = true;
    const html = formatHtmlReport(result);
    expect(html).toContain('<html lang="ru">');
    expect(html).toContain("Отчет BreakCurl");
    expect(html).toContain("Причина FAIL");
    expect(html).toContain("Следующее действие");
    expect(html).toContain("Недоступен: ответ неполный");
    expect(html).toContain("Ответ превысил лимит чтения");
    expect(html).not.toContain("Evidence FAIL");
  });

  it("keeps the baseline assessment separate from request and check counts", () => {
    const result = fixture();
    result.mode = "idor";
    result.plannedRequests = 3;
    result.completedRequests = 2;
    result.cases = [];
    result.baseline.assessment = {
      classification: "FAIL",
      reason: "A signal in the baseline",
      severity: "HIGH",
      confidence: "MEDIUM",
      securitySignals: [
        {
          id: "signal",
          title: "Sensitive error signal",
          severity: "HIGH",
          cwe: "CWE-209",
        },
      ],
    };
    const html = formatHtmlReport(result);
    expect(html).toContain("Mode: idor");
    expect(html).toContain(
      "Requests attempted / planned: <strong>2 / 3</strong>",
    );
    expect(html).toContain("0 checks executed");
    expect(html).toContain("Baseline assessment");
    expect(html).toContain("Sensitive error signal");
    expect(html).toContain("CWE-209");
    expect(html).toContain("not an additional check or request");
    expect(html).toContain("Counts cover additional checks only");
  });

  it.each([
    { status: 500, connectionError: undefined },
    { status: 503, connectionError: "Response body stream failed" },
  ])(
    "shows an incomplete verdict when baseline HTTP $status stops all checks",
    ({ status, connectionError }) => {
      const result = fixture();
      result.cases = [];
      result.plannedRequests = 16;
      result.completedRequests = 1;
      result.baseline.response = {
        ...result.baseline.response,
        status,
        ...(connectionError === undefined ? {} : { connectionError }),
      };
      result.baseline.assessment = {
        classification: "FAIL",
        reason: "The server returned an error before additional checks ran.",
      };

      const html = formatHtmlReport(result);
      const verdict = html.slice(
        html.indexOf('<section class="run-verdict'),
        html.indexOf('<section class="target"'),
      );
      expect(verdict).toContain('class="run-verdict incomplete"');
      expect(verdict).toContain(
        "Requests attempted / planned: <strong>1 / 16</strong>",
      );
      expect(verdict).toContain("0 checks executed");
      expect(verdict).toContain("Next action");
      expect(html).toContain("This run is incomplete.");
      expect(html).not.toContain("No FAIL, WARN, or ERROR results");
      expect(html).toContain("The server returned an error");
    },
  );

  it("does not imply that all requests completed after a timeout", () => {
    const result = fixture();
    const failed = result.cases.find((item) => item.classification === "ERROR");
    if (!failed) throw new Error("Missing fixture case");
    failed.response = { ...failed.response, status: 0, timedOut: true };
    result.cases = [failed];
    result.plannedRequests = 16;
    result.completedRequests = 2;

    const html = formatHtmlReport(result);
    expect(html).toContain('class="run-verdict incomplete"');
    expect(html).toContain(
      "Requests attempted / planned: <strong>2 / 16</strong>",
    );
    expect(html).not.toContain("Requests completed");
    expect(html).toContain("Check ERROR");
  });

  it.each([
    {
      language: "en" as const,
      meanings: [
        "A check rule was violated; confirm the impact.",
        "A signal needs confirmation against the API contract.",
        "The check could not be fully evaluated.",
        "An observation, without a defect conclusion.",
        "This check received the expected response.",
      ],
    },
    {
      language: "ru" as const,
      meanings: [
        "Нарушено правило проверки; подтвердите влияние.",
        "Сигнал требует сверки с контрактом API.",
        "Проверку не удалось полностью оценить.",
        "Наблюдение, без вывода об ошибке.",
        "В этой проверке получен ожидаемый ответ.",
      ],
    },
  ])("explains every status in $language", ({ language, meanings }) => {
    const result = fixture();
    result.language = language;
    const html = formatHtmlReport(result);
    const guide = html.slice(
      html.indexOf('<dl class="status-guide">'),
      html.indexOf("</dl></section>"),
    );
    for (const meaning of meanings) expect(guide).toContain(meaning);
  });
});
