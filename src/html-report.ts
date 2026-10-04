import { responseSchemaFingerprint } from "./classify.js";
import { message, renderText } from "./i18n.js";
import { requestForCase } from "./mutations.js";
import {
  collectSensitiveValues,
  redactText,
  sanitizeRequest,
} from "./redact.js";
import { summarizeRun } from "./run-summary.js";
import type { CaseResult, Classification, RunResult } from "./types.js";

export interface HtmlReportOptions {
  knownSecrets?: string[];
  replayByCase?: ReadonlyMap<CaseResult, string>;
}

/** A standalone, passive document. Response bodies never enter the template. */
export function formatHtmlReport(
  result: RunResult,
  options: HtmlReportOptions = {},
): string {
  const language = result.language === "ru" ? "ru" : "en";
  const t = (en: string, ru: string) => message(language, en, ru);
  const knownSecrets = [
    ...(options.knownSecrets ?? []),
    ...collectSensitiveValues(result.baseline.request),
    ...result.cases.flatMap((item) =>
      collectSensitiveValues(
        requestForCase(result.baseline.request, item.mutation),
      ),
    ),
  ];
  // Redaction happens before escaping, including for labels and metadata.
  const text = (value: unknown) =>
    escapeHtml(redactText(String(value), knownSecrets));
  const localized = (value: CaseResult["reason"]) =>
    text(renderText(value, language));
  const request = sanitizeRequest(result.baseline.request, knownSecrets);
  const response = result.baseline.response;
  const summary = summarizeRun(result);
  const statuses: Classification[] = ["FAIL", "WARN", "ERROR", "INFO", "PASS"];
  const counts = Object.fromEntries(
    statuses.map((status) => [
      status,
      result.cases.filter((item) => item.classification === status).length,
    ]),
  );
  const findings = result.cases.filter((item) =>
    ["FAIL", "WARN", "ERROR"].includes(item.classification),
  );
  const fingerprint = (item: CaseResult["response"]) => {
    if (item.bodyOmitted)
      return t(
        "Not retained: private response discarded after the oracle.",
        "Не сохраняется: приватный ответ удален после проверки критерия.",
      );
    const value = responseSchemaFingerprint(item);
    return value === null
      ? t(
          "Unavailable: response incomplete or transport failed.",
          "Недоступен: ответ неполный или произошла ошибка передачи.",
        )
      : value;
  };
  const nextAction = (item: Pick<CaseResult, "classification">) => {
    if (item.classification === "ERROR")
      return t(
        "Resolve the transport or run error, then repeat this check. The expected behavior could not be fully evaluated.",
        "Устраните ошибку передачи или запуска и повторите проверку. Ожидаемое поведение не удалось полностью оценить.",
      );
    if (item.classification === "FAIL")
      return t(
        "Reproduce with authorized test data and compare the expected rule with server logs and final state. Confirm impact before treating this as a vulnerability.",
        "Повторите на разрешенных тестовых данных, сверьте ожидаемое правило с логами сервера и итоговым состоянием. Подтвердите влияние до вывода об уязвимости.",
      );
    if (item.classification === "WARN")
      return t(
        "Review the API contract and final state, then repeat with a control request. This signal needs confirmation.",
        "Сверьте контракт API и итоговое состояние, затем повторите с контрольным запросом. Этот сигнал требует подтверждения.",
      );
    if (item.classification === "INFO")
      return t(
        "Compare this observation with the intended API behavior. An accepted input alone does not establish a defect.",
        "Сопоставьте наблюдение с ожидаемым поведением API. Сам факт принятия данных не доказывает дефект.",
      );
    return t(
      "The expected response was observed for this check. Keep this case as a regression check; coverage remains limited to the executed requests.",
      "Для этой проверки получен ожидаемый ответ. Сохраните случай для регрессии; охват ограничен выполненными запросами.",
    );
  };
  const expectation = (item: CaseResult) => {
    switch (item.mutation.expectation) {
      case "reject":
        return t("Reject this input", "Отклонить эти данные");
      case "accept":
        return t("Accept this input", "Принять эти данные");
      case "auth-reject":
        return t(
          "Reject unauthorized access",
          "Отклонить неавторизованный доступ",
        );
      case "observe":
        return t(
          "Observe; no rejection rule asserted",
          "Наблюдение; обязательное отклонение не задано",
        );
      default:
        return t(
          "Default mutation classification rules",
          "Стандартные правила оценки мутаций",
        );
    }
  };
  const evidence = (item: CaseResult) => {
    const path = options.replayByCase?.get(item);
    // Only generated local replay filenames may become links. Targets are plain text.
    const replay =
      path && /^findings\/[a-z0-9-]+\.curl$/.test(path)
        ? `<a class="replay" href="${text(path)}">${t("Open sanitized replay cURL", "Открыть очищенный cURL для повтора")}</a>`
        : "";
    const signals = (item.securitySignals ?? [])
      .map(
        (signal) =>
          `<li>${localized(signal.title)}${signal.cwe ? ` · ${text(signal.cwe)}` : ""}</li>`,
      )
      .join("");
    return `<div class="evidence">
      <p class="reason">${localized(item.reason)}</p>
      <dl class="facts">
        <div><dt>${t("Expected", "Ожидание")}</dt><dd>${text(expectation(item))}</dd></div>
        <div><dt>HTTP</dt><dd>${text(item.response.status || t("No response", "Нет ответа"))}</dd></div>
        <div><dt>${t("Time", "Время")}</dt><dd>${text(item.response.latencyMs)} ${t("ms", "мс")}</dd></div>
        <div><dt>${t("Category", "Категория")}</dt><dd>${text(item.mutation.category ?? "negative")}</dd></div>
        <div><dt>${t("Field / selector", "Поле / селектор")}</dt><dd><code>${text(item.mutation.path)}</code></dd></div>
        ${item.severity ? `<div><dt>${t("Risk", "Риск")}</dt><dd>${text(item.severity)}</dd></div>` : ""}
        ${item.confidence ? `<div><dt>${t("Confidence", "Уверенность")}</dt><dd>${text(item.confidence)}</dd></div>` : ""}
      </dl>
      ${signals ? `<ul class="signals">${signals}</ul>` : ""}
      ${item.response.bodyTruncated ? `<p class="notice">${t("The response exceeded the capture limit. Body-dependent evidence is incomplete.", "Ответ превысил лимит чтения. Доказательства, зависящие от тела ответа, неполные.")}</p>` : ""}
      <p class="action"><strong>${t("Next action", "Следующее действие")}</strong> ${text(nextAction(item))}</p>
      ${replay}
      <details class="technical"><summary>${t("Response metadata", "Метаданные ответа")}</summary><p>${t("Structure fingerprint", "Fingerprint структуры")}: <code>${text(fingerprint(item.response))}</code></p><p>${t("Check ID", "ID проверки")}: <code>${text(item.mutation.id)}</code></p></details>
    </div>`;
  };
  const badge = (item: Pick<CaseResult, "classification">) =>
    `<span class="badge ${statuses.includes(item.classification) ? item.classification.toLowerCase() : "info"}">${text(item.classification)}</span>`;
  const title = t("BreakCurl report", "Отчет BreakCurl");
  const notes = (result.notes ?? [])
    .map((note) => `<li>${localized(note)}</li>`)
    .join("");
  const baselineAssessment = result.baseline.assessment;
  const baselineSection = baselineAssessment
    ? `<section aria-labelledby="baseline-assessment-title"><h2 id="baseline-assessment-title">${t("Baseline assessment", "Оценка исходного запроса")}</h2><article class="finding"><h3>${badge(baselineAssessment)} <span>${t("Existing baseline response", "Уже полученный исходный ответ")}</span></h3><div class="evidence"><p class="reason">${localized(baselineAssessment.reason)}</p>${baselineAssessment.severity ? `<p>${t("Risk", "Риск")}: ${text(baselineAssessment.severity)}${baselineAssessment.confidence ? ` · ${t("Confidence", "Уверенность")}: ${text(baselineAssessment.confidence)}` : ""}</p>` : ""}<ul class="signals">${(baselineAssessment.securitySignals ?? []).map((signal) => `<li>${localized(signal.title)}${signal.cwe ? ` · ${text(signal.cwe)}` : ""}</li>`).join("")}</ul><p class="action"><strong>${t("Next action", "Следующее действие")}</strong> ${text(nextAction(baselineAssessment))}</p><p class="muted">${t("Uses the baseline already sent; it is not an additional check or request.", "Используется уже отправленный исходный запрос; это не дополнительная проверка или запрос.")}</p></div></article></section>`
    : "";
  const requestCounts = `<p class="run-counts">${t("Requests attempted / planned", "Запросов начато / запланировано")}: <strong>${text(summary.requestsAttempted)} / ${text(summary.requestsPlanned ?? "—")}</strong> · ${text(summary.checksRun)} ${t("checks executed", "проверок выполнено")}</p>`;
  const statusMeanings: Record<Classification, string> = {
    FAIL: t(
      "A check rule was violated; confirm the impact.",
      "Нарушено правило проверки; подтвердите влияние.",
    ),
    WARN: t(
      "A signal needs confirmation against the API contract.",
      "Сигнал требует сверки с контрактом API.",
    ),
    ERROR: t(
      "The check could not be fully evaluated.",
      "Проверку не удалось полностью оценить.",
    ),
    INFO: t(
      "An observation, without a defect conclusion.",
      "Наблюдение, без вывода об ошибке.",
    ),
    PASS: t(
      "This check received the expected response.",
      "В этой проверке получен ожидаемый ответ.",
    ),
  };
  const emptyFindings =
    summary.status === "incomplete"
      ? t(
          "This run is incomplete. Review the overall result and baseline above before drawing a conclusion.",
          "Запуск не завершен. Перед выводами проверьте итог запуска и исходный ответ выше.",
        )
      : result.cases.length === 0
        ? t(
            "No additional checks were executed. The baseline above is the only available evidence.",
            "Дополнительные проверки не выполнялись. Доступен только исходный ответ выше.",
          )
        : baselineAssessment &&
            ["FAIL", "WARN", "ERROR"].includes(
              baselineAssessment.classification,
            )
          ? t(
              "No additional findings in these checks. The baseline assessment above still needs attention.",
              "В этих проверках дополнительных находок нет. Оценка исходного ответа выше требует внимания.",
            )
          : t(
              "No FAIL, WARN, or ERROR results in the executed checks. This does not establish that the API is secure.",
              "В выполненных проверках нет FAIL, WARN или ERROR. Это не доказывает безопасность API.",
            );

  return `<!doctype html>
<html lang="${language}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>${title}</title>
<style>${STYLES}</style>
</head>
<body><main>
<header><p class="eyebrow">BREAKCURL / ${t("REQUEST EVIDENCE", "РЕЗУЛЬТАТЫ ПРОВЕРОК")}</p><h1>${title}</h1></header>
<section class="run-verdict ${summary.status}" data-outcome="${summary.status}" aria-labelledby="verdict-title"><p class="eyebrow">${t("OVERALL RESULT", "ИТОГ ЗАПУСКА")}</p><h2 id="verdict-title">${localized(summary.title)}</h2><p>${localized(summary.explanation)}</p>${requestCounts}<p class="action"><strong>${t("Next action", "Следующее действие")}</strong> ${localized(summary.nextAction)}</p></section>
<section class="target" aria-labelledby="target-title"><h2 id="target-title">${t("Target and baseline", "Цель и исходный запрос")}</h2><p class="target-url"><strong>${text(request.method)}</strong> <code>${text(request.url)}</code></p><p class="muted">${t("Mode", "Режим")}: ${text(result.mode ?? "checks")} · ${t("Profile", "Профиль")}: ${text(result.profile ?? "quick")} · HTTP ${text(response.status || t("No response", "Нет ответа"))} · ${text(response.latencyMs)} ${t("ms", "мс")}</p><details class="technical"><summary>${t("Baseline metadata", "Метаданные исходного запроса")}</summary><p>${t("Structure fingerprint", "Fingerprint структуры")}: <code>${text(fingerprint(response))}</code></p>${response.bodyTruncated ? `<p>${t("Response capture was truncated.", "Тело ответа прочитано не полностью.")}</p>` : ""}</details></section>
<section aria-labelledby="summary-title"><h2 id="summary-title">${t("Check results", "Результаты проверок")}</h2><p class="muted">${t("Counts cover additional checks only. The baseline is assessed separately below.", "Счетчики относятся только к дополнительным проверкам. Исходный ответ оценивается отдельно ниже.")}</p><div class="counts">${statuses.map((status) => `<div class="count ${status.toLowerCase()}"><strong>${text(counts[status])}</strong><span>${status}</span></div>`).join("")}</div><dl class="status-guide">${statuses.map((status) => `<div><dt>${badge({ classification: status })}</dt><dd>${text(statusMeanings[status])}</dd></div>`).join("")}</dl></section>
${baselineSection}
<section aria-labelledby="findings-title"><div class="section-heading"><h2 id="findings-title">${t("Checks needing attention", "Проверки, требующие внимания")}</h2>${findings.length ? `<span>${text(findings.length)}</span>` : ""}</div>${findings.length ? findings.map((item) => `<article class="finding"><h3>${badge(item)} <span>${localized(item.mutation.description)}</span></h3>${evidence(item)}</article>`).join("\n") : `<p class="empty">${text(emptyFindings)}</p>`}</section>
<section aria-labelledby="checks-title"><h2 id="checks-title">${t("All checks and observations", "Все проверки и наблюдения")}</h2><p class="muted">${t("Expand a check for its expectation, evidence, and next action.", "Раскройте проверку, чтобы увидеть ожидание, доказательства и следующее действие.")}</p>${result.cases.length ? result.cases.map((item) => `<details class="check"><summary>${badge(item)} <span>${localized(item.mutation.description)}</span><span class="http">HTTP ${text(item.response.status || "—")}</span></summary>${evidence(item)}</details>`).join("\n") : `<p class="empty">${t("No checks were executed.", "Проверки не выполнялись.")}</p>`}</section>
<section class="limitations" aria-labelledby="limitations-title"><h2 id="limitations-title">${t("Scope and limitations", "Охват и ограничения")}</h2><ul><li>${t("Results apply only to the target, input, credentials, and requests used in this run. They are not an assessment of the entire API's security.", "Результаты относятся только к цели, данным, учетным данным и запросам этого запуска. Они не оценивают безопасность всего API.")}</li><li>${t("A response status or heuristic signal alone does not prove a vulnerability or the final business state. Confirm findings against the contract and server-side evidence.", "Статус ответа или эвристический сигнал сами по себе не доказывают уязвимость или итоговое бизнес-состояние. Сверяйте находки с контрактом и данными сервера.")}</li><li>${t("API response bodies are not saved. Known credentials and sensitive values are redacted. Replay files contain sanitized requests; supply your own authorized test credentials before use.", "Тела ответов API не сохраняются. Известные учетные данные и чувствительные значения скрыты. Файлы повтора содержат очищенные запросы; перед использованием подставьте свои разрешенные тестовые учетные данные.")}</li><li>${t("Structure fingerprints are unavailable for truncated responses and transport failures. Equal fingerprints do not prove equal objects or authorized access.", "Fingerprint структуры недоступен для неполных ответов и ошибок передачи. Совпадение fingerprint не доказывает совпадение объектов или разрешенный доступ.")}</li>${notes}</ul></section>
<footer>${t("Generated by BreakCurl · Standalone report · No scripts or external resources", "Создано BreakCurl · Автономный отчет · Без скриптов и внешних ресурсов")}</footer>
</main></body></html>\n`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const STYLES = `
:root{color-scheme:light dark;--bg:#f5f6f8;--surface:#fff;--ink:#202a36;--muted:#596675;--border:#d9dfe6;--accent:#245d83;--fail:#a62539;--warn:#855300;--pass:#216440;--info:#435b77;--error:#79418b}
.run-verdict{background:var(--surface);border:1px solid var(--border);border-left:5px solid var(--accent);border-radius:14px;padding:24px}.run-verdict h2{font-size:clamp(24px,3vw,32px);margin-bottom:12px}.run-verdict.incomplete{border-left-color:var(--error)}.run-verdict.findings{border-left-color:var(--fail)}.run-verdict.review{border-left-color:var(--warn)}.run-verdict.complete{border-left-color:var(--pass)}.run-verdict .action{margin-bottom:0}.run-counts{font-size:14px;color:var(--muted);font-variant-numeric:tabular-nums}.status-guide{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 24px;margin:18px 0 0;font-size:13px}.status-guide>div{display:flex;align-items:baseline;gap:10px}.status-guide dt{flex:none}.status-guide dd{margin:0;color:var(--muted)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1120px;margin:auto;padding:52px 28px 28px}header{margin-bottom:32px}.eyebrow{font-size:11px;letter-spacing:.16em;font-weight:750;color:var(--accent)}h1{font-size:clamp(30px,4vw,46px);line-height:1.15;letter-spacing:-.03em;margin:10px 0 14px}h2{font-size:21px;margin:0 0 16px;line-height:1.3}h3{font-size:17px;display:flex;align-items:flex-start;gap:12px;margin:0;padding:20px 22px;border-bottom:1px solid var(--border)}p{margin:0 0 12px}.subtitle,.muted{color:var(--muted)}section{margin:0 0 34px}.target,.limitations{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px}.target-url{display:flex;gap:14px;align-items:baseline}.target-url strong{color:var(--accent)}code{font: .9em/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.count{border:1px solid var(--border);border-top:3px solid currentColor;background:var(--surface);border-radius:10px;padding:14px 18px;display:flex;justify-content:space-between;align-items:baseline;gap:8px}.count strong{font-size:30px;line-height:1.2}.count span{font-size:12px;font-weight:750;letter-spacing:.05em}.fail{color:var(--fail)}.warn{color:var(--warn)}.pass{color:var(--pass)}.info{color:var(--info)}.error{color:var(--error)}.section-heading{display:flex;align-items:baseline;justify-content:space-between;gap:12px}.section-heading>span{font-variant-numeric:tabular-nums;color:var(--muted)}.finding,.check{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin:0 0 12px;overflow:hidden}.badge{font-size:11px;line-height:1.8;font-weight:800;letter-spacing:.04em;border:1px solid currentColor;border-radius:5px;padding:1px 8px;flex:none}.evidence{padding:20px 22px}.reason{font-weight:600;white-space:pre-wrap;overflow-wrap:anywhere}.facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px 24px;margin:20px 0}.facts dt{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:650}.facts dd{margin:3px 0 0;overflow-wrap:anywhere}.action{border-left:3px solid var(--accent);padding:10px 14px;background:var(--bg);font-size:14px}.action strong{display:block}.replay{display:inline-block;font-size:14px;color:var(--accent);margin:6px 0 10px;text-underline-offset:3px}.technical{font-size:13px;color:var(--muted);margin-top:10px}.technical summary{cursor:pointer;display:list-item;padding:0}.technical p{margin:8px 0;overflow-wrap:anywhere}.check>summary{cursor:pointer;display:flex;align-items:baseline;gap:12px;padding:17px 22px}.check>summary::before{content:"+";color:var(--muted);font-weight:600}.check[open]>summary::before{content:"−"}.check[open]>summary{border-bottom:1px solid var(--border)}summary>span:not(.badge){overflow-wrap:anywhere}.http{font-size:12px;color:var(--muted);margin-left:auto;flex:none}.notice{color:var(--warn);border:1px solid var(--border);padding:10px 14px;border-radius:6px}.empty{padding:22px;border:1px dashed var(--border);border-radius:12px;color:var(--muted)}ul{padding-left:22px;margin:0}li+li{margin-top:10px}li{overflow-wrap:anywhere}.signals{font-size:14px;margin-bottom:16px}footer{padding-top:20px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}a:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:4px}
@media(prefers-color-scheme:dark){:root{--bg:#141a22;--surface:#1c2530;--ink:#e5ebf2;--muted:#adbac9;--border:#354151;--accent:#8bc9ee;--fail:#ff9bab;--warn:#e6bf7b;--pass:#93d9af;--info:#b2cbed;--error:#d9adeb}}
@media(max-width:680px){main{padding:28px 16px}.counts{grid-template-columns:repeat(3,1fr);gap:8px}.count{padding:12px;display:block}.count strong,.count span{display:block}.facts{grid-template-columns:repeat(2,minmax(0,1fr))}.target,.limitations,.run-verdict{padding:20px}.status-guide{grid-template-columns:1fr}.target-url{display:block}.target-url strong{display:block}.check>summary{flex-wrap:wrap;padding:16px}.http{margin-left:24px}.evidence,h3{padding:16px}h3{flex-wrap:wrap}}
@media print{:root{color-scheme:light;--bg:#fff;--surface:#fff;--ink:#111;--muted:#444;--border:#ccc;--accent:#245d83}main{max-width:none;padding:0}.finding,.check{break-inside:avoid}a{color:inherit}}
`;
