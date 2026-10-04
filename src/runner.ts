import type { HttpResult, ParsedCurl } from "./types.js";

const MAX_RESPONSE_BYTES = 16_384;
const UNSAFE_TRANSPORT_HEADERS = new Set([
  "content-length",
  "host",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export function isUnsafeTransportHeader(name: string): boolean {
  return UNSAFE_TRANSPORT_HEADERS.has(name.toLowerCase());
}

/** Sends one request with no retries and never writes request or response data. */
export async function sendRequest(
  request: ParsedCurl,
  timeoutMs: number,
): Promise<HttpResult> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      "Request timeout must be a positive number of milliseconds.",
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = performance.now();
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (!isUnsafeTransportHeader(name)) headers.set(name, value);
  }

  let status = 0;
  let responseHeaders: Record<string, string> = {};
  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers,
      ...(request.method === "GET"
        ? {}
        : { body: JSON.stringify(request.body) }),
      signal: controller.signal,
      redirect: "manual",
    });

    status = response.status;
    responseHeaders = Object.fromEntries(response.headers.entries());
    const bodyResult = await readResponseBody(response);
    return {
      status,
      latencyMs: Math.round(performance.now() - startedAt),
      headers: responseHeaders,
      ...bodyResult,
      timedOut: false,
    };
  } catch {
    const timedOut = controller.signal.aborted;
    return {
      status,
      latencyMs: Math.round(performance.now() - startedAt),
      headers: responseHeaders,
      body: "",
      timedOut,
      connectionError: timedOut ? "Request timed out." : "Connection failed.",
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function readResponseBody(
  response: Response,
): Promise<{ body: string; bodyTruncated: boolean }> {
  if (!response.body) return { body: "", bodyTruncated: false };

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let remaining = MAX_RESPONSE_BYTES;
  let bodyTruncated = false;

  try {
    // Read once beyond an exact-size body to distinguish EOF from truncation.
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      if (value.byteLength <= remaining) {
        chunks.push(value);
        remaining -= value.byteLength;
      } else {
        chunks.push(value.slice(0, remaining));
        remaining = 0;
        bodyTruncated = true;
        break;
      }
    }
  } finally {
    if (bodyTruncated) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }

  return {
    // Do not replace a UTF-8 character cut at the cap with a misleading glyph.
    body: new TextDecoder().decode(concatenate(chunks), {
      stream: bodyTruncated,
    }),
    bodyTruncated,
  };
}

function concatenate(chunks: Uint8Array[]): Uint8Array {
  const size = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}
