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

  try {
    const response = await fetch(request.url, {
      method: request.method,
      headers,
      body: JSON.stringify(request.body),
      signal: controller.signal,
      redirect: "manual",
    });

    return {
      status: response.status,
      latencyMs: Math.round(performance.now() - startedAt),
      headers: Object.fromEntries(response.headers.entries()),
      body: await readResponseBody(response),
      timedOut: false,
    };
  } catch {
    const timedOut = controller.signal.aborted;
    return {
      status: 0,
      latencyMs: Math.round(performance.now() - startedAt),
      headers: {},
      body: "",
      timedOut,
      connectionError: timedOut ? "Request timed out." : "Connection failed.",
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function readResponseBody(response: Response): Promise<string> {
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let remaining = MAX_RESPONSE_BYTES;

  try {
    while (remaining > 0) {
      const { done, value } = await reader.read();
      if (done) break;

      if (value.byteLength <= remaining) {
        chunks.push(value);
        remaining -= value.byteLength;
      } else {
        chunks.push(value.slice(0, remaining));
        remaining = 0;
      }
    }
  } finally {
    if (remaining === 0) await reader.cancel().catch(() => undefined);
  }

  return new TextDecoder().decode(concatenate(chunks));
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
