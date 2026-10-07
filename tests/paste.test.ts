import { readFile } from "node:fs/promises";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { parseCurl } from "../src/curl.js";
import { needsMoreInput, readPastedCurl } from "../src/paste.js";

const curl = "curl 'https://example.test/users' --json '{\"name\":\"QA\"}'";

function session(terminal = true) {
  const input = new PassThrough();
  const output = Object.assign(new PassThrough(), { isTTY: terminal });
  let printed = "";
  output.on("data", (chunk) => {
    printed += String(chunk);
  });
  const result = readPastedCurl(input, output, "en");
  return { input, result, printed: () => printed };
}

describe("single-Enter cURL input", () => {
  it.each(["vacancies", "candidates"])(
    "submits the complete browser %s fixture with one Enter",
    async (kind) => {
      const command = (
        await readFile(
          new URL(`./fixtures/browser-curl/${kind}.curl`, import.meta.url),
          "utf8",
        )
      ).trimEnd();
      const expected: unknown = JSON.parse(
        await readFile(
          new URL(
            `./fixtures/browser-curl/${kind}.expected.json`,
            import.meta.url,
          ),
          "utf8",
        ),
      );
      const { input, result } = session();
      input.write(`\u001b[200~${command}\n\u001b[201~\r`);
      expect(parseCurl(await result)).toEqual(expected);
    },
  );

  it("submits ANSI-C input without bracketed-paste support", async () => {
    const command =
      'curl --url \'https://example.test\' \\\n --data-raw $\'{"text":"line1\\\\nline2","education":"Bachelor\\\'s degree"}\'';
    const { input, result } = session();
    input.write(`${command}\r`);
    expect(parseCurl(await result).body).toEqual({
      text: "line1\nline2",
      education: "Bachelor's degree",
    });
  });

  it("submits a single-line command on its first Enter", async () => {
    const { input, result } = session();
    input.write(`${curl}\r`);
    expect(await result).toBe(curl);
  });

  it("preserves browser-style line continuations without a final blank line", async () => {
    const command =
      "curl 'https://example.test/users' \\\n  -H 'Content-Type: application/json' \\\n  --data-raw '{\n\n\"name\":\"QA\"\n}'";
    const { input, result } = session();
    let finished = false;
    void result.then(() => {
      finished = true;
    });
    for (const line of command.split("\n").slice(0, -1)) {
      input.write(`${line}\r`);
      await Promise.resolve();
      expect(finished).toBe(false);
    }
    input.write(`${command.split("\n").at(-1)}\r`);
    const value = await result;
    expect(value).toBe(command);
    expect(parseCurl(value).body).toEqual({ name: "QA" });
  });

  it.each(["", "\n", "\r\n"])(
    "waits for one Enter after bracketed paste ending in %j",
    async (ending) => {
      const { input, result, printed } = session();
      let finished = false;
      void result.then(() => {
        finished = true;
      });
      input.write(`\u001b[200~${curl}${ending}\u001b[201~`);
      await Promise.resolve();
      expect(finished).toBe(false);
      input.write("\r");
      expect(await result).toBe(curl);
      expect(printed()).toContain("\u001b[?2004h");
      expect(printed()).toContain("\u001b[?2004l");
      expect(input.listenerCount("keypress")).toBe(0);
    },
  );

  it("keeps every line of a paste even if its first line is already a valid command", async () => {
    const { input, result } = session();
    input.write(`\u001b[200~${curl}\ny\n\u001b[201~\r`);
    const value = await result;
    expect(value).toBe(`${curl}\ny`);
    expect(() => parseCurl(value)).toThrow();
  });

  it("handles paste markers split across input chunks", async () => {
    const { input, result } = session();
    for (const chunk of ["\u001b[20", "0~", curl, "\n", "\u001b[201", "~"]) {
      input.write(chunk);
    }
    input.write("\r");
    expect(await result).toBe(curl);
  });

  it("returns unsupported input promptly for the normal parser error", async () => {
    const { input, result } = session();
    input.write("curl --not-supported https://example.test\r");
    const value = await result;
    expect(value).toBe("curl --not-supported https://example.test");
    expect(() => parseCurl(value)).toThrow();
  });

  it("cancels on Ctrl-C and restores terminal paste mode", async () => {
    const { input, result, printed } = session();
    const failure = expect(result).rejects.toThrow("Input canceled");
    input.write("curl 'incomplete\u0003");
    await failure;
    expect(printed()).toContain("\u001b[?2004l");
    expect(input.listenerCount("keypress")).toBe(0);
  });

  it("supports EOF and does not emit terminal controls to redirected output", async () => {
    const { input, result, printed } = session(false);
    input.end(curl);
    expect(await result).toBe(curl);
    expect(printed()).not.toContain("\u001b");
  });

  it("rejects empty EOF", async () => {
    const { input, result } = session(false);
    const failure = expect(result).rejects.toThrow("No cURL");
    input.end();
    await failure;
  });
});

describe("shell input continuation", () => {
  it.each([
    [curl, false],
    ["curl url \\", true],
    ["curl url \\\\", false],
    ["curl 'unfinished", true],
    ['curl "unfinished', true],
    ["curl 'foo'\\''bar'", false],
    ['curl "foo\\"bar"', false],
    ['curl "foo\\"bar', true],
  ])("detects continuation for %s", (value, expected) => {
    expect(needsMoreInput(value)).toBe(expected);
  });
});
