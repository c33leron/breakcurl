import { describe, expect, it } from "vitest";
import { parseCurl } from "../src/curl.js";
import {
  needsMoreShellInput,
  normalizeShellInput,
} from "../src/shell-input.js";

const URL = "https://api.example.test/users";

describe("ANSI-C quoted cURL input", () => {
  it("parses a browser-style JSON body with an apostrophe and escaped newline", () => {
    const parsed = parseCurl(
      String.raw`curl '${URL}' --data-raw $'{"name":"Bachelor\'s degree","note":"line1\\nline2"}'`,
    );

    expect(parsed.body).toEqual({
      name: "Bachelor's degree",
      note: "line1\nline2",
    });
  });

  it("keeps raw and hex-encoded shell metacharacters inert request data", () => {
    const raw = parseCurl(
      "curl 'https://api.example.test/users' --data-raw $'{\"note\":\"$(touch nope); `touch nope` | > $VALUE\"}'",
    );
    const encoded = parseCurl(
      String.raw`curl '${URL}' --data-raw $'{"note":"\x24\x28touch nope\x29\x3b \x60touch nope\x60 \x7c \x3e \x24VALUE"}'`,
    );

    const expected = { note: "$(touch nope); `touch nope` | > $VALUE" };
    expect(raw.body).toEqual(expected);
    expect(encoded.body).toEqual(expected);
  });

  it("keeps decoded apostrophes and metacharacters inside one header argument", () => {
    const parsed = parseCurl(
      String.raw`curl '${URL}' -H $'X-Probe: it\'s $safe ` +
        "`literal`" +
        " | > ;'",
    );

    expect(parsed.headers).toEqual({
      "X-Probe": "it's $safe `literal` | > ;",
    });
  });

  it("preserves word concatenation around and between ANSI-C literals", () => {
    const parsed = parseCurl(
      `curl https://api.example.test/$'us'$'ers' --header=$'X-Test: safe'`,
    );

    expect(parsed.url).toBe(URL);
    expect(parsed.headers).toEqual({ "X-Test": "safe" });
  });

  it("decodes strict hex, Unicode, and UTF-8 byte escapes", () => {
    const parsed = parseCurl(
      String.raw`curl '${URL}' -H $'X-Text: A\x41F Caf\xc3\xa9 Caf\303\251 \u20ac \U0001f680'`,
    );

    expect(parsed.headers["X-Text"]).toBe(
      "AAF Caf\u00e9 Caf\u00e9 \u20ac \ud83d\ude80",
    );
  });

  it("preserves a physical backslash-newline inside ANSI-C quoted data", () => {
    const input = "curl $'line\\\nfeed'";

    expect(normalizeShellInput(input, "en")).toBe("curl 'line\\\nfeed'");
  });

  it.each([
    String.raw`curl $'\q'`,
    String.raw`curl $'\cA'`,
    String.raw`curl $'\x4'`,
    String.raw`curl $'\xGG'`,
    String.raw`curl $'\u123'`,
    String.raw`curl $'\uD800'`,
    String.raw`curl $'\U00110000'`,
    String.raw`curl $'\401'`,
  ])("rejects unsupported, malformed, or overflowing escape: %s", (input) => {
    expect(() => normalizeShellInput(input, "en")).toThrow();
  });

  it.each([
    "curl $'\ud800'",
    String.raw`curl $'\xc3'`,
    String.raw`curl $'\xff'`,
    String.raw`curl $'\303'`,
  ])("rejects text that cannot round-trip as valid UTF-8: %s", (input) => {
    expect(() => normalizeShellInput(input, "en")).toThrow();
  });

  it.each([
    "curl https://api.example.test/\0x",
    String.raw`curl $'\0'`,
    String.raw`curl $'\000'`,
    String.raw`curl $'\x00'`,
    String.raw`curl $'\u0000'`,
    String.raw`curl $'\U00000000'`,
  ])("rejects direct or escaped NUL: %s", (input) => {
    expect(() => normalizeShellInput(input, "en")).toThrow(/NUL/);
  });
});

describe("shell syntax boundaries", () => {
  it.each([
    `curl $(touch nope) '${URL}'`,
    `curl "$(touch nope)" '${URL}'`,
    `curl \`touch nope\` '${URL}'`,
    `curl "\`touch nope\`" '${URL}'`,
  ])("rejects active command substitution: %s", (input) => {
    expect(() => parseCurl(input)).toThrow(/Command substitution/);
  });

  it.each([`curl $TARGET_URL`, `curl \${TARGET_URL}`])(
    "keeps rejecting active shell variables: %s",
    (input) => {
      expect(() => parseCurl(input)).toThrow(/Shell variables/);
    },
  );

  it("preserves ordinary single-quote apostrophe splicing", () => {
    const parsed = parseCurl(
      String.raw`curl '${URL}' --data-raw '{"name":"Bachelor'\''s degree"}'`,
    );

    expect(parsed.body).toEqual({ name: "Bachelor's degree" });
  });

  it("preserves escaped data in double quotes", () => {
    const parsed = parseCurl(
      `curl "${URL}" --data-raw "{\\"note\\":\\"\\$(literal) and \\\`literal\\\`\\"}"`,
    );

    expect(parsed.body).toEqual({ note: "$(literal) and `literal`" });
  });

  it("allows substitutions only as ordinary single-quoted data", () => {
    const parsed = parseCurl(
      `curl '${URL}' --data-raw '{"note":"$(literal) and \`literal\`"}'`,
    );

    expect(parsed.body).toEqual({ note: "$(literal) and `literal`" });
  });
});

describe("HTTP control characters decoded from ANSI-C literals", () => {
  it("allows HTTP horizontal tab inside a header value", () => {
    const parsed = parseCurl(
      String.raw`curl '${URL}' -H $'X-Probe: left\tright'`,
    );

    expect(parsed.headers["X-Probe"]).toBe("left\tright");
  });

  it.each(["a", "b", "e", "E", "f", "n", "r", "v"])(
    "rejects encoded \\%s in a header value",
    (escapeCode) => {
      expect(() =>
        parseCurl(`curl '${URL}' -H $'X-Probe: safe\\${escapeCode}unsafe'`),
      ).toThrow(/control characters/);
    },
  );

  it.each(["01", "1f", "7f"])(
    "rejects encoded byte 0x%s in a header value",
    (hex) => {
      expect(() =>
        parseCurl(`curl '${URL}' -H $'X-Probe: safe\\x${hex}unsafe'`),
      ).toThrow(/control characters/);
    },
  );

  it("checks controls before trimming the header value", () => {
    expect(() =>
      parseCurl(String.raw`curl '${URL}' -H $'X-Probe: safe\r'`),
    ).toThrow(/control characters/);
  });

  it("rejects encoded controls in cookies", () => {
    expect(() =>
      parseCurl(String.raw`curl '${URL}' --cookie $'session=safe\x1funsafe'`),
    ).toThrow(/control characters/);
  });
});

describe("interactive completeness", () => {
  it.each([
    [String.raw`curl $'it\'s complete'`, false],
    ["curl $'still open", true],
    ["curl $'trailing\\", true],
    [String.raw`curl $'bad\q'`, false],
    [String.raw`curl 'foo'\''bar'`, false],
    [`curl "foo\\"bar"`, false],
  ])("reports whether another line is needed for %s", (input, expected) => {
    expect(needsMoreShellInput(input)).toBe(expected);
  });
});
