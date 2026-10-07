import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { printFileLink, safeTerminalText } from "../src/terminal.js";

const originalTTY = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  if (originalTTY) Object.defineProperty(process.stdout, "isTTY", originalTTY);
  else Reflect.deleteProperty(process.stdout, "isTTY");
});

function captureLink(tty: boolean, color: boolean, path: string): string {
  Object.defineProperty(process.stdout, "isTTY", {
    configurable: true,
    value: tty,
  });
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  printFileLink("browser", path, color);
  return String(log.mock.calls.at(-1)?.[0]);
}

describe("terminal report links", () => {
  it.each([
    [false, false],
    [false, true],
    [true, false],
  ])(
    "prints an encoded file URL without OSC links for tty=%s color=%s",
    (tty, color) => {
      const path = "reports with spaces/#100%/отчет.html";
      const line = captureLink(tty, color, path);
      const url = line.slice(line.indexOf("file://"));
      expect(fileURLToPath(url)).toBe(resolve(path));
      expect(url).toContain("%20");
      expect(url).toContain("%23");
      expect(url).toContain("%25");
      expect(line).not.toContain("\u001b]8");
      expect(line).not.toContain("\u001b");
    },
  );

  it("wraps a visible file URL in a balanced hyperlink on an interactive terminal", () => {
    vi.stubEnv("TERM", "xterm-256color");
    const line = captureLink(true, true, "report.html");
    expect(line).toContain("\u001b[36m");
    expect(line).toContain("\u001b[4m");
    const link = line.match(
      // biome-ignore lint/suspicious/noControlCharactersInRegex: verify the OSC 8 protocol boundaries
      /\u001b\]8;;([^\u001b]+)\u001b\\([^\u001b]+)\u001b\]8;;\u001b\\/,
    );
    expect(link).not.toBeNull();
    expect(link?.[1]).toBe(link?.[2]);
    expect(fileURLToPath(link?.[1] ?? "")).toBe(resolve("report.html"));
  });

  it("uses the visible URL as a fallback for dumb terminals", () => {
    vi.stubEnv("TERM", "dumb");
    const line = captureLink(true, true, "report.html");
    expect(line).toContain("file://");
    expect(line).not.toContain("\u001b]8");
    expect(line).not.toContain("\u001b");
  });

  it("encodes control characters in paths instead of letting them control the terminal", () => {
    const path = "reports/\u001b]8;;https://example.test\u0007\nreport.html";
    const line = captureLink(true, false, path);
    const url = line.slice(line.indexOf("file://"));
    expect(fileURLToPath(url)).toBe(resolve(path));
    expect(line).not.toContain("\u001b");
    expect(line).not.toContain("\u0007");
    expect(line).not.toContain("\n");
    expect(
      safeTerminalText(
        "\u001b]8;;https://example.test\u0007text\u001b]8;;\u0007",
      ),
    ).toBe("text");
  });
});
