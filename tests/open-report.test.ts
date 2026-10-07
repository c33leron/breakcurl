import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

const execFileMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", () => ({ execFile: execFileMock }));

import { openReport, shouldOpenReport } from "../src/open-report.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");

afterEach(() => {
  execFileMock.mockReset();
  vi.restoreAllMocks();
  if (originalPlatform) {
    Object.defineProperty(process, "platform", originalPlatform);
  }
});

function platform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", {
    configurable: true,
    value,
  });
}

function processResults(
  ...results: Array<{ error?: Error | null; stdout?: string }>
): void {
  for (const result of results) {
    execFileMock.mockImplementationOnce(
      (
        _command: string,
        _args: string[],
        _options: unknown,
        callback: (error: Error | null, stdout: string, stderr: string) => void,
      ) => {
        callback(result.error ?? null, result.stdout ?? "", "");
      },
    );
  }
}

function invocation(index = 0): {
  command: string;
  args: string[];
  options: {
    encoding: string;
    env?: NodeJS.ProcessEnv;
    killSignal: string;
    shell: boolean;
    timeout: number;
    windowsHide: boolean;
  };
} {
  const call = execFileMock.mock.calls[index];
  if (!call) throw new Error(`Missing execFile call ${index}`);
  return { command: call[0], args: call[1], options: call[2] };
}

describe("automatic report opening gate", () => {
  const interactive = {
    enabled: true,
    stdinIsTTY: true,
    stdoutIsTTY: true,
    ci: undefined,
  };

  it("opens only for an enabled interactive non-CI run", () => {
    expect(shouldOpenReport(interactive)).toBe(true);
    for (const override of [
      { enabled: false },
      { stdinIsTTY: false },
      { stdinIsTTY: undefined },
      { stdoutIsTTY: false },
      { stdoutIsTTY: undefined },
      { ci: "true" },
      { ci: "1" },
      { ci: "yes" },
    ]) {
      expect(shouldOpenReport({ ...interactive, ...override })).toBe(false);
    }
  });

  it.each([undefined, "", "0", "false", "FALSE"])(
    "treats CI=%s as a non-CI run",
    (ci) => {
      expect(shouldOpenReport({ ...interactive, ci })).toBe(true);
    },
  );
});

describe("safe platform report launchers", () => {
  it("asks macOS for the HTTPS handler and opens the file with that browser", async () => {
    platform("darwin");
    processResults({ stdout: "com.apple.Safari\n" }, {});
    const path = "reports with spaces/quote' % #/отчет $(touch nope).html";

    await expect(openReport(path)).resolves.toBe(true);

    const lookup = invocation(0);
    expect(lookup.command).toBe("/usr/bin/osascript");
    expect(lookup.args.slice(0, 3)).toEqual(["-l", "JavaScript", "-e"]);
    expect(lookup.args[3]).toContain("URLForApplicationToOpenURL");
    expect(lookup.args[3]).toContain("https://breakcurl.invalid");
    expect(lookup.args[3]).not.toContain(path);

    const open = invocation(1);
    expect(open.command).toBe("/usr/bin/open");
    expect(open.args.slice(0, 2)).toEqual(["-b", "com.apple.Safari"]);
    expect(fileURLToPath(open.args[2] ?? "")).toBe(resolve(path));
    expect(open.args[2]).toContain("%20");
    expect(open.args[2]).toContain("%25");
    expect(open.args[2]).toContain("%23");
    expect(open.options.shell).toBe(false);
    expect(open.options.timeout).toBeGreaterThan(0);
  });

  it.each(["", "com.apple.Safari\nmalicious", "-bad.bundle", "bad bundle"])(
    "rejects an invalid macOS bundle id without launching it: %s",
    async (bundleId) => {
      platform("darwin");
      processResults({ stdout: bundleId });

      await expect(openReport("report.html")).resolves.toBe(false);
      expect(execFileMock).toHaveBeenCalledTimes(1);
    },
  );

  it("returns false when the macOS lookup or browser launch fails", async () => {
    platform("darwin");
    processResults({ error: new Error("lookup failed") });
    await expect(openReport("report.html")).resolves.toBe(false);
    expect(execFileMock).toHaveBeenCalledTimes(1);

    execFileMock.mockReset();
    processResults(
      { stdout: "org.mozilla.firefox" },
      { error: new Error("launch failed") },
    );
    await expect(openReport("report.html")).resolves.toBe(false);
    expect(execFileMock).toHaveBeenCalledTimes(2);
  });

  it("passes a single encoded file URL argument to xdg-open", async () => {
    platform("linux");
    processResults({});
    const path = "--args; $(touch nope) 'quoted' #100%.html";

    await expect(openReport(path)).resolves.toBe(true);

    const open = invocation();
    expect(open.command).toBe("xdg-open");
    expect(open.args).toHaveLength(1);
    expect(fileURLToPath(open.args[0] ?? "")).toBe(resolve(path));
    expect(open.options.shell).toBe(false);
  });

  it("uses a fixed PowerShell program and script with the URL only in env", async () => {
    platform("win32");
    processResults({});
    const path = "report '$(touch nope)' #100%.html";

    await expect(openReport(path)).resolves.toBe(true);

    const open = invocation();
    expect(open.command).toBe("powershell.exe");
    expect(open.args.slice(0, 3)).toEqual([
      "-NoProfile",
      "-NonInteractive",
      "-Command",
    ]);
    expect(open.args[3]).toContain("$ErrorActionPreference = 'Stop'");
    expect(open.args[3]).toContain("UseShellExecute = $true");
    expect(open.args[3]).toContain(
      "[void][System.Diagnostics.Process]::Start($info)",
    );
    expect(open.args[3]).not.toContain("$null");
    expect(open.args.join(" ")).not.toContain(path);
    const url = open.options.env?.BREAKCURL_REPORT_URL ?? "";
    expect(url).toMatch(/^file:\/\//);
    expect(fileURLToPath(url)).toBe(resolve(path));
    expect(open.options.shell).toBe(false);
  });

  it("returns false on launch errors and configured timeouts", async () => {
    platform("linux");
    const timeout = Object.assign(new Error("timed out"), {
      code: "ETIMEDOUT",
      killed: true,
    });
    processResults({ error: timeout });

    await expect(openReport("report.html")).resolves.toBe(false);
    expect(invocation().options.timeout).toBe(4_000);
    expect(invocation().options.killSignal).toBe("SIGKILL");
  });

  it("absorbs synchronous launcher failures", async () => {
    platform("linux");
    execFileMock.mockImplementationOnce(() => {
      throw new Error("synthetic spawn failure");
    });

    await expect(openReport("report.html")).resolves.toBe(false);
  });

  it("rejects empty, NUL, and unsupported-platform input without spawning", async () => {
    platform("linux");
    await expect(openReport("  ")).resolves.toBe(false);
    await expect(openReport("report\0.html")).resolves.toBe(false);
    platform("freebsd");
    await expect(openReport("report.html")).resolves.toBe(false);
    expect(execFileMock).not.toHaveBeenCalled();
  });
});
