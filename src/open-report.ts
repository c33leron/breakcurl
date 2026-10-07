import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const OPEN_TIMEOUT_MS = 4_000;
const DEFAULT_BROWSER_SCRIPT = [
  "ObjC.import('AppKit');",
  "const workspace = $.NSWorkspace.sharedWorkspace;",
  "const url = $.NSURL.URLWithString('https://breakcurl.invalid');",
  "const applicationUrl = workspace.URLForApplicationToOpenURL(url);",
  "if (!applicationUrl) throw new Error('No default browser');",
  "const bundleId = ObjC.unwrap($.NSBundle.bundleWithURL(applicationUrl).bundleIdentifier);",
  "if (!bundleId) throw new Error('No browser bundle identifier');",
  "bundleId;",
].join("\n");
const WINDOWS_OPEN_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$info = [System.Diagnostics.ProcessStartInfo]::new()",
  "$info.FileName = $env:BREAKCURL_REPORT_URL",
  "$info.UseShellExecute = $true",
  "[void][System.Diagnostics.Process]::Start($info)",
].join("; ");
const BUNDLE_ID = /^[A-Za-z0-9][A-Za-z0-9.-]*$/;

interface OpenReportOptions {
  enabled: boolean;
  stdinIsTTY?: boolean | undefined;
  stdoutIsTTY?: boolean | undefined;
  ci?: string | undefined;
}

interface ProcessResult {
  ok: boolean;
  stdout: string;
}

export function shouldOpenReport(options: OpenReportOptions): boolean {
  const ci = options.ci?.toLowerCase();
  return (
    options.enabled &&
    options.stdinIsTTY === true &&
    options.stdoutIsTTY === true &&
    (!ci || ci === "false" || ci === "0")
  );
}

export async function openReport(filePath: string): Promise<boolean> {
  if (typeof filePath !== "string" || filePath.trim() === "") return false;
  if (filePath.includes("\0")) return false;

  const fileUrl = pathToFileURL(resolve(filePath)).href;
  if (process.platform === "darwin") return openOnMac(fileUrl);
  if (process.platform === "linux") {
    return (await run("xdg-open", [fileUrl])).ok;
  }
  if (process.platform === "win32") {
    return (
      await run(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", WINDOWS_OPEN_SCRIPT],
        {
          ...process.env,
          BREAKCURL_REPORT_URL: fileUrl,
        },
      )
    ).ok;
  }
  return false;
}

async function openOnMac(fileUrl: string): Promise<boolean> {
  const lookup = await run("/usr/bin/osascript", [
    "-l",
    "JavaScript",
    "-e",
    DEFAULT_BROWSER_SCRIPT,
  ]);
  const bundleId = lookup.stdout.trim();
  if (!lookup.ok || !BUNDLE_ID.test(bundleId)) return false;
  return (await run("/usr/bin/open", ["-b", bundleId, fileUrl])).ok;
}

async function run(
  command: string,
  args: string[],
  env?: NodeJS.ProcessEnv,
): Promise<ProcessResult> {
  try {
    return await new Promise((resolveResult) => {
      execFile(
        command,
        args,
        {
          encoding: "utf8",
          env,
          killSignal: "SIGKILL",
          maxBuffer: 16 * 1024,
          shell: false,
          timeout: OPEN_TIMEOUT_MS,
          windowsHide: true,
        },
        (error, stdout) => {
          resolveResult({ ok: error === null, stdout });
        },
      );
    });
  } catch {
    return { ok: false, stdout: "" };
  }
}
