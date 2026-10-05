import { createInterface, type Key } from "node:readline";
import { message } from "./i18n.js";
import { needsMoreShellInput } from "./shell-input.js";
import type { Language } from "./types.js";

// This checks only whether another physical line is needed. parseCurl still
// validates the complete command; no part of the input is executed by a shell.
export const needsMoreInput = needsMoreShellInput;

export async function readPastedCurl(
  input: NodeJS.ReadableStream,
  output: NodeJS.WritableStream & { isTTY?: boolean },
  language: Language,
): Promise<string> {
  output.write(
    message(
      language,
      "Paste the complete Copy as cURL command, then press Enter:\n\n",
      "Вставьте Copy as cURL целиком, затем нажмите Enter:\n\n",
    ),
  );
  const terminal = output.isTTY === true;
  const reader = createInterface({ input, output, terminal });
  const lines: string[] = [];
  let pasting = false;
  const onKeypress = (_text: string, key: Key) => {
    if (key.name === "paste-start") pasting = true;
    if (key.name === "paste-end") pasting = false;
  };
  if (terminal) {
    input.on("keypress", onKeypress);
    output.write("\u001b[?2004h");
  }
  try {
    const value = await new Promise<string>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        reader.close();
        if (error) reject(error);
        else resolve(lines.join("\n").trim());
      };
      // Handle lines synchronously: one paste can emit many lines and its end
      // marker in the same chunk, before an async iterator resumes.
      reader.on("line", (line) => {
        if (settled) return;
        lines.push(line);
        const value = lines.join("\n");
        if (!pasting && value.trim() && !needsMoreInput(value)) finish();
      });
      reader.once("close", () => finish());
      reader.once("error", finish);
      reader.once("SIGINT", () =>
        finish(
          new Error(
            message(
              language,
              "Input canceled. Nothing was sent.",
              "Ввод отменен. Ничего не отправлено.",
            ),
          ),
        ),
      );
    });
    if (!value) {
      throw new Error(
        message(language, "No cURL was provided.", "cURL не был введен."),
      );
    }
    return value;
  } finally {
    input.removeListener("keypress", onKeypress);
    reader.close();
    if (terminal) output.write("\u001b[?2004l");
  }
}
