import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { writeReport } from "../src/report.js";
import { printCaseLine } from "../src/terminal.js";
import type { RunResult } from "../src/types.js";

describe("privacy across output channels", () => {
  it("redacts both identities from case IDs, text, paths, replay, and CI reports", async () => {
    const primary = "PRIMARY_CREDENTIAL_CANARY";
    const secondary = "SECONDARY_CREDENTIAL_CANARY";
    const marker = "PRIVATE_OBJECT_CANARY";
    const fragmentSecret = "FRAGMENT_SECRET_1234";
    const response = {
      status: 200,
      latencyMs: 1,
      headers: {},
      body: `response-body-that-must-never-be-saved ${marker}`,
      timedOut: false,
    };
    const result: RunResult = {
      baseline: {
        request: {
          method: "POST",
          url: `https://example.test/${primary}#access_token=${fragmentSecret}`,
          headers: { Authorization: `Bearer ${primary}` },
          body: {},
        },
        response,
      },
      cases: [
        {
          mutation: {
            id: `custom-${primary}-${secondary}`,
            path: `$.${secondary}`,
            kind: "custom-set",
            description: `check ${primary} ${secondary} ${marker}`,
            body: {},
            headers: { Authorization: `Bearer ${secondary}` },
          },
          response,
          classification: "FAIL",
          reason: `observed ${marker}`,
        },
      ],
    };
    const directory = await mkdtemp(join(tmpdir(), "breakcurl-privacy-"));
    try {
      await writeReport(result, directory, {
        knownSecrets: [marker],
        junitPath: join(directory, "junit.xml"),
        sarifPath: join(directory, "sarif.json"),
      });
      const names = await readdir(directory, { recursive: true });
      const fileNames = names.filter((name) =>
        /\.(json|xml|md|html|curl)$/.test(name),
      );
      const content = (
        await Promise.all(
          fileNames.map((name) => readFile(join(directory, name), "utf8")),
        )
      ).join("\n");
      for (const canary of [primary, secondary, marker, fragmentSecret]) {
        expect(content).not.toContain(canary);
        expect(names.join("\n")).not.toContain(canary);
      }
      expect(content).not.toContain("response-body-that-must-never-be-saved");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const first = result.cases[0];
      if (!first) throw new Error("Expected a finding");
      printCaseLine(first, 0, 1, false, "en", [primary, secondary, marker]);
      expect(log.mock.calls.flat().join(" ")).not.toMatch(
        /CREDENTIAL_CANARY|PRIVATE_OBJECT_CANARY/,
      );
    } finally {
      log.mockRestore();
    }
  });
});
