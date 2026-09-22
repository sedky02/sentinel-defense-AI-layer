import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolveComplianceReportPath } from "@/lib/compliancePath";
import { resolveRepoRoot } from "@/lib/repoRoot";
import { resolveTracePath } from "@/lib/tracePath";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const execFileAsync = promisify(execFile);

export async function GET() {
  try {
    const markdown = await fs.readFile(resolveComplianceReportPath(), "utf-8");
    return Response.json({ markdown });
  } catch {
    return Response.json({ status: "not_generated" }, { status: 404 });
  }
}

export async function POST() {
  const repoRoot = resolveRepoRoot();
  const tracePath = resolveTracePath();
  const outputPath = resolveComplianceReportPath();

  try {
    await execFileAsync(
      "python3",
      ["run_compliance_check.py", tracePath, "--output", outputPath],
      { cwd: repoRoot, timeout: 15_000 },
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "generation_failed";
    return Response.json({ error: "generation_failed", message }, { status: 500 });
  }

  try {
    const markdown = await fs.readFile(outputPath, "utf-8");
    return Response.json({ markdown });
  } catch {
    return Response.json({ error: "read_failed" }, { status: 500 });
  }
}
