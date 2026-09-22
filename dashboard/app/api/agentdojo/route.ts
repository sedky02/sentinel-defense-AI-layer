import fs from "node:fs/promises";
import { resolveAgentDojoSummaryPath } from "@/lib/agentdojoPath";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  try {
    const content = await fs.readFile(resolveAgentDojoSummaryPath(), "utf-8");
    return Response.json(JSON.parse(content));
  } catch {
    return Response.json({ status: "not_executed" }, { status: 404 });
  }
}
