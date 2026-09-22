import path from "node:path";

export function resolveComplianceReportPath(): string {
  const configured = process.env.COMPLIANCE_REPORT_PATH;
  if (configured) return path.resolve(configured);
  return path.resolve(process.cwd(), "..", "results", "eu_ai_act_alignment.md");
}
