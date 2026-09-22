import path from "node:path";

/** Repo root next to `dashboard/`, where run_compliance_check.py lives. */
export function resolveRepoRoot(): string {
  const configured = process.env.REPO_ROOT;
  if (configured) return path.resolve(configured);
  return path.resolve(process.cwd(), "..");
}
