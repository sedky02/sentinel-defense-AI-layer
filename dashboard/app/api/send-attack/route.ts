import { resolveAdapterUrl } from "@/lib/adapterUrl";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  let payload: Record<string, unknown>;
  try {
    payload = await request.json();
  } catch {
    return Response.json({ error: "invalid_json" }, { status: 400 });
  }

  if (!payload.run_id) {
    payload.run_id = `manual-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  let response: globalThis.Response;
  try {
    response = await fetch(`${resolveAdapterUrl()}/v1/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    return Response.json({ error: "adapter_unreachable" }, { status: 502 });
  }

  const text = await response.text();
  return new Response(text, {
    status: response.status,
    headers: { "Content-Type": "application/json" },
  });
}
