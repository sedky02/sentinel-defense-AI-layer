export function resolveAdapterUrl(): string {
  return process.env.ADAPTER_URL ?? "http://127.0.0.1:8080";
}
