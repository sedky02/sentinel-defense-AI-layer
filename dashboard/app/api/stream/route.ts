import fs from "node:fs";
import { resolveTracePath } from "@/lib/tracePath";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/**
 * Server-Sent Events bridge to sentinel_decisions.jsonl. On connect it
 * replays every line currently in the file (so a mid-demo browser refresh
 * still shows full history), then watches for appended lines and streams
 * each new one as its own event. Pure tail -f over a JSON-lines file --
 * no changes to the Python side are needed.
 */
export async function GET() {
  const tracePath = resolveTracePath();
  const encoder = new TextEncoder();
  let closed = false;
  let cleanup: () => void = () => {};

  const stream = new ReadableStream({
    start(controller) {
      let offset = 0;
      let seq = 0;
      let pending = "";

      const send = (event: string, data: unknown) => {
        if (closed) return;
        controller.enqueue(
          encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        );
      };

      const flushNewBytes = () => {
        if (!fs.existsSync(tracePath)) return;
        const stat = fs.statSync(tracePath);
        if (stat.size < offset) {
          // File was truncated/recreated (e.g. a fresh demo run) -- restart.
          offset = 0;
          pending = "";
          seq = 0;
          send("reset", {});
        }
        if (stat.size <= offset) return;
        const fd = fs.openSync(tracePath, "r");
        const length = stat.size - offset;
        const buffer = Buffer.alloc(length);
        fs.readSync(fd, buffer, 0, length, offset);
        fs.closeSync(fd);
        offset = stat.size;
        pending += buffer.toString("utf-8");
        const lines = pending.split("\n");
        pending = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const record = JSON.parse(line);
            record.seq = seq++;
            send("decision", record);
          } catch {
            // Ignore a partially-written line; it will be re-read once complete.
          }
        }
      };

      send("connected", { tracePath });
      flushNewBytes();

      let watcher: fs.FSWatcher | null = null;
      try {
        const dir = tracePath.substring(0, tracePath.lastIndexOf("/")) || ".";
        watcher = fs.watch(dir, (_event, filename) => {
          if (filename && !tracePath.endsWith(filename)) return;
          flushNewBytes();
        });
      } catch {
        watcher = null;
      }
      // Fallback / belt-and-suspenders poll in case fs.watch misses an event
      // (common on some filesystems); cheap since it's just a stat() call.
      const poll = setInterval(flushNewBytes, 500);
      const heartbeat = setInterval(() => send("heartbeat", {}), 15000);

      cleanup = () => {
        closed = true;
        clearInterval(poll);
        clearInterval(heartbeat);
        watcher?.close();
      };
    },
    cancel() {
      cleanup();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
