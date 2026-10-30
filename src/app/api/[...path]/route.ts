import { NextRequest, NextResponse } from "next/server";
import { ensureScannerService, SCANNER_PORT } from "@/lib/scanner-service";

export const dynamic = "force-dynamic";

/**
 * Единый прокси /api/* -> Python-сервис сканера (порт 3031).
 *
 * В песочнице те же запросы перехватывает Caddy-гейтвей (параметр XTransformPort).
 * Этот маршрут позволяет работать и без него — при обычном `npm run dev`
 * на http://localhost:3000 (локальный запуск без реверс-прокси).
 */

const HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

async function proxy(req: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  const { path = [] } = await ctx.params;
  const port = Number(req.nextUrl.searchParams.get("XTransformPort")) || SCANNER_PORT;

  const target = new URL(`http://127.0.0.1:${port}/api/${path.map(encodeURIComponent).join("/")}`);
  req.nextUrl.searchParams.forEach((v, k) => {
    if (k !== "XTransformPort") target.searchParams.append(k, v);
  });

  const headers = new Headers();
  req.headers.forEach((v, k) => {
    if (!HOP_HEADERS.has(k.toLowerCase())) headers.set(k, v);
  });

  const method = req.method.toUpperCase();
  let body: ArrayBuffer | undefined;
  if (method !== "GET" && method !== "HEAD") {
    const raw = await req.arrayBuffer();
    if (raw.byteLength > 0) body = raw;
  }

  try {
    const res = await fetch(target, { method, headers, body, cache: "no-store" });
    const buf = await res.arrayBuffer();
    const out = new Headers();
    const ct = res.headers.get("content-type");
    const cd = res.headers.get("content-disposition");
    if (ct) out.set("content-type", ct);
    if (cd) out.set("content-disposition", cd);
    out.set("cache-control", "no-store");
    return new NextResponse(buf, { status: res.status, headers: out });
  } catch {
    // Движок не отвечает: пробуем поднять его в фоне и объясняем, что делать.
    ensureScannerService().catch(() => {});
    return NextResponse.json(
      {
        detail:
          "Python-движок не отвечает. Он запускается автоматически — подождите 10–20 секунд и повторите попытку. Либо запустите всё скриптом: ./start.sh",
      },
      { status: 503 },
    );
  }
}

export const GET = proxy;
export const POST = proxy;
export const DELETE = proxy;
