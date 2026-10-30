import { NextResponse } from "next/server";
import { ensureScannerService } from "@/lib/scanner-service";

export const dynamic = "force-dynamic";

/** Поднимает Python-сервис сканера, если он не запущен, и возвращает его состояние. */
export async function GET() {
  const result = await ensureScannerService();
  return NextResponse.json(result);
}

export async function POST() {
  return GET();
}
