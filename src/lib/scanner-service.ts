import { spawn } from "child_process";
import path from "path";

/**
 * Управление Python mini-service сканера (порт 3031).
 * Сервис порождается как дочерний процесс Next.js, поэтому живёт,
 * пока жив dev-сервер, и автоматически поднимается при его старте
 * (см. src/instrumentation.ts и /api/scanner-boot).
 */

export const SCANNER_PORT = 3031;
const SERVICE_DIR = path.join(process.cwd(), "mini-services", "scanner-service");

let booting: Promise<boolean> | null = null;

export async function isScannerUp(timeoutMs = 1500): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(`http://127.0.0.1:${SCANNER_PORT}/api/health`, {
      signal: ctrl.signal,
      cache: "no-store",
    });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

export function spawnScanner(): void {
  const cmd = process.env.SCANNER_PYTHON || "python3";
  try {
    const child = spawn(cmd, ["server.py"], {
      cwd: SERVICE_DIR,
      detached: true,
      stdio: "ignore",
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
    });
    child.unref();
  } catch {
    // тихо: повторные попытки делает ensureScannerService
  }
}

export async function ensureScannerService(): Promise<{ ok: boolean; health?: unknown }> {
  if (await isScannerUp()) {
    return { ok: true };
  }
  if (!booting) {
    booting = (async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        spawnScanner();
        for (let i = 0; i < 24; i++) {
          await new Promise((r) => setTimeout(r, 500));
          if (await isScannerUp()) return true;
        }
      }
      return false;
    })().finally(() => {
      booting = null;
    });
  }
  const ok = await booting;
  let health: unknown;
  if (ok) {
    try {
      health = await fetch(`http://127.0.0.1:${SCANNER_PORT}/api/health`).then((r) => r.json());
    } catch {
      health = undefined;
    }
  }
  return { ok, health };
}
