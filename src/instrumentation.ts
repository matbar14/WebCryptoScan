/**
 * Автозапуск Python-сервиса сканера при старте Next.js.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    try {
      const { ensureScannerService } = await import("./lib/scanner-service");
      ensureScannerService().catch(() => {});
    } catch {
      // сервис можно поднять вручную: python3 mini-services/scanner-service/server.py
    }
  }
}
