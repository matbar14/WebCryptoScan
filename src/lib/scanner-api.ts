/**
 * Клиент API Python-сервиса сканера (порт 3031 через Caddy-гейтвей).
 * Все запросы — относительные пути с параметром XTransformPort.
 */

export const SCANNER_PORT = 3031;

export function apiUrl(path: string): string {
  const sep = path.includes("?") ? "&" : "?";
  return `/api/${path.replace(/^\/+/, "")}${sep}XTransformPort=${SCANNER_PORT}`;
}

// --- Типы ---------------------------------------------------------------------

export type FindingType =
  | "wif_compressed"
  | "wif_uncompressed"
  | "mini_private_key"
  | "hex_private_key"
  | `bip39_seed_phrase_${number}`
  | `address_${string}`;

export interface Finding {
  id: number;
  image: string;
  qr_index: number;
  type: FindingType;
  value: string;
  address?: string;
  address_uncompressed?: string;
  addresses?: Record<string, string>;
  wif?: string;
  valid_checksum?: boolean;
  word_count?: number;
  engine: string;
  variant: string;
  bbox: [number, number, number, number];
  detail?: string;
}

export interface CrawlInfo {
  keywords?: Record<
    string,
    { engines: Record<string, { count: number; error: string | null; note?: string | null }>; total: number }
  >;
  total?: number;
}

export interface JobStats {
  images: number;
  qr_codes: number;
  findings: number;
  by_type: Record<string, number>;
  valid_seeds: number;
  invalid_seeds: number;
  qr_images?: string[];
}

export interface Job {
  id: string;
  label: string;
  source_type: "upload" | "folder" | "crawl" | "site";
  status: "queued" | "crawling" | "running" | "done" | "error";
  phase: "crawl" | "scan" | "done";
  created_at: string;
  finished_at?: string | null;
  progress: { total: number; processed: number };
  stats: JobStats;
  findings: Finding[];
  errors: { image: string; error: string }[];
  options: Record<string, boolean>;
  crawl?: CrawlInfo | null;
  error?: string | null;
}

export interface Preset {
  label: string;
  keywords: string[];
}

export interface ScanOptions {
  preprocess: boolean;
  detect_wif: boolean;
  detect_mini: boolean;
  detect_hex: boolean;
  detect_seed: boolean;
  detect_seedqr: boolean;
  detect_electrum: boolean;
  detect_addresses: boolean;
}

export const DEFAULT_OPTIONS: ScanOptions = {
  preprocess: true,
  detect_wif: true,
  detect_mini: true,
  detect_hex: true,
  detect_seed: true,
  detect_seedqr: true,
  detect_electrum: true,
  detect_addresses: true,
};

export interface JobSummary {
  id: string;
  label: string;
  source_type: string;
  status: string;
  created_at: string;
  stats: JobStats;
}

// --- Запросы --------------------------------------------------------------------

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || body.error || detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export async function bootService(): Promise<{ ok: boolean; health?: unknown }> {
  const res = await fetch("/api/scanner-boot", { cache: "no-store" });
  return handle<{ ok: boolean; health?: unknown }>(res);
}

export async function getPresets(): Promise<Record<string, Preset>> {
  const res = await fetch(apiUrl("presets"), { cache: "no-store" });
  return handle<Record<string, Preset>>(res);
}

export async function getJobs(): Promise<JobSummary[]> {
  const res = await fetch(apiUrl("jobs"), { cache: "no-store" });
  return handle<JobSummary[]>(res);
}

export async function getJob(id: string): Promise<Job> {
  const res = await fetch(apiUrl(`jobs/${id}`), { cache: "no-store" });
  return handle<Job>(res);
}

export async function deleteJob(id: string): Promise<void> {
  const res = await fetch(apiUrl(`jobs/${id}`), { method: "DELETE" });
  return handle<void>(res);
}

export async function scanUpload(files: File[], options: ScanOptions, label: string): Promise<string> {
  const fd = new FormData();
  files.forEach((f) => fd.append("files", f));
  fd.append("options", JSON.stringify(options));
  fd.append("label", label);
  const res = await fetch(apiUrl("scan/upload"), { method: "POST", body: fd });
  const body = await handle<{ job_id: string }>(res);
  return body.job_id;
}

export async function scanFolder(path: string, options: ScanOptions): Promise<{ job_id: string; images: number }> {
  const res = await fetch(apiUrl("scan/folder"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path, options }),
  });
  return handle<{ job_id: string; images: number }>(res);
}

export async function scanCrawl(params: {
  keyword?: string;
  preset?: string;
  engines: string[];
  max_num: number;
  options: ScanOptions;
}): Promise<{ job_id: string; keywords: string[]; max_num: number }> {
  const res = await fetch(apiUrl("scan/crawl"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  return handle<{ job_id: string; keywords: string[]; max_num: number }>(res);
}

export async function scanSite(params: {
  url: string;
  archive: "auto" | "yes" | "no";
  max_num: number;
  options: ScanOptions;
}): Promise<{ job_id: string; url: string; archive: string; max_num: number }> {
  const res = await fetch(apiUrl("scan/site"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  return handle<{ job_id: string; url: string; archive: string; max_num: number }>(res);
}

// --- Хелперы UI -------------------------------------------------------------------

export const TYPE_LABELS: Record<string, string> = {
  wif_compressed: "WIF (сжатый)",
  wif_uncompressed: "WIF (несжатый)",
  mini_private_key: "Mini-ключ",
  hex_private_key: "Hex-ключ",
  address_btc_p2pkh: "Адрес BTC (Legacy)",
  address_btc_p2sh: "Адрес BTC (P2SH)",
  address_btc_segwit: "Адрес BTC (SegWit)",
  address_btc_taproot: "Адрес BTC (Taproot)",
  address_ltc_p2pkh: "Адрес LTC",
  address_ltc_p2sh: "Адрес LTC (P2SH)",
  address_ltc_segwit: "Адрес LTC (SegWit)",
  address_ltc_taproot: "Адрес LTC (Taproot)",
  address_doge: "Адрес DOGE",
  address_dash: "Адрес DASH",
  address_dash_p2sh: "Адрес DASH (P2SH)",
  address_eth: "Адрес ETH",
  address_bch_cashaddr: "Адрес BCH (CashAddr)",
  address_xrp: "Адрес XRP",
  address_trx: "Адрес TRX",
  address_sol: "Адрес SOL",
};

// порядок отображения адресов, выведенных из одного ключа/сида
export const ADDRESS_ORDER = [
  "btc_legacy",
  "btc_segwit",
  "btc_taproot",
  "eth",
  "ltc",
  "ltc_segwit",
  "doge",
  "dash",
] as const;

export const ADDRESS_KEY_LABELS: Record<string, string> = {
  btc_legacy: "BTC Legacy",
  btc_legacy_uncompressed: "BTC Legacy (uncompressed)",
  btc_segwit: "BTC SegWit",
  btc_taproot: "BTC Taproot",
  ltc: "LTC",
  ltc_segwit: "LTC SegWit",
  doge: "DOGE",
  dash: "DASH",
  eth: "ETH",
};

export function typeLabel(type: string): string {
  if (TYPE_LABELS[type]) return TYPE_LABELS[type];
  let m = type.match(/^bip39_seed_phrase_(\d+)$/);
  if (m) return `Сид-фраза (${m[1]} слов)`;
  m = type.match(/^seedqr_compact_(\d+)$/);
  if (m) return `SeedQR Compact (${m[1]} слов)`;
  m = type.match(/^seedqr_standard_(\d+)$/);
  if (m) return `SeedQR Standard (${m[1]} слов)`;
  if (type === "electrum_legacy_seed") return "Electrum (старый формат)";
  return type;
}

export function isSeedType(type: string): boolean {
  return type.startsWith("bip39") || type.startsWith("seedqr") || type.startsWith("electrum");
}

export function isAddressType(type: string): boolean {
  return type.startsWith("address_");
}

export function isKeyType(type: string): boolean {
  return !isSeedType(type) && !isAddressType(type);
}

export function imageUrl(jobId: string, name: string, annotated = false): string {
  // превью с рамками сохраняются бэкендом в JPEG
  const finalName = annotated ? `${name.replace(/\.[^.]+$/, "")}.jpg` : name;
  return apiUrl(`jobs/${jobId}/${annotated ? "annotated" : "images"}/${encodeURIComponent(finalName)}`);
}

export function reportUrl(jobId: string, fmt: "txt" | "csv" | "json" | "seeds" | "addresses"): string {
  return apiUrl(`jobs/${jobId}/report?fmt=${fmt}`);
}
