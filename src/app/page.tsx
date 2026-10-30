"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Delete, History, Loader2, QrCode, ScanLine, ShieldCheck, Trash2, Wifi, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  bootService,
  DEFAULT_OPTIONS,
  deleteJob,
  getJob,
  getJobs,
  isSeedType,
  scanCrawl,
  scanFolder,
  scanGlobal,
  scanSite,
  scanUpload,
  type GlobalMode,
  type Job,
  type JobSummary,
  type ScanOptions,
} from "@/lib/scanner-api";
import { SourcePanel, type SourceTab } from "@/components/scanner/source-panel";
import { ScanOptionsCard } from "@/components/scanner/scan-options";
import { JobProgress } from "@/components/scanner/job-progress";
import { StatsCards } from "@/components/scanner/stats-cards";
import { Gallery } from "@/components/scanner/gallery";
import { FindingsTable } from "@/components/scanner/findings-table";
import { ReportButtons } from "@/components/scanner/report-buttons";

const ACTIVE_STATUSES = new Set(["queued", "crawling", "running"]);

export default function Home() {
  const { toast } = useToast();
  const [serviceOk, setServiceOk] = useState<boolean | null>(null);
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);
  const [sourceTab, setSourceTab] = useState<SourceTab>("upload");
  const [job, setJob] = useState<Job | null>(null);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<JobSummary[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refreshHistory = useCallback(() => {
    getJobs()
      .then((list) => setHistory(list.slice(0, 12)))
      .catch(() => setHistory([]));
  }, []);

  useEffect(() => {
    bootService()
      .then((r) => {
        setServiceOk(r.ok);
        if (r.ok) refreshHistory();
        else setTimeout(() => bootService().then((x) => setServiceOk(x.ok)), 5000);
      })
      .catch(() => setServiceOk(false));
  }, [refreshHistory]);

  const trackJob = useCallback(
    (jobId: string) => {
      if (pollRef.current) clearInterval(pollRef.current);
      const poll = async () => {
        try {
          const j = await getJob(jobId);
          setJob(j);
          if (!ACTIVE_STATUSES.has(j.status)) {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
            setBusy(false);
            refreshHistory();
            if (j.status === "done") {
              const keys = Object.entries(j.stats.by_type).filter(([t]) => !isSeedType(t)).length;
              toast({
                title: "Сканирование завершено",
                description: `QR-кодов: ${j.stats.qr_codes}, находок: ${j.stats.findings}${keys ? ", типов ключей: " + keys : ""}`,
              });
            }
          }
        } catch {
          /* следующая попытка покажет */
        }
      };
      void poll();
      pollRef.current = setInterval(poll, 1200);
    },
    [refreshHistory, toast],
  );

  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current);
  }, []);

  const runJob = useCallback(
    async (action: () => Promise<string>) => {
      setBusy(true);
      try {
        const id = await action();
        trackJob(id);
      } catch (e) {
        setBusy(false);
        toast({ title: "Не удалось запустить сканирование", description: e instanceof Error ? e.message : String(e), variant: "destructive" });
      }
    },
    [trackJob, toast],
  );

  const onUpload = useCallback(
    (files: File[]) => runJob(() => scanUpload(files, options, `Загрузка: ${files.length} файл(ов)`)),
    [options, runJob],
  );

  const onFolder = useCallback(
    (path: string) => runJob(() => scanFolder(path, options).then((r) => r.job_id)),
    [options, runJob],
  );

  const onCrawl = useCallback(
    (p: { keyword: string; preset: string; engines: string[]; maxNum: number }) =>
      runJob(() =>
        scanCrawl({
          keyword: p.keyword || undefined,
          preset: p.preset || undefined,
          engines: p.engines,
          max_num: p.maxNum,
          options,
        }).then((r) => r.job_id),
      ),
    [options, runJob],
  );

  const onSite = useCallback(
    (p: { url: string; archive: "auto" | "yes" | "no"; maxNum: number }) =>
      runJob(() =>
        scanSite({ url: p.url, archive: p.archive, max_num: p.maxNum, options }).then((r) => r.job_id),
      ),
    [options, runJob],
  );

  const onGlobal = useCallback(
    (p: {
      mode: GlobalMode;
      domain?: string;
      provider?: "auto" | "wayback" | "arquivo";
      delta?: boolean;
      mask?: string;
      presets?: string[];
      custom?: string;
      engines?: string[];
      token?: string;
      max_urls?: number;
      max_pages?: number;
      max_files?: number;
    }) =>
      runJob(() => scanGlobal({ ...p, options }).then((r) => r.job_id)),
    [options, runJob],
  );

  const openHistoryJob = (id: string) => {
    setBusy(ACTIVE_STATUSES.has("queued"));
    getJob(id)
      .then((j) => {
        setJob(j);
        if (ACTIVE_STATUSES.has(j.status)) trackJob(id);
        else setBusy(false);
        setSourceTab(
          j.source_type === "crawl"
            ? "crawl"
            : j.source_type === "site"
              ? "site"
              : j.source_type.startsWith("global_")
                ? "global"
                : j.source_type === "folder"
                  ? "folder"
                  : "upload",
        );
      })
      .catch(() => toast({ title: "Джоба недоступна", variant: "destructive" }));
  };

  const removeHistoryJob = (id: string) => {
    deleteJob(id)
      .then(() => {
        setHistory((h) => h.filter((x) => x.id !== id));
        setJob((j) => (j && j.id === id ? null : j));
      })
      .catch(() => toast({ title: "Не удалось удалить", variant: "destructive" }));
  };

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      {/* --- Шапка --- */}
      <header className="sticky top-0 z-40 border-b border-zinc-800 bg-zinc-950/90 backdrop-blur">
        <div className="mx-auto flex w-full max-w-6xl items-center gap-3 px-4 py-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-md border border-emerald-400/40 bg-emerald-400/10">
            <QrCode className="h-5 w-5 text-emerald-400" aria-hidden />
          </div>
          <div className="min-w-0">
            <h1 className="text-base font-semibold leading-tight">
              MrRobotQR <span className="text-emerald-400">2.0</span>
            </h1>
            <p className="hidden text-xs text-zinc-500 sm:block">
              Ключи, сид-фразы и адреса: BTC, ETH, LTC, DOGE, DASH, BCH, XRP, TRX, SOL · оффлайн-валидация
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge variant="outline" className="hidden border-zinc-700 text-zinc-400 sm:inline-flex">
              <ShieldCheck className="mr-1 h-3 w-3" aria-hidden /> без сети
            </Badge>
            {serviceOk === null ? (
              <Badge variant="outline" className="border-zinc-700 text-zinc-400">
                <Loader2 className="mr-1 h-3 w-3 animate-spin" aria-hidden /> запуск…
              </Badge>
            ) : serviceOk ? (
              <Badge variant="outline" className="border-emerald-400/40 text-emerald-400">
                <Wifi className="mr-1 h-3 w-3" aria-hidden /> сервис активен
              </Badge>
            ) : (
              <Badge variant="outline" className="border-rose-400/40 text-rose-400">
                <WifiOff className="mr-1 h-3 w-3" aria-hidden /> сервис недоступен
              </Badge>
            )}
          </div>
        </div>
      </header>

      {/* --- Контент --- */}
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6">
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-4 min-w-0">
            <Card className="border-zinc-800 bg-zinc-900/80">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ScanLine className="h-4 w-4 text-emerald-400" aria-hidden />
                  Источник изображений
                </CardTitle>
                <CardDescription>Файлы, папка, краулер, парсер сайтов — или глобальный поиск: архивы, dork-запросы, Common Crawl, GitHub.</CardDescription>
              </CardHeader>
              <CardContent>
                <SourcePanel active={sourceTab} onActiveChange={setSourceTab} busy={busy} onUpload={onUpload} onFolder={onFolder} onCrawl={onCrawl} onSite={onSite} onGlobal={onGlobal} />
              </CardContent>
            </Card>

            {job && (
              <Card className="border-zinc-800 bg-zinc-900/80">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Джоба {job.id}</CardTitle>
                  <CardDescription className="truncate">{job.label}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <JobProgress job={job} />
                  <StatsCards job={job} />
                  <ReportButtons job={job} />
                </CardContent>
              </Card>
            )}

            {job && (
              <Card className="border-zinc-800 bg-zinc-900/80">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Находки</CardTitle>
                  <CardDescription>Валидация выполняется локально, без сетевых запросов.</CardDescription>
                </CardHeader>
                <CardContent>
                  <FindingsTable job={job} />
                </CardContent>
              </Card>
            )}

            {job && (
              <Card className="border-zinc-800 bg-zinc-900/80">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Изображения с QR-кодами</CardTitle>
                  <CardDescription>Зелёной рамкой отмечены найденные коды. Нажмите на карточку для деталей.</CardDescription>
                </CardHeader>
                <CardContent>
                  <Gallery job={job} />
                </CardContent>
              </Card>
            )}
          </div>

          {/* --- Правая колонка --- */}
          <div className="space-y-4">
            <Card className="border-zinc-800 bg-zinc-900/80">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Настройки сканирования</CardTitle>
              </CardHeader>
              <CardContent>
                <ScanOptionsCard options={options} onChange={setOptions} disabled={busy} />
              </CardContent>
            </Card>

            <Card className="border-zinc-800 bg-zinc-900/80">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <History className="h-4 w-4 text-emerald-400" aria-hidden />
                  История
                </CardTitle>
              </CardHeader>
              <CardContent>
                {history.length === 0 ? (
                  <p className="text-sm text-zinc-500">Пока нет завершённых сканирований.</p>
                ) : (
                  <ScrollArea className="max-h-72">
                    <div className="space-y-1.5 pr-2">
                      {history.map((h) => (
                        <div
                          key={h.id}
                          className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950/60 p-2"
                        >
                          <button
                            type="button"
                            onClick={() => openHistoryJob(h.id)}
                            className="min-w-0 flex-1 text-left focus-visible:outline-none"
                            aria-label={`Открыть джобу ${h.id}`}
                          >
                            <p className="truncate text-xs text-zinc-300">{h.label || h.id}</p>
                            <p className="font-mono text-[10px] text-zinc-500">
                              {new Date(h.created_at).toLocaleString("ru-RU")} · {h.status === "done" ? `находок: ${h.stats.findings}` : h.status}
                            </p>
                          </button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-7 w-7 shrink-0 text-zinc-600 hover:text-rose-400"
                            onClick={() => removeHistoryJob(h.id)}
                            aria-label={`Удалить джобу ${h.id}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      {/* --- Подвал --- */}
      <footer className="mt-auto border-t border-zinc-800 bg-zinc-950">
        <div className="mx-auto w-full max-w-6xl px-4 py-4 text-xs text-zinc-600">
          <Separator className="mb-4 bg-zinc-800/60" />
          <p>
            MrRobotQR 2.0 — модернизированный сканер (каскад pyzbar → WeChatQRCode → OpenCV + препроцессинг).
            Предназначен для исследований безопасности: демонстрирует, как быстро публичные QR-коды с секретами
            находятся и вскрываются. Валидация ключей и адресов выполняется полностью офлайн.
          </p>
          <p className="mt-1.5">Не публикуйте QR-коды с приватными ключами и сид-фразами — даже «на секунду».</p>
        </div>
      </footer>
    </div>
  );
}
