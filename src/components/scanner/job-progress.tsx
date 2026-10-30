"use client";

import { AlertTriangle, CheckCircle2, FileSearch, Globe, Loader2, ScanLine, XCircle } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import type { Job } from "@/lib/scanner-api";

function phaseLabel(job: Job): string {
  if (job.status === "queued") return "В очереди…";
  if (job.status === "crawling") return "Поиск изображений в поисковых системах…";
  if (job.status === "running") return "Сканирование изображений…";
  if (job.status === "done") return "Готово";
  if (job.status === "error") return "Ошибка";
  return job.status;
}

export function JobProgress({ job }: { job: Job }) {
  const total = job.progress.total || 0;
  const processed = job.progress.processed || 0;
  const pct = total > 0 ? Math.round((processed / total) * 100) : job.status === "done" ? 100 : 0;
  const crawling = job.status === "crawling";
  const done = job.status === "done";
  const error = job.status === "error";

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        {crawling ? (
          <Globe className="h-4 w-4 animate-pulse text-amber-400" aria-hidden />
        ) : done ? (
          <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden />
        ) : error ? (
          <XCircle className="h-4 w-4 text-rose-400" aria-hidden />
        ) : (
          <Loader2 className="h-4 w-4 animate-spin text-emerald-400" aria-hidden />
        )}
        <span className="text-sm font-medium text-zinc-200">{phaseLabel(job)}</span>
        {total > 0 && !crawling && (
          <span className="ml-auto font-mono text-xs text-zinc-400">
            {processed} / {total}
          </span>
        )}
      </div>

      <Progress value={pct} className="h-2 bg-zinc-800 [&>div]:bg-emerald-400" aria-label="Прогресс сканирования" />

      {job.status === "crawling" && job.crawl?.keywords && (
        <div className="space-y-1 rounded-md border border-zinc-800 bg-zinc-950/60 p-2 text-xs font-mono text-zinc-400">
          {Object.entries(job.crawl.keywords).map(([kw, info]) => (
            <div key={kw} className="space-y-0.5">
              <div className="flex items-center gap-1.5">
                <FileSearch className="h-3 w-3 shrink-0 text-zinc-500" aria-hidden />
                <span className="truncate">{kw}</span>
                <span className="ml-auto shrink-0 text-zinc-500">{info.total} фото</span>
                {Object.values(info.engines).some((e) => e.error) && (
                  <AlertTriangle className="h-3 w-3 shrink-0 text-amber-400" aria-hidden />
                )}
              </div>
              {Object.values(info.engines)
                .filter((e) => e.note)
                .map((e, i) => (
                  <div key={i} className="truncate pl-4 text-[11px] text-sky-400/80">
                    ⓘ {e.note}
                  </div>
                ))}
            </div>
          ))}
        </div>
      )}

      {error && job.error && (
        <p className="rounded-md border border-rose-500/30 bg-rose-500/10 p-2 text-xs text-rose-300">{job.error}</p>
      )}

      {job.errors.length > 0 && (
        <p className="text-xs text-amber-400/90">
          <AlertTriangle className="mr-1 inline h-3 w-3" aria-hidden />
          Проблемных изображений: {job.errors.length}
        </p>
      )}
    </div>
  );
}
