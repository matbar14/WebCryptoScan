"use client";

import { Images, QrCode, KeyRound, Fingerprint, ScanLine, Wallet } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { isAddressType, isKeyType, type Job } from "@/lib/scanner-api";

export function StatsCards({ job, className }: { job: Job | null; className?: string }) {
  const keysCount =
    job === null
      ? 0
      : Object.entries(job.stats.by_type)
          .filter(([t]) => isKeyType(t))
          .reduce((acc, [, n]) => acc + n, 0);

  // адреса: найденные в QR + выведенные из ключей/сидов
  const addressesCount =
    job === null
      ? 0
      : Object.entries(job.stats.by_type)
          .filter(([t]) => isAddressType(t))
          .reduce((acc, [, n]) => acc + n, 0) +
        job.findings.reduce((acc, f) => acc + Object.keys(f.addresses ?? {}).length, 0);

  const items = [
    {
      label: "Изображений",
      value: job?.stats.images ?? 0,
      icon: <Images className="h-4 w-4" aria-hidden />,
      color: "text-zinc-300",
    },
    {
      label: "QR-кодов",
      value: job?.stats.qr_codes ?? 0,
      icon: <QrCode className="h-4 w-4" aria-hidden />,
      color: "text-sky-300",
    },
    {
      label: "Приватных ключей",
      value: keysCount,
      icon: <KeyRound className="h-4 w-4" aria-hidden />,
      color: "text-emerald-400",
    },
    {
      label: "Сид-фраз",
      value: job === null ? 0 : (job.stats.valid_seeds ?? 0) + (job.stats.invalid_seeds ?? 0),
      icon: <Fingerprint className="h-4 w-4" aria-hidden />,
      color: "text-amber-300",
    },
    {
      label: "Адресов",
      value: addressesCount,
      icon: <Wallet className="h-4 w-4" aria-hidden />,
      color: "text-sky-300",
    },
  ];

  return (
    <div className={cn("grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5", className)}>
      {items.map((it) => (
        <Card key={it.label} className="border-zinc-800 bg-zinc-900/80">
          <CardContent className="flex items-center gap-3 p-4">
            <div className={cn("rounded-md bg-zinc-950/80 p-2 border border-zinc-800", it.color)}>{it.icon}</div>
            <div className="min-w-0">
              <p className="truncate text-xs text-zinc-500">{it.label}</p>
              <p className={cn("text-xl font-semibold tabular-nums", it.color)}>{it.value}</p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export function ServiceOfflineHint({ className }: { className?: string }) {
  return (
    <div className={cn("flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200", className)}>
      <ScanLine className="h-4 w-4 shrink-0" aria-hidden />
      Сервис сканирования запускается — подождите несколько секунд и обновите страницу.
    </div>
  );
}
