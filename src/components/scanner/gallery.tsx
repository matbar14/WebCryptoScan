"use client";

import { useMemo } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { typeLabel, imageUrl, isSeedType, isImageName, sourceLabel, type Job } from "@/lib/scanner-api";
import { CopyValue } from "./copy-value";

function TypeBadge({ type }: { type: string }) {
  const seed = isSeedType(type);
  return (
    <Badge
      variant="outline"
      className={
        seed
          ? "border-amber-400/40 bg-amber-400/10 text-amber-300"
          : "border-emerald-400/40 bg-emerald-400/10 text-emerald-300"
      }
    >
      {typeLabel(type)}
    </Badge>
  );
}

export function Gallery({ job }: { job: Job }) {
  const qrImages = useMemo(() => {
    const set = new Set<string>();
    (job.stats.qr_images ?? []).forEach((n) => {
      if (isImageName(n)) set.add(n);
    });
    job.findings.forEach((f) => {
      if (isImageName(f.image)) set.add(f.image);
    });
    return Array.from(set);
  }, [job]);

  if (qrImages.length === 0) {
    return <p className="text-sm text-zinc-500">Нет изображений с находками — QR и OCR не дали результатов.</p>;
  }

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
      {qrImages.map((name) => {
        const findings = job.findings.filter((f) => f.image === name);
        const preview = imageUrl(job.id, name, true);
        return (
          <Dialog key={name}>
            <DialogTrigger asChild>
              <button
                type="button"
                className="group relative overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950 text-left transition-colors hover:border-emerald-400/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
                aria-label={`Изображение ${name}, находок: ${findings.length}`}
              >
                <img
                  src={preview}
                  alt={`Изображение ${name}`}
                  loading="lazy"
                  className="aspect-square w-full object-contain p-1"
                />
                <div className="absolute inset-x-0 bottom-0 space-y-1 bg-gradient-to-t from-zinc-950 via-zinc-950/85 to-transparent p-2">
                  <p className="truncate font-mono text-[11px] text-zinc-400">{name}</p>
                  <div className="flex flex-wrap gap-1">
                    {findings.length === 0 ? (
                      <Badge variant="outline" className="border-zinc-600 text-zinc-400">
                        Без секретов
                      </Badge>
                    ) : (
                      findings.slice(0, 2).map((f) => <TypeBadge key={f.id} type={f.type} />)
                    )}
                    {findings.length > 2 && (
                      <Badge variant="outline" className="border-zinc-600 text-zinc-400">
                        +{findings.length - 2}
                      </Badge>
                    )}
                  </div>
                </div>
              </button>
            </DialogTrigger>
            <DialogContent className="max-w-3xl border-zinc-800 bg-zinc-900 text-zinc-100">
              <DialogHeader>
                <DialogTitle className="font-mono text-sm">{name}</DialogTitle>
                <DialogDescription className="text-zinc-400">
                  Источников находок: {new Set(findings.map((f) => f.source ?? "qr")).size} · находок: {findings.length}
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 sm:grid-cols-2">
                <img
                  src={imageUrl(job.id, name)}
                  alt={`Оригинал ${name}`}
                  className="max-h-80 w-full rounded-md border border-zinc-800 object-contain bg-zinc-950"
                />
                <ScrollArea className="max-h-80 rounded-md border border-zinc-800">
                  <div className="space-y-3 p-3">
                    {findings.length === 0 && <p className="text-sm text-zinc-500">Секретов на изображении не обнаружено.</p>}
                    {findings.map((f) => (
                      <div key={f.id} className="space-y-1.5 rounded-md border border-zinc-800 bg-zinc-950/60 p-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <TypeBadge type={f.type} />
                          <span className="font-mono text-[10px] text-zinc-600">
                            {sourceLabel(f.source)} · {f.engine}/{f.variant}
                          </span>
                        </div>
                        <CopyValue value={f.value} label={isSeedType(f.type) ? "Фраза" : "Значение"} />
                        {f.address && <CopyValue value={f.address} label="Адрес" />}
                        {f.address_uncompressed && <CopyValue value={f.address_uncompressed} label="Адрес (несжатый)" />}
                        {f.wif && f.wif !== f.value && <CopyValue value={f.wif} label="WIF" />}
                        {isSeedType(f.type) && (
                          <p className={f.valid_checksum ? "text-xs text-emerald-400" : "text-xs text-rose-400"}>
                            {f.valid_checksum
                              ? "Контрольная сумма BIP39 верна"
                              : "Контрольная сумма BIP39 НЕ совпадает (фраза повреждена)"}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </div>
            </DialogContent>
          </Dialog>
        );
      })}
    </div>
  );
}
