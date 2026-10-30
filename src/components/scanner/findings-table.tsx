"use client";

import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ADDRESS_KEY_LABELS,
  ADDRESS_ORDER,
  isAddressType,
  isKeyType,
  isSeedType,
  sourceLabel,
  typeLabel,
  type Finding,
  type Job,
} from "@/lib/scanner-api";
import { CopyValue } from "./copy-value";

type Filter = "all" | "keys" | "seeds" | "addresses";

/** Мультивалютные адреса, выведенные из одного ключа/сида. */
function AddressRows({ addresses }: { addresses: Record<string, string> }) {
  const [expanded, setExpanded] = useState(false);
  const keys = ADDRESS_ORDER.filter((k) => addresses[k]);
  const rest = Object.keys(addresses).filter((k) => !ADDRESS_ORDER.includes(k as never));
  const all = [...keys, ...rest];
  if (all.length === 0) return null;

  const shown = expanded ? all : all.slice(0, 2);
  const hidden = all.length - shown.length;

  return (
    <div className="space-y-1 pt-1">
      {shown.map((k) => (
        <CopyValue key={k} value={addresses[k]} label={ADDRESS_KEY_LABELS[k] ?? k} />
      ))}
      {hidden > 0 && (
        <Button
          size="sm"
          variant="ghost"
          className="h-6 px-2 text-[11px] text-zinc-500 hover:text-emerald-400"
          onClick={() => setExpanded(true)}
          aria-label={`Показать ещё ${hidden} сетей`}
        >
          ещё {hidden} {hidden === 1 ? "сеть" : hidden < 5 ? "сети" : "сетей"}…
        </Button>
      )}
    </div>
  );
}

export function FindingsTable({ job }: { job: Job }) {
  const [filter, setFilter] = useState<Filter>("all");

  const counts = useMemo(() => {
    const keys = job.findings.filter((f) => isKeyType(f.type)).length;
    const seeds = job.findings.filter((f) => isSeedType(f.type)).length;
    const addresses = job.findings.filter((f) => isAddressType(f.type)).length;
    return { keys, seeds, addresses };
  }, [job.findings]);

  const rows = useMemo(() => {
    if (filter === "keys") return job.findings.filter((f) => isKeyType(f.type));
    if (filter === "seeds") return job.findings.filter((f) => isSeedType(f.type));
    if (filter === "addresses") return job.findings.filter((f) => isAddressType(f.type));
    return job.findings;
  }, [job.findings, filter]);

  const badgeClass = (type: string) =>
    isSeedType(type)
      ? "border-amber-400/40 bg-amber-400/10 text-amber-300 whitespace-nowrap"
      : isAddressType(type)
        ? "border-sky-400/40 bg-sky-400/10 text-sky-300 whitespace-nowrap"
        : "border-emerald-400/40 bg-emerald-400/10 text-emerald-300 whitespace-nowrap";

  if (job.findings.length === 0) {
    return <p className="text-sm text-zinc-500">Секретов не найдено — проверьте настройки детекторов или источник изображений.</p>;
  }

  return (
    <div className="space-y-3">
      <Tabs value={filter} onValueChange={(v) => setFilter(v as Filter)}>
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="all" className="data-[state=active]:text-emerald-400">
            Все ({job.findings.length})
          </TabsTrigger>
          <TabsTrigger value="keys" className="data-[state=active]:text-emerald-400">
            Ключи ({counts.keys})
          </TabsTrigger>
          <TabsTrigger value="seeds" className="data-[state=active]:text-emerald-400">
            Сид-фразы ({counts.seeds})
          </TabsTrigger>
          <TabsTrigger value="addresses" className="data-[state=active]:text-emerald-400">
            Адреса ({counts.addresses})
          </TabsTrigger>
        </TabsList>
      </Tabs>

      <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-800">
        <Table>
          <TableHeader className="sticky top-0 bg-zinc-900">
            <TableRow className="border-zinc-800 hover:bg-zinc-900">
              <TableHead className="w-10 text-zinc-400">#</TableHead>
              <TableHead className="text-zinc-400">Тип</TableHead>
              <TableHead className="text-zinc-400">Значение / адреса</TableHead>
              <TableHead className="hidden text-zinc-400 md:table-cell">Источник</TableHead>
              <TableHead className="w-24 text-right text-zinc-400">Статус</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((f: Finding) => (
              <TableRow key={f.id} className="border-zinc-800/70 hover:bg-zinc-900/60">
                <TableCell className="font-mono text-xs text-zinc-500">{f.id}</TableCell>
                <TableCell>
                  <Badge variant="outline" className={badgeClass(f.type)}>
                    {typeLabel(f.type)}
                  </Badge>
                </TableCell>
                <TableCell className="max-w-[420px] space-y-1 py-2">
                  <CopyValue value={f.value} />
                  {f.address && f.address !== f.value && <CopyValue value={f.address} label="адрес" />}
                  {f.address_uncompressed && <CopyValue value={f.address_uncompressed} label="адрес*" />}
                  {f.addresses && <AddressRows addresses={f.addresses} />}
                </TableCell>
                <TableCell className="hidden font-mono text-xs text-zinc-500 md:table-cell">
                  <div className="space-y-1">
                    <span title={f.image}>{f.image}</span>
                    {(f.source && f.source !== "qr") || f.source_detail ? (
                      <Badge
                        variant="outline"
                        className="block w-fit border-violet-400/40 bg-violet-400/10 text-violet-300 whitespace-nowrap"
                        title={f.source_detail}
                      >
                        {sourceLabel(f.source)}
                      </Badge>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  {isSeedType(f.type) ? (
                    <Badge
                      variant="outline"
                      className={
                        f.valid_checksum
                          ? "border-emerald-400/40 text-emerald-400"
                          : "border-rose-400/40 text-rose-400"
                      }
                    >
                      {f.valid_checksum ? "checksum OK" : "checksum FAIL"}
                    </Badge>
                  ) : isAddressType(f.type) ? (
                    <Badge variant="outline" className="border-sky-400/40 text-sky-300">
                      {f.detail?.includes("без контрольной суммы") ? "вероятный" : "checksum OK"}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="border-zinc-600 text-zinc-400">
                      валиден
                    </Badge>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
