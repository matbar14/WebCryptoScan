"use client";

import { KeyRound, ListChecks, ScanLine, SlidersHorizontal, TextCursorInput } from "lucide-react";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { ScanOptions } from "@/lib/scanner-api";

const ITEMS: { key: keyof ScanOptions; label: string; hint: string; icon: React.ReactNode }[] = [
  {
    key: "detect_wif",
    label: "WIF-ключи",
    hint: "Base58Check, адрес P2PKH",
    icon: <KeyRound className="h-3.5 w-3.5" aria-hidden />,
  },
  {
    key: "detect_seed",
    label: "BIP39 сид-фразы",
    hint: "12/15/18/21/24 слов + checksum",
    icon: <ListChecks className="h-3.5 w-3.5" aria-hidden />,
  },
  {
    key: "detect_mini",
    label: "Mini-ключи",
    hint: "формат Casascius",
    icon: <TextCursorInput className="h-3.5 w-3.5" aria-hidden />,
  },
  {
    key: "detect_hex",
    label: "Hex-ключи",
    hint: "сырой ключ, 64 символа",
    icon: <KeyRound className="h-3.5 w-3.5" aria-hidden />,
  },
  {
    key: "preprocess",
    label: "Улучшение изображений",
    hint: "масштаб, CLAHE, Отсу, адаптив",
    icon: <ScanLine className="h-3.5 w-3.5" aria-hidden />,
  },
];

export function ScanOptionsCard({
  options,
  onChange,
  disabled,
}: {
  options: ScanOptions;
  onChange: (o: ScanOptions) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1.5 text-sm font-medium text-zinc-300">
        <SlidersHorizontal className="h-4 w-4 text-emerald-400" aria-hidden />
        Что искать
      </div>
      <div className="divide-y divide-zinc-800/70">
        {ITEMS.map((it) => (
          <div key={it.key} className="flex items-center justify-between gap-3 py-2.5">
            <div className="min-w-0">
              <Label className="text-sm text-zinc-200">{it.label}</Label>
              <p className="text-xs text-zinc-500">{it.hint}</p>
            </div>
            <Switch
              checked={options[it.key]}
              onCheckedChange={(v) => onChange({ ...options, [it.key]: v })}
              disabled={disabled}
              aria-label={it.label}
              className="data-[state=checked]:bg-emerald-500"
            />
          </div>
        ))}
      </div>
    </div>
  );
}
