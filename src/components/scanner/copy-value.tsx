"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function CopyValue({ value, label, className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = value;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className={cn("group flex min-w-0 items-center gap-1.5", className)}>
      {label && <span className="shrink-0 text-[11px] text-zinc-500">{label}:</span>}
      <code className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-200" title={value}>
        {value}
      </code>
      <Button
        size="icon"
        variant="ghost"
        className="h-6 w-6 shrink-0 text-zinc-500 hover:text-emerald-400"
        onClick={copy}
        aria-label={`Скопировать ${label ?? "значение"}`}
      >
        {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
      </Button>
    </div>
  );
}
