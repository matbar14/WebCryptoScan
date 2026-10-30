"use client";

import { FileDown, FileJson, FileSpreadsheet, FileText, ListChecks } from "lucide-react";
import { Button } from "@/components/ui/button";
import { reportUrl, type Job } from "@/lib/scanner-api";

export function ReportButtons({ job }: { job: Job }) {
  if (job.status !== "done") return null;

  const btns: { fmt: "txt" | "seeds" | "csv" | "json"; label: string; icon: React.ReactNode }[] = [
    { fmt: "txt", label: "keylist.txt", icon: <FileText className="h-4 w-4" aria-hidden /> },
    { fmt: "seeds", label: "seedlist.txt", icon: <ListChecks className="h-4 w-4" aria-hidden /> },
    { fmt: "csv", label: "scan_report.csv", icon: <FileSpreadsheet className="h-4 w-4" aria-hidden /> },
    { fmt: "json", label: "scan_report.json", icon: <FileJson className="h-4 w-4" aria-hidden /> },
  ];

  return (
    <div className="flex flex-wrap gap-2">
      {btns.map((b) => (
        <Button
          key={b.fmt}
          asChild
          variant="outline"
          size="sm"
          className="border-zinc-700 bg-zinc-950/60 text-zinc-200 hover:border-emerald-400/60 hover:text-emerald-300"
        >
          <a href={reportUrl(job.id, b.fmt)} download aria-label={`Скачать ${b.label}`}>
            {b.icon}
            {b.label}
          </a>
        </Button>
      ))}
    </div>
  );
}
