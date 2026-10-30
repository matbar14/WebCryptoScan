"use client";

import { useCallback, useRef, useState } from "react";
import { ImagePlus, Loader2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function UploadZone({
  onFiles,
  disabled,
}: {
  onFiles: (files: File[]) => void;
  disabled?: boolean;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [files, setFiles] = useState<File[]>([]);

  const addFiles = useCallback(
    (list: FileList | null) => {
      if (!list) return;
      const imgs = Array.from(list).filter(
        (f) => f.type.startsWith("image/") || /\.(jpe?g|png|gif|bmp|webp|tiff?)$/i.test(f.name),
      );
      if (imgs.length === 0) return;
      setFiles((prev) => {
        const names = new Set(prev.map((f) => f.name + f.size));
        const fresh = imgs.filter((f) => !names.has(f.name + f.size));
        return [...prev, ...fresh];
      });
    },
    [],
  );

  const start = () => {
    if (files.length > 0) {
      onFiles(files);
      setFiles([]);
    }
  };

  return (
    <div className="space-y-3">
      <div
        role="button"
        tabIndex={0}
        aria-label="Зона загрузки изображений"
        onClick={() => !disabled && inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          if (!disabled) addFiles(e.dataTransfer.files);
        }}
        className={cn(
          "flex min-h-36 cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-6 text-center transition-colors",
          dragOver ? "border-emerald-400 bg-emerald-400/10" : "border-zinc-700 bg-zinc-950/60 hover:border-zinc-500",
          disabled && "pointer-events-none opacity-50",
        )}
      >
        <ImagePlus className="h-8 w-8 text-zinc-500" aria-hidden />
        <p className="text-sm text-zinc-300">
          Перетащите изображения сюда или <span className="text-emerald-400 underline underline-offset-2">выберите файлы</span>
        </p>
        <p className="text-xs text-zinc-500">JPG, PNG, GIF, BMP, WebP, TIFF</p>
        <input
          ref={inputRef}
          type="file"
          accept="image/*,.tiff,.tif,.bmp"
          multiple
          className="hidden"
          onChange={(e) => {
            addFiles(e.target.files);
            e.target.value = "";
          }}
        />
      </div>

      {files.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs text-zinc-400">Выбрано файлов: {files.length}</p>
            <Button size="sm" variant="ghost" onClick={() => setFiles([])} disabled={disabled}>
              <X className="h-3.5 w-3.5" aria-hidden /> Очистить
            </Button>
          </div>
          <div className="max-h-32 overflow-y-auto rounded-md border border-zinc-800 bg-zinc-950/60 p-2">
            <ul className="space-y-1 text-xs text-zinc-400 font-mono">
              {files.map((f) => (
                <li key={f.name + f.size} className="truncate">
                  {f.name} <span className="text-zinc-600">({(f.size / 1024).toFixed(0)} КБ)</span>
                </li>
              ))}
            </ul>
          </div>
          <Button onClick={start} disabled={disabled} className="w-full bg-emerald-500 text-zinc-950 hover:bg-emerald-400">
            {disabled ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : null}
            Сканировать {files.length} файл(ов)
          </Button>
        </div>
      )}
    </div>
  );
}
