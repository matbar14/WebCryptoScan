"use client";

import { useEffect, useState } from "react";
import { FolderOpen, Globe, Loader2, Search, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Slider } from "@/components/ui/slider";
import { getPresets, type Preset } from "@/lib/scanner-api";
import { UploadZone } from "./upload-zone";

export type SourceTab = "upload" | "folder" | "crawl";

export function SourcePanel({
  active,
  onActiveChange,
  busy,
  onUpload,
  onFolder,
  onCrawl,
}: {
  active: SourceTab;
  onActiveChange: (t: SourceTab) => void;
  busy: boolean;
  onUpload: (files: File[]) => void;
  onFolder: (path: string) => void;
  onCrawl: (p: { keyword: string; preset: string; engines: string[]; maxNum: number }) => void;
}) {
  const [folderPath, setFolderPath] = useState("");
  const [keyword, setKeyword] = useState("");
  const [preset, setPreset] = useState("");
  const [presets, setPresets] = useState<Record<string, Preset>>({});
  const [engines, setEngines] = useState<string[]>(["google", "bing", "baidu"]);
  const [maxNum, setMaxNum] = useState(30);

  useEffect(() => {
    getPresets()
      .then(setPresets)
      .catch(() => setPresets({}));
  }, []);

  const toggleEngine = (e: string) =>
    setEngines((prev) => (prev.includes(e) ? prev.filter((x) => x !== e) : [...prev, e]));

  return (
    <Tabs value={active} onValueChange={(v) => onActiveChange(v as SourceTab)} className="w-full">
      <TabsList className="grid w-full grid-cols-3 bg-zinc-900 border border-zinc-800">
        <TabsTrigger value="upload" className="gap-1.5 data-[state=active]:text-emerald-400">
          <FolderOpen className="h-4 w-4" aria-hidden /> Файлы
        </TabsTrigger>
        <TabsTrigger value="folder" className="gap-1.5 data-[state=active]:text-emerald-400">
          <FolderOpen className="h-4 w-4" aria-hidden /> Папка
        </TabsTrigger>
        <TabsTrigger value="crawl" className="gap-1.5 data-[state=active]:text-emerald-400">
          <Globe className="h-4 w-4" aria-hidden /> Краулер
        </TabsTrigger>
      </TabsList>

      <TabsContent value="upload" className="mt-4">
        <UploadZone onFiles={onUpload} disabled={busy} />
      </TabsContent>

      <TabsContent value="folder" className="mt-4 space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor="folder-path" className="text-zinc-300">
            Путь к папке с изображениями на сервере
          </Label>
          <div className="flex gap-2">
            <Input
              id="folder-path"
              placeholder="/path/to/qrbooty"
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              disabled={busy}
              className="bg-zinc-950/60 border-zinc-800 font-mono text-sm"
            />
            <Button
              onClick={() => onFolder(folderPath.trim())}
              disabled={busy || !folderPath.trim()}
              className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400 shrink-0"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Search className="h-4 w-4" aria-hidden />}
              Сканировать
            </Button>
          </div>
          <p className="text-xs text-zinc-500">
            Например, папка <code className="text-zinc-400">qrbooty</code> от старого MrRobotQR или любой каталог с JPG/PNG.
          </p>
        </div>
      </TabsContent>

      <TabsContent value="crawl" className="mt-4 space-y-4">
        <div className="space-y-1.5">
          <Label className="text-zinc-300">Пресеты запросов</Label>
          <div className="flex flex-wrap gap-2">
            {Object.entries(presets).map(([key, p]) => (
              <Badge
                key={key}
                variant={preset === key ? "default" : "outline"}
                className={
                  preset === key
                    ? "cursor-pointer bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
                    : "cursor-pointer border-zinc-700 text-zinc-300 hover:border-emerald-400 hover:text-emerald-400"
                }
                onClick={() => {
                  setPreset(preset === key ? "" : key);
                  setKeyword("");
                }}
              >
                <Sparkles className="mr-1 h-3 w-3" aria-hidden />
                {p.label}
              </Badge>
            ))}
          </div>
          {preset && presets[preset] && (
            <p className="text-xs text-zinc-500 font-mono">
              {presets[preset].keywords.length} запросов × {maxNum} фото на запрос
            </p>
          )}
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="crawl-keyword" className="text-zinc-300">
            Или своё ключевое слово
          </Label>
          <Input
            id="crawl-keyword"
            placeholder="например: bitcoin paper wallet qr"
            value={keyword}
            onChange={(e) => {
              setKeyword(e.target.value);
              if (e.target.value) setPreset("");
            }}
            disabled={busy}
            className="bg-zinc-950/60 border-zinc-800 text-sm"
          />
        </div>

        <div className="space-y-2">
          <Label className="text-zinc-300">Поисковые системы</Label>
          <div className="flex gap-4">
            {(["google", "bing", "baidu"] as const).map((e) => (
              <label key={e} className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
                <Checkbox checked={engines.includes(e)} onCheckedChange={() => toggleEngine(e)} disabled={busy} />
                {e}
              </label>
            ))}
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label className="text-zinc-300">Фото на запрос: {maxNum}</Label>
          </div>
          <Slider value={[maxNum]} min={5} max={200} step={5} onValueChange={(v) => setMaxNum(v[0])} disabled={busy} />
        </div>

        <Button
          onClick={() => onCrawl({ keyword: keyword.trim(), preset, engines, maxNum })}
          disabled={busy || (!keyword.trim() && !preset) || engines.length === 0}
          className="w-full bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Globe className="h-4 w-4" aria-hidden />}
          Найти и просканировать
        </Button>
        <p className="text-xs text-zinc-500">
          Краулер скачивает изображения из поиска, затем они автоматически проходят через сканер QR-кодов.
        </p>
      </TabsContent>
    </Tabs>
  );
}
