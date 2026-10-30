"use client";

import { useEffect, useState } from "react";
import { Archive, Database, FileSearch, FolderOpen, Globe, Github, Link2, Loader2, Radar, RotateCcw, Search, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Slider } from "@/components/ui/slider";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getGlobalPresets, getGlobalState, getPresets, resetGlobalState, type GlobalDomainState, type GlobalMode, type GlobalPresets, type Preset } from "@/lib/scanner-api";
import { UploadZone } from "./upload-zone";

export type SourceTab = "upload" | "folder" | "crawl" | "site" | "global";

function fmtStateDate(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const GLOBAL_MODES: { id: GlobalMode; label: string; icon: typeof Archive; hint: string }[] = [
  { id: "archive", label: "Архивы", icon: Archive, hint: "домен целиком из веб-архива" },
  { id: "dorks", label: "Dork-поиск", icon: FileSearch, hint: "открытые каталоги и файлы" },
  { id: "commoncrawl", label: "Common Crawl", icon: Database, hint: "миллиарды URL по маске" },
  { id: "github", label: "GitHub", icon: Github, hint: "утечки в коде и гистах" },
];

const ENGINE_LIST: { id: string; label: string; hint: string }[] = [
  { id: "baidu", label: "Baidu", hint: "работает из дата-центров" },
  { id: "so360", label: "360 Поиск", hint: "работает из дата-центров" },
  { id: "duckduckgo", label: "DuckDuckGo", hint: "на локальной машине" },
  { id: "wikimedia", label: "Wikimedia", hint: "свободные изображения" },
  { id: "google", label: "Google", hint: "на локальной машине" },
  { id: "bing", label: "Bing", hint: "на локальной машине" },
  { id: "sogou", label: "Sogou", hint: "на локальной машине" },
  { id: "yandex", label: "Яндекс", hint: "часто капча" },
  { id: "openverse", label: "Openverse", hint: "CC-изображения" },
];

export function SourcePanel({
  active,
  onActiveChange,
  busy,
  onUpload,
  onFolder,
  onCrawl,
  onSite,
  onGlobal,
}: {
  active: SourceTab;
  onActiveChange: (t: SourceTab) => void;
  busy: boolean;
  onUpload: (files: File[]) => void;
  onFolder: (path: string) => void;
  onCrawl: (p: { keyword: string; preset: string; engines: string[]; maxNum: number }) => void;
  onSite: (p: { url: string; archive: "auto" | "yes" | "no"; maxNum: number }) => void;
  onGlobal: (p: {
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
  }) => void;
}) {
  const [folderPath, setFolderPath] = useState("");
  const [keyword, setKeyword] = useState("");
  const [preset, setPreset] = useState("");
  const [presets, setPresets] = useState<Record<string, Preset>>({});
  const [engines, setEngines] = useState<string[]>(["baidu", "so360", "duckduckgo", "wikimedia"]);
  const [maxNum, setMaxNum] = useState(30);
  const [siteUrl, setSiteUrl] = useState("");
  const [siteArchive, setSiteArchive] = useState<"auto" | "yes" | "no">("auto");
  const [siteMaxNum, setSiteMaxNum] = useState(30);

  // --- Глобальный поиск ---
  const [gMode, setGMode] = useState<GlobalMode>("archive");
  const [gPresets, setGPresets] = useState<GlobalPresets | null>(null);
  const [gDomain, setGDomain] = useState("");
  const [gProvider, setGProvider] = useState<"auto" | "wayback" | "arquivo">("auto");
  const [gDelta, setGDelta] = useState(false);
  const [gDomState, setGDomState] = useState<GlobalDomainState | null>(null);
  const [gMask, setGMask] = useState("");
  const [gDorkPresets, setGDorkPresets] = useState<string[]>(["open_dirs"]);
  const [gGhPresets, setGGhPresets] = useState<string[]>(["wallet_files"]);
  const [gEngines, setGEngines] = useState<string[]>(["bing", "marginalia"]);
  const [gCustom, setGCustom] = useState("");
  const [gToken, setGToken] = useState("");
  const [gMaxUrls, setGMaxUrls] = useState(60);
  const [gMaxPages, setGMaxPages] = useState(10);
  const [gMaxFiles, setGMaxFiles] = useState(20);

  useEffect(() => {
    getPresets()
      .then(setPresets)
      .catch(() => setPresets({}));
    getGlobalPresets()
      .then(setGPresets)
      .catch(() => setGPresets(null));
  }, []);

  // дельта-состояние домена: подтягиваем с задержкой при вводе и после джобы
  useEffect(() => {
    if (gMode !== "archive") return;
    const dom = gDomain.trim();
    if (!dom) {
      setGDomState(null);
      return;
    }
    const t = setTimeout(() => {
      getGlobalState(dom)
        .then((r) => setGDomState(r.state))
        .catch(() => setGDomState(null));
    }, 400);
    return () => clearTimeout(t);
  }, [gMode, gDomain, busy]);

  const toggleEngine = (e: string) =>
    setEngines((prev) => (prev.includes(e) ? prev.filter((x) => x !== e) : [...prev, e]));
  const toggleIn = (setter: React.Dispatch<React.SetStateAction<string[]>>, v: string) =>
    setter((prev) => (prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]));

  const gDorkOk = gDorkPresets.length > 0 || gCustom.trim().length > 0;
  const gGhOk = gGhPresets.length > 0 || gCustom.trim().length > 0;
  const gCanStart =
    gMode === "archive"
      ? gDomain.trim().length > 0
      : gMode === "dorks"
        ? gDorkOk && gEngines.length > 0
        : gMode === "commoncrawl"
          ? gMask.trim().length > 0
          : gGhOk && gToken.trim().length > 0;

  const startGlobal = () => {
    if (gMode === "archive") {
      onGlobal({ mode: "archive", domain: gDomain.trim(), provider: gProvider, delta: gDelta, max_urls: gMaxUrls });
    } else if (gMode === "dorks") {
      onGlobal({ mode: "dorks", presets: gDorkPresets, custom: gCustom.trim(), engines: gEngines, max_pages: gMaxPages, max_files: gMaxFiles });
    } else if (gMode === "commoncrawl") {
      onGlobal({ mode: "commoncrawl", mask: gMask.trim(), max_urls: gMaxUrls });
    } else {
      onGlobal({ mode: "github", presets: gGhPresets, custom: gCustom.trim(), token: gToken.trim(), max_files: gMaxFiles });
    }
  };

  return (
    <Tabs value={active} onValueChange={(v) => onActiveChange(v as SourceTab)} className="w-full">
      <TabsList className="grid w-full grid-cols-5 bg-zinc-900 border border-zinc-800">
        <TabsTrigger value="upload" className="gap-1.5 data-[state=active]:text-emerald-400">
          <FolderOpen className="h-4 w-4" aria-hidden /> Файлы
        </TabsTrigger>
        <TabsTrigger value="folder" className="gap-1.5 data-[state=active]:text-emerald-400">
          <FolderOpen className="h-4 w-4" aria-hidden /> Папка
        </TabsTrigger>
        <TabsTrigger value="crawl" className="gap-1.5 data-[state=active]:text-emerald-400">
          <Globe className="h-4 w-4" aria-hidden /> Краулер
        </TabsTrigger>
        <TabsTrigger value="site" className="gap-1.5 data-[state=active]:text-emerald-400">
          <Link2 className="h-4 w-4" aria-hidden /> Сайт
        </TabsTrigger>
        <TabsTrigger value="global" className="gap-1.5 data-[state=active]:text-sky-400">
          <Radar className="h-4 w-4" aria-hidden /> Глобально
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
            Например, папка с выгрузкой изображений или любой каталог с JPG/PNG.
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
          <Label className="text-zinc-300">Поисковые системы ({engines.length}/9)</Label>
          <div className="flex flex-wrap gap-x-4 gap-y-2">
            {ENGINE_LIST.map((eng) => (
              <label key={eng.id} className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
                <Checkbox checked={engines.includes(eng.id)} onCheckedChange={() => toggleEngine(eng.id)} disabled={busy} />
                <span>
                  {eng.label}
                  <span className="ml-1 text-[10px] text-zinc-600">{eng.hint}</span>
                </span>
              </label>
            ))}
          </div>
          <p className="text-xs text-zinc-500">
            Baidu и 360 стабильно работают с серверных IP; Google, Bing, Sogou и другие часто
            блокируют дата-центры — включайте их при локальном запуске.
          </p>
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

      <TabsContent value="site" className="mt-4 space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="site-url" className="text-zinc-300">
            Адрес страницы
          </Label>
          <div className="flex gap-2">
            <Input
              id="site-url"
              placeholder="например: bitcointalk.org или bitcoin.org/ru/"
              value={siteUrl}
              onChange={(e) => setSiteUrl(e.target.value)}
              disabled={busy}
              className="bg-zinc-950/60 border-zinc-800 font-mono text-sm"
            />
            <Button
              onClick={() => onSite({ url: siteUrl.trim(), archive: siteArchive, maxNum: siteMaxNum })}
              disabled={busy || !siteUrl.trim()}
              className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400 shrink-0"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Search className="h-4 w-4" aria-hidden />}
              Парсить
            </Button>
          </div>
          <p className="text-xs text-zinc-500">
            Парсер собирает картинки со страницы и прогоняет их через сканер. Если сайт мёртв,
            возьмём сохранённую копию из веб-архива (Wayback Machine) — удобно для старых
            форумов и закрытых проектов.
          </p>
        </div>

        <div className="space-y-1.5">
          <Label className="text-zinc-300">Веб-архив</Label>
          <Select value={siteArchive} onValueChange={(v) => setSiteArchive(v as "auto" | "yes" | "no")} disabled={busy}>
            <SelectTrigger className="bg-zinc-950/60 border-zinc-800">
              <SelectValue placeholder="Режим" />
            </SelectTrigger>
            <SelectContent className="bg-zinc-900 border-zinc-800">
              <SelectItem value="auto">Авто: сайт → при неудаче архив</SelectItem>
              <SelectItem value="yes">Только веб-архив (Wayback)</SelectItem>
              <SelectItem value="no">Только прямая загрузка</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label className="text-zinc-300">Максимум фото: {siteMaxNum}</Label>
          <Slider value={[siteMaxNum]} min={5} max={200} step={5} onValueChange={(v) => setSiteMaxNum(v[0])} disabled={busy} />
        </div>
      </TabsContent>

      <TabsContent value="global" className="mt-4 space-y-4">
        {/* выбор режима */}
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {GLOBAL_MODES.map((m) => {
            const Icon = m.icon;
            const on = gMode === m.id;
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => setGMode(m.id)}
                disabled={busy}
                className={`rounded-md border p-2.5 text-left transition-colors ${
                  on
                    ? "border-sky-400 bg-sky-400/10 text-sky-300"
                    : "border-zinc-800 bg-zinc-950/60 text-zinc-300 hover:border-zinc-600"
                }`}
              >
                <Icon className="mb-1 h-4 w-4" aria-hidden />
                <div className="text-sm font-medium">{m.label}</div>
                <div className="text-[10px] leading-tight text-zinc-500">{m.hint}</div>
              </button>
            );
          })}
        </div>

        {/* --- Режим: Архивы --- */}
        {gMode === "archive" && (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="g-domain" className="text-zinc-300">Домен целиком</Label>
              <Input
                id="g-domain"
                placeholder="например: bitcointalk.org или oldforum.com/forum/*"
                value={gDomain}
                onChange={(e) => setGDomain(e.target.value)}
                disabled={busy}
                className="bg-zinc-950/60 border-zinc-800 font-mono text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-zinc-300">Источник архива</Label>
              <Select value={gProvider} onValueChange={(v) => setGProvider(v as typeof gProvider)} disabled={busy}>
                <SelectTrigger className="bg-zinc-950/60 border-zinc-800">
                  <SelectValue placeholder="Провайдер" />
                </SelectTrigger>
                <SelectContent className="bg-zinc-900 border-zinc-800">
                  <SelectItem value="auto">Авто: Wayback → arquivo.pt</SelectItem>
                  <SelectItem value="wayback">Wayback Machine (локально)</SelectItem>
                  <SelectItem value="arquivo">arquivo.pt (из дата-центров)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-zinc-500">
                CDX API перечисляет все сохранённые снимки домена: картинки и страницы PDF уйдут
                в сканер QR, страницы и файлы — в детекторы строк. arquivo.pt работает с серверных IP, но глубоко
                индексирует только португальский веб; полный охват — Wayback на локальной машине.
              </p>
            </div>

            {/* дельта: не проходить по кругу */}
            <label className="flex items-start gap-2 text-sm text-zinc-300 cursor-pointer">
              <Checkbox checked={gDelta} onCheckedChange={(v) => setGDelta(v === true)} disabled={busy} className="mt-0.5" />
              <span>
                Только новое (дельта)
                <span className="ml-1 text-[10px] text-zinc-600">
                  пропускать снимки, уже скачанные в прошлый раз
                </span>
              </span>
            </label>

            {gDomState && (
              <div className="rounded-md border border-zinc-800 bg-zinc-950/60 p-2.5 text-xs text-zinc-400 space-y-1">
                <div>
                  Последний проход: <span className="text-zinc-200">{fmtStateDate(gDomState.last_run) || "неизвестно"}</span>
                  {" · "}снимков: <span className="text-zinc-200">{gDomState.last_count ?? "?"}</span>
                  {gDomState.provider && <> · архив: <span className="text-zinc-200">{gDomState.provider}</span></>}
                </div>
                <div>
                  {gDomState.complete
                    ? "Домен охвачен целиком — дельта возьмёт только новые снимки."
                    : "Домен больше лимита URL: старые снимки остались вне прохода (увеличьте «Максимум URL» для полного охвата)."}
                </div>
                <button
                  type="button"
                  onClick={() =>
                    resetGlobalState(gDomain.trim())
                      .then(() => setGDomState(null))
                      .catch(() => undefined)
                  }
                  disabled={busy}
                  className="inline-flex items-center gap-1 text-[11px] text-zinc-500 hover:text-amber-400 transition-colors disabled:opacity-50"
                >
                  <RotateCcw className="h-3 w-3" aria-hidden />
                  Сбросить дельту (в следующий раз пройти всё заново)
                </button>
              </div>
            )}
            <div className="space-y-2">
              <Label className="text-zinc-300">Максимум URL: {gMaxUrls}</Label>
              <Slider value={[gMaxUrls]} min={10} max={400} step={10} onValueChange={(v) => setGMaxUrls(v[0])} disabled={busy} />
            </div>
          </div>
        )}

        {/* --- Режим: Dork-поиск --- */}
        {gMode === "dorks" && (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label className="text-zinc-300">Пресеты dork-запросов</Label>
              <div className="flex flex-wrap gap-2">
                {Object.entries(gPresets?.dorks ?? {}).map(([key, p]) => (
                  <Badge
                    key={key}
                    variant={gDorkPresets.includes(key) ? "default" : "outline"}
                    className={
                      gDorkPresets.includes(key)
                        ? "cursor-pointer bg-sky-500 text-zinc-950 hover:bg-sky-400"
                        : "cursor-pointer border-zinc-700 text-zinc-300 hover:border-sky-400 hover:text-sky-400"
                    }
                    onClick={() => toggleIn(setGDorkPresets, key)}
                  >
                    <Sparkles className="mr-1 h-3 w-3" aria-hidden />
                    {p.label}
                  </Badge>
                ))}
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="g-dork-custom" className="text-zinc-300">Или свой dork-запрос</Label>
              <Input
                id="g-dork-custom"
                placeholder='например: intitle:"index of" "wallet backup"'
                value={gCustom}
                onChange={(e) => setGCustom(e.target.value)}
                disabled={busy}
                className="bg-zinc-950/60 border-zinc-800 font-mono text-sm"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Поисковые движки</Label>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                {Object.entries(gPresets?.dork_engines ?? {}).map(([id, label]) => (
                  <label key={id} className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
                    <Checkbox checked={gEngines.includes(id)} onCheckedChange={() => toggleIn(setGEngines, id)} disabled={busy} />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
              <p className="text-xs text-zinc-500">
                Bing и Marginalia работают с серверных IP, но без поисковых операторов; полные
                dork-запросы (intitle:, filetype:) исполняют Baidu и DuckDuckGo на локальной машине.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label className="text-zinc-300">Страниц на движок: {gMaxPages}</Label>
                <Slider value={[gMaxPages]} min={3} max={30} step={1} onValueChange={(v) => setGMaxPages(v[0])} disabled={busy} />
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-300">Файлов всего: {gMaxFiles}</Label>
                <Slider value={[gMaxFiles]} min={3} max={60} step={1} onValueChange={(v) => setGMaxFiles(v[0])} disabled={busy} />
              </div>
            </div>
          </div>
        )}

        {/* --- Режим: Common Crawl --- */}
        {gMode === "commoncrawl" && (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="g-mask" className="text-zinc-300">Маска URL</Label>
              <Input
                id="g-mask"
                placeholder="например: example.com/* или *.forum.org/attachments/*"
                value={gMask}
                onChange={(e) => setGMask(e.target.value)}
                disabled={busy}
                className="bg-zinc-950/60 border-zinc-800 font-mono text-sm"
              />
              <p className="text-xs text-zinc-500">
                Индекс Common Crawl покрывает миллиарды страниц без капч и блокировок. Из
                выдачи берём картинки (в QR-сканер), страницы и файлы (в детекторы строк).
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Максимум URL: {gMaxUrls}</Label>
              <Slider value={[gMaxUrls]} min={10} max={400} step={10} onValueChange={(v) => setGMaxUrls(v[0])} disabled={busy} />
            </div>
            <p className="rounded-md border border-amber-500/30 bg-amber-500/10 p-2 text-xs text-amber-300">
              index.commoncrawl.org часто недоступен с дата-центровских IP — из дата-центра режим
              вернёт честную ошибку; на локальной машине работает.
            </p>
          </div>
        )}

        {/* --- Режим: GitHub --- */}
        {gMode === "github" && (
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label className="text-zinc-300">Пресеты поиска по коду</Label>
              <div className="flex flex-wrap gap-2">
                {Object.entries(gPresets?.github ?? {}).map(([key, p]) => (
                  <Badge
                    key={key}
                    variant={gGhPresets.includes(key) ? "default" : "outline"}
                    className={
                      gGhPresets.includes(key)
                        ? "cursor-pointer bg-sky-500 text-zinc-950 hover:bg-sky-400"
                        : "cursor-pointer border-zinc-700 text-zinc-300 hover:border-sky-400 hover:text-sky-400"
                    }
                    onClick={() => toggleIn(setGGhPresets, key)}
                  >
                    <Sparkles className="mr-1 h-3 w-3" aria-hidden />
                    {p.label}
                  </Badge>
                ))}
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="g-gh-custom" className="text-zinc-300">Или свой запрос</Label>
              <Input
                id="g-gh-custom"
                placeholder='например: filename:wallet.dat или "seed" language:JSON'
                value={gCustom}
                onChange={(e) => setGCustom(e.target.value)}
                disabled={busy}
                className="bg-zinc-950/60 border-zinc-800 font-mono text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="g-gh-token" className="text-zinc-300">GitHub-токен (поиск кода требует авторизацию)</Label>
              <Input
                id="g-gh-token"
                type="password"
                placeholder="ghp_…"
                value={gToken}
                onChange={(e) => setGToken(e.target.value)}
                disabled={busy}
                className="bg-zinc-950/60 border-zinc-800 font-mono text-sm"
              />
              <p className="text-xs text-zinc-500">
                Токен используется только на время джобы и не сохраняется. Скачанные файлы
                репозиториев идут в детекторы строк (WIF, сиды, адреса).
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Файлов всего: {gMaxFiles}</Label>
              <Slider value={[gMaxFiles]} min={3} max={60} step={1} onValueChange={(v) => setGMaxFiles(v[0])} disabled={busy} />
            </div>
          </div>
        )}

        <Button
          onClick={startGlobal}
          disabled={busy || !gCanStart}
          className="w-full bg-sky-500 text-zinc-950 hover:bg-sky-400"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Radar className="h-4 w-4" aria-hidden />}
          Запустить глобальный поиск
        </Button>
      </TabsContent>
    </Tabs>
  );
}
