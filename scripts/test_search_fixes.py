#!/usr/bin/env python3
"""Юнит-тесты фиксов поиска: bing relevance-check, sourcegraph_search, serp_arquivo."""
import sys, json
sys.path.insert(0, "/home/z/my-project/mini-services/scanner-service")

from engine import globalsearch as gs

PASS = []
def ok(name, cond, extra=""):
    PASS.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}: {name} {extra}")

class FakeResp:
    def __init__(self, text="", status_code=200, payload=None):
        self.text = text if payload is None else json.dumps(payload)
        self.status_code = status_code

    def json(self):
        return json.loads(self.text)

def _bing_html(results):
    """results: list[(title, url)] -> фейковая выдача Bing."""
    import base64
    blocks = []
    for t, u in results:
        enc = base64.urlsafe_b64encode(u.encode()).decode().rstrip("=")
        blocks.append(
            f'<li class="b_algo"><h2><a href="https://www.bing.com/ck/a?&amp;u=a1{enc}">'
            f'{t}</a></h2><p>snippet</p></li>')
    return "<html>" + "".join(blocks) + "</html>"

# --- 1. Bing: мусорная выдача распознаётся ---
garbage = _bing_html([
    ("Лучшие блюда Вьетнама", "https://www.tasteatlas.com/best-rated-dishes-in-vietnam"),
    ("Travel guide", "https://vietnam.travel/things-to-do"),
    ("Food blog", "https://foodvietnamese.com/food"),
    ("Recipes", "https://example.org/recipes"),
])
orig_get = gs._get
gs._get = lambda *a, **kw: FakeResp(text=garbage)
r = gs.serp_bing('"seed.txt" bitcoin backup', 10)
ok("bing poisoned -> error", r["urls"] == [] and "не по запросу" in (r["error"] or ""), r["error"])

# --- 2. Bing: релевантная выдача проходит ---
good = _bing_html([
    ("How to backup a bitcoin seed.txt file", "https://coinsutra.com/seed-txt-backup/"),
    ("Bitcoin paper wallet guide", "https://bitcoin.org/paper-wallet"),
    ("Seed phrase backup best practices", "https://blog.lopp.net/seed-backup"),
    ("wallet.dat backup instructions", "https://electrum.org/backup"),
])
gs._get = lambda *a, **kw: FakeResp(text=good)
r = gs.serp_bing('"seed.txt" bitcoin backup', 10)
ok("bing relevant -> urls", r["urls"] and r["error"] is None and len(r["urls"]) == 4, str(len(r["urls"])))
gs._get = orig_get

# --- 3. Sourcegraph: парсинг SSE + перевод filename: -> file: ---
sse = (
    'event: matches\ndata: [{"repository": "github.com/org/repo1", "path": "src/a.txt", "lineMatches": []}]\n'
    'event: matches\ndata: [{"repository": "gitlab.com/org/repo2", "path": "b.txt"}]\n'
    'event: matches\ndata: [{"repository": "github.com/org/repo1", "path": "src/a.txt"}]\n'
    'event: progress\ndata: [{"done": true, "matchCount": 2}]\n'
)
captured = {}
def fake_sg_get(url, params=None, headers=None, timeout=None):
    captured["url"] = url
    captured["q"] = (params or {}).get("q", "")
    return FakeResp(text=sse)
gs._get = fake_sg_get
r = gs.sourcegraph_search('filename:seed.txt "abandon abandon"', 10)
ok("sourcegraph only github files", [f["repo"] for f in r["files"]] == ["org/repo1"], str(r))
ok("sourcegraph raw url", r["files"] and r["files"][0]["raw"] ==
   "https://raw.githubusercontent.com/org/repo1/HEAD/src/a.txt")
ok("sourcegraph filename->file:", "file:seed.txt" in captured["q"] and "filename:" not in captured["q"],
   captured["q"])
ok("sourcegraph count/timeout in q", "count:" in captured["q"] and "timeout:20s" in captured["q"])

# --- 4. Sourcegraph: пустая выдача + alert ---
gs._get = lambda *a, **kw: FakeResp(text='event: alert\ndata: ["bad query"]\n')
r = gs.sourcegraph_search("zzz", 5)
ok("sourcegraph alert surfaced", r["files"] == [] and "bad query" in (r["error"] or ""), str(r))

# --- 5. Arquivo: парсинг + дедуп по оригинальному URL ---
payload = {"response_items": [
    {"title": "a", "originalURL": "https://ex.com/page", "linkToNoFrame": "https://arquivo.pt/noFrame/replay/2024/https://ex.com/page"},
    {"title": "a-snap2", "originalURL": "https://ex.com/page", "linkToNoFrame": "https://arquivo.pt/noFrame/replay/2023/https://ex.com/page"},
    {"title": "b", "originalURL": "https://ex.com/other", "linkToNoFrame": "https://arquivo.pt/noFrame/replay/2024/https://ex.com/other"},
]}
gs._get = lambda *a, **kw: FakeResp(payload=payload)
r = gs.serp_arquivo('"seed phrase" backup', 10)
ok("arquivo dedupe by originalURL", len(r["urls"]) == 2, str(r["urls"]))
ok("arquivo newest first", r["urls"][0].endswith("/2024/https://ex.com/page"))
gs._get = orig_get

# --- 6. Пресеты GitHub содержат WIF-тестовый ключ ---
wif_q = [q for q in gs.GITHUB_PRESETS["known_seeds"]["queries"] if "5HpHag" in q]
ok("known_seeds has WIF test key", bool(wif_q))

# --- 7. Регистрация arquivo в реестрах ---
ok("arquivo in SERPS", "arquivo" in gs.SERPS)
ok("arquivo plain-only", "arquivo" in gs.PLAIN_ONLY_ENGINES)
ok("arquivo in DORK_ENGINE_LABELS", "arquivo" in gs.DORK_ENGINE_LABELS)

# --- 8. _query_tokens: дот-токены раскладываются ---
toks = gs._query_tokens('"seed.txt" bitcoin backup')
ok("query tokens", "seed.txt" in toks and "seed" in toks and "bitcoin" in toks, str(toks))

fails = [n for n, c in PASS if not c]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} PASS" + (f"; FAILS: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
