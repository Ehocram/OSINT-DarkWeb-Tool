#!/usr/bin/env python3
"""
DarkWeb OSINT Intelligence Tool v1.1
Sviluppato da: Marco Bonometti — CISO
Uso legittimo: SOC team, CISO, ricercatori di sicurezza.
"""

import sys, json, csv, sqlite3, datetime, re, time, socket, ssl
import urllib.request, urllib.parse, urllib.error
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget,
    QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QStatusBar, QSplitter,
    QDialog, QFormLayout, QSpinBox, QMessageBox, QFileDialog, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QColor, QPalette, QFont, QTextCursor, QAction

# ─── DB ────────────────────────────────────────────────────────────────────────
DB_PATH = Path.home() / ".darkweb_osint" / "osint.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def get_db():
    c = sqlite3.connect(str(DB_PATH)); c.row_factory = sqlite3.Row; return c

def init_db():
    with get_db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS searches(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, keywords TEXT, backend TEXT, result_count INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS results(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                search_id INTEGER, title TEXT, url TEXT, snippet TEXT, source TEXT, found_at TEXT);
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword TEXT NOT NULL UNIQUE, active INTEGER DEFAULT 1,
                created_at TEXT, last_triggered TEXT, trigger_count INTEGER DEFAULT 0);
        """)
init_db()

# ─── HTTP helpers ──────────────────────────────────────────────────────────────
def _make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _fetch(url: str, timeout: int = 15, socks_port: int | None = None) -> str:
    """
    Fetch URL. Se socks_port è impostato usa PySocks con proxy_rdns=True
    (risoluzione DNS sul nodo Tor — necessario per .onion).
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "identity",
    }
    if socks_port:
        import socks as _socks, http.client as _http, ssl as _ssl
        parsed = urllib.parse.urlparse(url)
        host   = parsed.hostname
        is_ssl = parsed.scheme == "https"
        port   = parsed.port or (443 if is_ssl else 80)
        path   = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        # create_connection con proxy_rdns=True: il DNS viene risolto dal nodo Tor
        sock = _socks.create_connection(
            (host, port), timeout,
            proxy_type=_socks.SOCKS5, proxy_addr="127.0.0.1",
            proxy_port=socks_port, proxy_rdns=True
        )
        if is_ssl:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        conn = (_http.HTTPSConnection if is_ssl else _http.HTTPConnection)(host, port, timeout=timeout)
        conn.sock = sock
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return data.decode("utf-8", errors="replace")
    else:
        req    = urllib.request.Request(url, headers=headers)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_make_ssl_ctx()))
        with opener.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")

# ─── Ahmia Parser ──────────────────────────────────────────────────────────────
# ─── Backends ──────────────────────────────────────────────────────────────────
# Ahmia (sia clearnet che .onion) usa JavaScript per i risultati — non ha API REST pubblica.
# Usiamo motori alternativi con endpoint server-side funzionanti:
#   - Tor: msydqstlz2kzerdg.onion (Ahmia mirror) + DuckDuckGo .onion
#   - Clearnet: HiddenSearch API + Tor2Web aggregators

def _decode_ddg_url(raw: str) -> str:
    """Decodifica URL DDG redirect: /l/?uddg=https%3A%2F%2F... → URL reale"""
    m = re.search(r'uddg=([^&]+)', raw)
    if m:
        return urllib.parse.unquote(m.group(1))
    return raw

def _parse_ddg_html(html: str, source: str) -> list[dict]:
    """
    Parser DDG /html/ — struttura verificata:
    class="result results_links results_links_deep web-result"
      h2 class="result__title"
        a class="result__a" href="/l/?uddg=URL_encoded"  → titolo
      div class="result__extras__url" → URL visibile
      div/a class="result__snippet" → snippet
    """
    clean = lambda s: re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', s)).strip()
    results = []

    # Estrai direttamente result__a (titolo + URL redirect)
    anchors  = re.findall(
        r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        html, re.DOTALL | re.I
    )
    snippets = re.findall(
        r'class="result__snippet"[^>]*>(.*?)</(?:a|div)>',
        html, re.DOTALL | re.I
    )

    for i, (raw_url, title_raw) in enumerate(anchors[:25]):
        title = clean(title_raw)
        if not title or len(title) < 4:
            continue
        url = _decode_ddg_url(raw_url)
        snippet = clean(snippets[i])[:300] if i < len(snippets) else ""
        results.append({"title": title, "url": url, "snippet": snippet, "source": source})

    return results


def _parse_haystak(html: str, source: str) -> list[dict]:
    """Parser per Haystak .onion — motore con endpoint server-side."""
    clean = lambda s: re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', s)).strip()
    results = []
    # Haystak usa <div class="result"> con <h4> e <p>
    blocks = re.findall(r'<div[^>]+class=["\'][^"\']*result[^"\']*["\'][^>]*>(.*?)</div>', html, re.DOTALL|re.I)
    if not blocks:
        blocks = re.findall(r'<article[^>]*>(.*?)</article>', html, re.DOTALL|re.I)
    for b in blocks[:25]:
        t = re.search(r'<h[2-5][^>]*>(.*?)</h[2-5]>', b, re.DOTALL|re.I) or re.search(r'<a[^>]*>(.*?)</a>', b, re.DOTALL|re.I)
        title = clean(t.group(1)) if t else ""
        if not title or len(title) < 4: continue
        u = re.search(r'href=["\']([^"\']+)["\']', b, re.I)
        url = u.group(1) if u else ""
        s = re.search(r'<p[^>]*>(.*?)</p>', b, re.DOTALL|re.I)
        snippet = clean(s.group(1))[:300] if s else ""
        results.append({"title": title, "url": url, "snippet": snippet, "source": source})
    return results


class AhmiaBackend:
    NAME = "Ahmia.fi"

    @staticmethod
    def search(kw: str, timeout=20) -> list[dict]:
        """
        Ahmia non ha API pubblica senza JS.
        Usiamo HiddenSearch come alternativa clearnet con API REST.
        """
        q = urllib.parse.quote_plus(kw)
        # HiddenSearch — aggregatore clearnet con risultati .onion
        sources = [
            ("https://hiddensearch.onion.pet/search?q={q}&lang=en",   _parse_haystak),
            ("https://tor.link/search?q={q}",                          _parse_ddg_html),
            ("https://onion.live/search?q={q}",                        _parse_ddg_html),
        ]
        for url_tpl, parser in sources:
            try:
                url = url_tpl.format(q=q)
                html = _fetch(url, timeout)
                res  = parser(html, "Clearnet Aggregator")
                if res: return res
            except Exception:
                pass
        return [{"title": "[Clearnet: nessun risultato]", "url": "",
                 "snippet": "Nessun aggregatore clearnet ha restituito risultati. "
                            "Usa il backend Tor per ricerche dirette su .onion.",
                 "source": "Ahmia.fi"}]


class TorProxyBackend:
    NAME = "Tor Proxy (locale)"

    @staticmethod
    def _tor_port() -> int:
        for p in (9150, 9050):
            try:
                s = socket.create_connection(("127.0.0.1", p), timeout=3)
                s.close()
                return p
            except Exception:
                pass
        return 0

    @staticmethod
    def _onion_request(host: str, port_num: int, path: str, tor_port: int,
                       timeout: int, cookies: dict | None = None) -> tuple[int, dict, str]:
        import socks as _socks, http.client as _http
        sock = _socks.create_connection(
            (host, port_num), timeout,
            proxy_type=_socks.SOCKS5, proxy_addr="127.0.0.1",
            proxy_port=tor_port, proxy_rdns=True
        )
        conn = _http.HTTPConnection(host, port_num, timeout=timeout)
        conn.sock = sock
        hdrs = {
            "Host": host,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
        }
        if cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        status = resp.status
        headers = dict(resp.getheaders())
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()
        return status, headers, body

    @staticmethod
    def _ddg_onion_search(kw: str, tor_port: int, timeout: int) -> list[dict]:
        """
        DuckDuckGo .onion /html/ — HTTPS port 443, server-side, no JS.
        Verificato funzionante.
        """
        import socks as _socks, http.client as _http, ssl as _ssl
        host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        q    = urllib.parse.quote_plus(kw)
        path = f"/html/?q={q}&kl=wt-wt&kp=-2"

        sock = _socks.create_connection(
            (host, 443), timeout,
            proxy_type=_socks.SOCKS5, proxy_addr="127.0.0.1",
            proxy_port=tor_port, proxy_rdns=True
        )
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

        conn = _http.HTTPSConnection(host, 443, timeout=timeout)
        conn.sock = sock
        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        resp = conn.getresponse()
        html = resp.read().decode("utf-8", errors="replace")
        conn.close()
        return _parse_ddg_html(html, f"DuckDuckGo .onion (Tor :{tor_port})")

    @staticmethod
    def search(kw: str, timeout=40) -> list[dict]:
        port = TorProxyBackend._tor_port()
        if not port:
            return [{"title": "[Tor non disponibile]", "url": "",
                     "snippet": "Tor non trovato su :9150 (Tor Browser) né :9050 (daemon).",
                     "source": "Tor Proxy"}]
        try:
            import socks as _t; del _t
        except ImportError:
            return [{"title": "[PySocks non installato]", "url": "",
                     "snippet": "pip install PySocks nel venv.",
                     "source": "Tor Proxy"}]

        # DuckDuckGo .onion /html/ — verificato funzionante (HTTPS:443)
        try:
            res = TorProxyBackend._ddg_onion_search(kw, port, timeout)
            if res:
                return res
        except Exception as e:
            last = f"DDG .onion: {type(e).__name__}: {e}"
        else:
            last = "DDG .onion: nessun risultato parsato"

        return [{"title": "[Tor: nessun risultato]", "url": "",
                 "snippet": f"Connesso su :{port} ma nessun risultato. {last}",
                 "source": "Tor Proxy"}]
# ─── Worker thread ─────────────────────────────────────────────────────────────
class SearchWorker(QThread):
    results_ready = pyqtSignal(list, str)
    error         = pyqtSignal(str)
    progress      = pyqtSignal(int)

    def __init__(self, kw, backends, api_key="", api_ep=""):
        super().__init__()
        self.kw, self.backends, self.api_key, self.api_ep = kw, backends, api_key, api_ep

    def run(self):
        n = len(self.backends)
        for i, b in enumerate(self.backends):
            self.progress.emit(int(i/n*100))
            try:
                if   b == "Ahmia.fi":           r = AhmiaBackend.search(self.kw)
                elif b == "Tor Proxy (locale)":  r = TorProxyBackend.search(self.kw)
                elif b == "API Commerciale":     r = CommercialAPIBackend.search(self.kw, self.api_key, self.api_ep)
                else: continue
                self.results_ready.emit(r, b)
            except Exception as e:
                self.error.emit(f"{b}: {e}")
        self.progress.emit(100)

# ─── Alert monitor ─────────────────────────────────────────────────────────────
class AlertMonitor(QThread):
    alert_triggered = pyqtSignal(str, list)
    def __init__(self, interval_min=30):
        super().__init__(); self.interval = interval_min*60; self._stop = False
    def stop(self): self._stop = True
    def run(self):
        while not self._stop:
            self._check()
            for _ in range(self.interval):
                if self._stop: return
                time.sleep(1)
    def _check(self):
        with get_db() as c:
            alerts = c.execute("SELECT * FROM alerts WHERE active=1").fetchall()
        for a in alerts:
            hits = [r for r in AhmiaBackend.search(a["keyword"]) if "[" not in r["title"]]
            if hits:
                self.alert_triggered.emit(a["keyword"], hits)
                with get_db() as c:
                    c.execute("UPDATE alerts SET last_triggered=?,trigger_count=trigger_count+1 WHERE id=?",
                              (datetime.datetime.now().isoformat(), a["id"]))

# ─── Dark theme ────────────────────────────────────────────────────────────────
class HIBPBackend:
    """Have I Been Pwned API v3 — breach per dominio aziendale."""
    NAME = "HIBP"

    @staticmethod
    def search_domain(domain: str, api_key: str, timeout=15) -> list[dict]:
        if not api_key:
            return [{"title":"[HIBP: API key mancante]","url":"https://haveibeenpwned.com/API/Key",
                     "snippet":"Ottieni API key su haveibeenpwned.com. Inseriscila in Impostazioni.","source":"HIBP","severity":"info"}]
        try:
            url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{urllib.parse.quote(domain)}"
            req = urllib.request.Request(url, headers={"hibp-api-key":api_key,"User-Agent":"OSINTTool/2.0","Accept":"application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read())
            results = []
            for email, breaches in data.items():
                for breach in breaches:
                    results.append({"title":f"💧 {email} — {breach}","url":f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}",
                                    "snippet":f"Account trovato nel breach: {breach}","source":"HIBP","severity":"high"})
            return results or [{"title":f"✅ Nessun breach per {domain}","url":"","snippet":"Dominio non presente in breach noti.","source":"HIBP","severity":"ok"}]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return [{"title":f"✅ {domain} non trovato in breach","url":"","snippet":"Nessun breach noto.","source":"HIBP","severity":"ok"}]
            if e.code == 401:
                return [{"title":"[HIBP: API key non valida]","url":"","snippet":"Verifica la API key.","source":"HIBP","severity":"error"}]
            return [{"title":f"[HIBP Error {e.code}]","url":"","snippet":str(e),"source":"HIBP","severity":"error"}]
        except Exception as e:
            return [{"title":"[HIBP Errore]","url":"","snippet":str(e),"source":"HIBP","severity":"error"}]

    @staticmethod
    def search_breaches(keyword: str, timeout=15) -> list[dict]:
        try:
            req = urllib.request.Request("https://haveibeenpwned.com/api/v3/breaches",
                                         headers={"User-Agent":"OSINTTool/2.0","Accept":"application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                breaches = json.loads(r.read())
            kw = keyword.lower()
            results = []
            for b in breaches:
                if kw in b.get("Name","").lower() or kw in b.get("Domain","").lower():
                    pwn = b.get("PwnCount",0); dt = b.get("BreachDate","?")
                    classes = ", ".join(b.get("DataClasses",[])[:5])
                    results.append({"title":f"🔓 {b['Name']} ({dt}) — {pwn:,} account",
                                    "url":f"https://haveibeenpwned.com/PwnedWebsites#{b['Name']}",
                                    "snippet":f"Leaked: {classes}","source":"HIBP Public",
                                    "severity":"high" if pwn>1_000_000 else "medium"})
            return results or [{"title":f"Nessun breach pubblico per '{keyword}'","url":"","snippet":"","source":"HIBP Public","severity":"ok"}]
        except Exception as e:
            return [{"title":"[HIBP Public Error]","url":"","snippet":str(e),"source":"HIBP Public","severity":"error"}]
class RansomwareBackend:
    """
    RansomLook API — aggrega post dei principali ransomware group leak site.
    Pubblico, no auth richiesta.
    """
    NAME = "Ransomware Leak Sites"
    BASE = "https://www.ransomlook.io/api"

    # Indirizzi .onion noti dei principali gruppi ransomware (aggiornati)
    ONION_SITES = {
        "lockbit":    "lockbit3olp7oetlc.onion",
        "blackcat":   "alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion",
        "cl0p":       "clop24oimnbzlb2g.onion",
        "play":       "k7kg3jqxang3wh7zkvzvmgrqtedvyibkzcncon4t3dszopbpk3gyevyd.onion",
        "akira":      "akiral2iz6a7qgd3ayp3l6yub7xx7inolbyiqn74v3zkjbcdenla67qd.onion",
        "rhysida":    "rhysidafohrhyy7bfnirxn56fpfcfchvhfmkzzbpemrewmhcqseyq5ad.onion",
        "hunters":    "hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejkid.onion",
        "8base":      "basemmdzxpxnxmxhesoaasw4fdxztbkv7jrquihqvdlb7x4bwz7fjqd.onion",
        "ransomhouse":"ransomhouses3k6jjikq2xlssjprzlzn3jy5l5smgk63nkrxlsxhvvid.onion",
    }

    @staticmethod
    def search(keyword: str, timeout=20) -> list[dict]:
        kw_lower = keyword.lower()
        results  = []
        try:
            # Lista tutti i post recenti
            url = f"{RansomwareBackend.BASE}/recent"
            req = urllib.request.Request(url, headers={"User-Agent":"OSINTTool/2.0","Accept":"application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                posts = json.loads(r.read())
            for p in posts:
                title    = p.get("post_title", p.get("title","")).strip()
                group    = p.get("group_name", p.get("group","?"))
                desc     = p.get("description", p.get("post_description",""))
                pub_date = p.get("published","")
                if kw_lower in title.lower() or kw_lower in desc.lower():
                    # Cerca URL .onion del gruppo
                    onion = p.get("url", p.get("link",""))
                    if not onion:
                        for g_key, g_onion in RansomwareBackend.ONION_SITES.items():
                            if g_key in group.lower():
                                onion = f"http://{g_onion}"
                                break
                    results.append({
                        "title": f"🚨 [{group}] {title}",
                        "url":   onion,
                        "snippet": f"Pubblicato: {pub_date}. {desc[:200]}",
                        "source": f"RansomLook / {group}",
                        "severity": "critical"
                    })
        except Exception as e:
            results.append({"title":"[RansomLook API error]","url":"","snippet":str(e),"source":"RansomLook","severity":"error"})

        # Fallback: RansomWatch (endpoint aggiornato)
        if not [r for r in results if r.get("severity") == "critical"]:
            for rw_url in [
                "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
                "https://ransomwatch.telemetry.ltd/posts.json",
            ]:
                try:
                    req = urllib.request.Request(rw_url, headers={"User-Agent":"OSINTTool/2.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        posts = json.loads(r.read())
                    for p in posts:
                        title = p.get("post_title","")
                        group = p.get("group_name","?")
                        if kw_lower in title.lower():
                            results.append({
                                "title":   f"🚨 [{group}] {title}",
                                "url":     "",
                                "snippet": f"Trovato su RansomWatch. Data: {p.get('discovered','')}",
                                "source":  f"RansomWatch / {group}",
                                "severity": "critical"
                            })
                    break  # se arriva qui senza eccezione, stop
                except Exception as e:
                    results.append({"title":"[RansomWatch error]","url":"","snippet":str(e),"source":"RansomWatch","severity":"error"})

        return results or [{"title":f"✅ Nessun leak ransomware per '{keyword}'","url":"",
                            "snippet":"Nessuna vittima trovata nei database ransomware monitorati.",
                            "source":"Ransomware","severity":"ok"}]


class PasteBackend:
    """
    Cerca keyword su aggregatori di paste pubblici.
    Psbdmp.ws ha API pubblica JSON senza auth.
    """
    NAME = "Paste Sites"

    @staticmethod
    def search(keyword: str, timeout=15) -> list[dict]:
        results = []
        q = urllib.parse.quote_plus(keyword)

        # Fonte 1: psbdmp.ws
        try:
            url = f"https://psbdmp.ws/api/v3/search/{q}"
            req = urllib.request.Request(url, headers={"User-Agent":"OSINTTool/2.0","Accept":"application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read())
            items = data.get("data", data if isinstance(data, list) else [])
            for item in items[:30]:
                paste_id = item.get("id","")
                title    = item.get("title","") or item.get("text","")[:60] or f"Paste {paste_id}"
                results.append({
                    "title":   f"📋 {title}",
                    "url":     f"https://pastebin.com/{paste_id}" if paste_id else "",
                    "snippet": f"Trovato: {item.get('time','')}",
                    "source":  "Pastebin (psbdmp)",
                    "severity": "high"
                })
        except Exception:
            pass  # offline o timeout — prova fallback

        # Fonte 2: IntelX public search (no auth, risultati limitati)
        if not results:
            try:
                url = f"https://2.intelx.io/intelligent/search?term={q}&target=3&maxresults=20&timeout=5"
                req = urllib.request.Request(url, headers={"User-Agent":"OSINTTool/2.0","Accept":"application/json","x-key":"null"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.loads(r.read())
                for item in data.get("records", [])[:20]:
                    results.append({
                        "title":   f"📋 {item.get('name', item.get('type','paste'))}",
                        "url":     "",
                        "snippet": f"Fonte: {item.get('storageid','')} | {item.get('date','')}",
                        "source":  "IntelX",
                        "severity": "high"
                    })
            except Exception:
                pass

        # Fonte 3: DDG clearnet per paste recenti
        if not results:
            try:
                search_url = f"https://html.duckduckgo.com/html/?q={q}+site:pastebin.com+OR+site:paste.ee+OR+site:ghostbin.co"
                req = urllib.request.Request(search_url, headers={
                    "User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
                })
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    html = r.read().decode("utf-8", errors="replace")
                anchors = re.findall(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL|re.I)
                snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</(?:a|div)>', html, re.DOTALL|re.I)
                clean = lambda s: re.sub(r'\s+',' ',re.sub(r'<[^>]+>','',s)).strip()
                for i,(raw_url,title_raw) in enumerate(anchors[:15]):
                    url_decoded = urllib.parse.unquote(re.search(r'uddg=([^&]+)',raw_url).group(1)) if 'uddg=' in raw_url else raw_url
                    if 'pastebin' in url_decoded or 'paste' in url_decoded:
                        results.append({
                            "title":   f"📋 {clean(title_raw)}",
                            "url":     url_decoded,
                            "snippet": clean(snippets[i])[:200] if i < len(snippets) else "",
                            "source":  "DDG Paste Search",
                            "severity": "high"
                        })
            except Exception as e:
                results.append({"title":"[Paste DDG error]","url":"","snippet":str(e),"source":"Paste","severity":"error"})

        return results or [{"title":f"✅ Nessun paste trovato per '{keyword}'","url":"",
                            "snippet":"Nessun risultato su psbdmp, IntelX o DDG paste search.",
                            "source":"Paste","severity":"ok"}]


# ─── Dark theme ────────────────────────────────────────────────────────────────

class ThreatIntelWorker(QThread):
    result_ready  = pyqtSignal(dict)
    source_done   = pyqtSignal(str, int)
    finished_all  = pyqtSignal(int)
    progress      = pyqtSignal(int)

    def __init__(self, target, hibp_key="", tor_port=0,
                 do_hibp=True, do_ransomware=True, do_paste=True, do_tor=True):
        super().__init__()
        self.target=target; self.hibp_key=hibp_key; self.tor_port=tor_port
        self.do_hibp=do_hibp; self.do_ransomware=do_ransomware
        self.do_paste=do_paste; self.do_tor=do_tor

    def run(self):
        all_results=[]; steps=sum([self.do_hibp*2,self.do_ransomware,self.do_paste,self.do_tor]); step=0

        def emit(results, source):
            nonlocal step
            for r in results:
                self.result_ready.emit(r); all_results.append(r)
            self.source_done.emit(source, len(results))
            step+=1; self.progress.emit(int(step/max(steps,1)*100))

        target = self.target.strip()
        domain = re.sub(r'^.*@','',target) if '@' in target else re.sub(r'^https?://','',target).split('/')[0]

        if self.do_hibp:
            emit(HIBPBackend.search_domain(domain, self.hibp_key), "HIBP Domain")
            emit(HIBPBackend.search_breaches(target), "HIBP Breach DB")
        if self.do_ransomware:
            emit(RansomwareBackend.search(domain), "Ransomware")
        if self.do_paste:
            emit(PasteBackend.search(domain), "Paste Sites")
        if self.do_tor and self.tor_port:
            tor_results=[]
            # Query mirate per threat intel — riducono falsi positivi
            ti_queries = [
                f'"{domain}" site:pastebin.com',
                f'"{domain}" credentials dump filetype:txt',
                f'"{domain}" data breach leaked',
                f'"{domain}" password database',
                f'"{domain}" ransomware',
            ]
            for q in ti_queries:
                try:
                    results = TorProxyBackend._ddg_onion_search(q, self.tor_port, 30)
                    # Filtra risultati: mantieni solo quelli con keyword TI nel titolo/snippet
                    TI_KEYWORDS = {"leak","breach","dump","credential","password","ransomware",
                                   "hack","stolen","exposed","database","combo","stealer"}
                    filtered = [r for r in results if
                                any(kw in (r.get("title","") + r.get("snippet","")).lower()
                                    for kw in TI_KEYWORDS)]
                    tor_results.extend(filtered)
                except: pass
            seen=set(); deduped=[]
            for r in tor_results:
                k=r.get("url") or r.get("title")
                if k not in seen: seen.add(k); deduped.append(r)
            emit(deduped, "DDG .onion TI")

        self.progress.emit(100); self.finished_all.emit(len(all_results))



# ─── DeepDarkCTI Resources ────────────────────────────────────────────────────
# Fonti da https://github.com/fastfire/deepdarkCTI

DEEPDARK_RANSOMWARE = [
    ("LockBit 3.0",        "lockbit3olp7oetlc4tl5zydnoluphh7fvdt5oa6arcp2757r7xkutid.onion", "ONLINE"),
    ("LockBit 4.0",        "lockbitapyx2kr5b7ma7qn6ziwqgbrij2czhcbojuxmgnwpkgv2yx2yd.onion", "ONLINE"),
    ("BlackBasta",         "stniiomyjliimcgkvdszvgen3eaaoz55hreqqx6o77yvmpwt7gklffqd.onion", "ONLINE"),
    ("Akira",              "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion", "ONLINE"),
    ("Medusa",             "medusaxko7jxtrojdkxo66j7ck4q5tgktf7uqsqyfry4ebnxlcbkccyd.onion", "ONLINE"),
    ("Play",               "k7kg3jqxang3wh7zkvzvmgrqtedvyibkzcncon4t3dszopbpk3gyevyd.onion", "ONLINE"),
    ("Cl0p",               "santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion", "ONLINE"),
    ("RansomHub",          "ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion", "ONLINE"),
    ("Hunters International", "hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion", "ONLINE"),
    ("BianLian",           "bianlianlbc5an4kgnay3opdemgcryg2kpfcbgczopmm3dnbz3uaunad.onion", "ONLINE"),
    ("BlackCat/ALPHV",     "alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion", "ONLINE"),
    ("Rhysida",            "rhysidafohrhyy7bfnirxn56fpfcfchvhfmkzzbpemrewmhcqseyq5ad.onion", "ONLINE"),
    ("8Base",              "xb6q2aggycmlcrjtbjendcnnwpmmwbosqaugxsqb4nx6cmod3emy7sad.onion", "ONLINE"),
    ("Cactus",             "cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid.onion", "ONLINE"),
    ("INC Ransom",         "incblog7vmuq7rktic73r4ha4j757m3ptym37tyvifzp2roedyyzzxid.onion", "ONLINE"),
    ("Fog",                "xbkv2qey6u3gd3qxcojynrt4h5sgrhkar6whuo74wo63hijnn677jnyd.onion", "ONLINE"),
    ("KillSec",            "kill432ltnkqvaqntbalnsgojqqs2wz4lhnamrqjg66tq6fuvcztilyd.onion", "ONLINE"),
    ("BlackSuit",          "weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd.onion", "ONLINE"),
    ("DragonForce",        "z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion", "ONLINE"),
    ("Everest",            "ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion", "ONLINE"),
    ("Babuk",              "nq4zyac4ukl4tykmidbzgdlvaboqeqsemkp4t35bzvjeve6zm2lqcjid.onion", "ONLINE"),
    ("Cuba",               "cuba4ikm4jakjgmkezytyawtdgr2xymvy6nvzgw5cglswg3si76icnqd.onion", "ONLINE"),
    ("Lorenz",             "lorenzmlwpzgxq736jzseuterytjueszsvznuibanxomlpkyxk6ksoyd.onion", "ONLINE"),
    ("Interlock",          "ebhmkoohccl45qesdbvrjqtyro2hmhkmh6vkyfyjjzfllm3ix72aqaid.onion", "ONLINE"),
    ("Lynx",               "lynxblogxstgzsarfyk2pvhdv45igghb4zmthnzmsipzeoduruz3xwqd.onion", "ONLINE"),
    ("Hellcat",            "hellcakbszllztlyqbjzwcbdhfrodx55wq77kmftp4bhnhsnn5r3odad.onion", "ONLINE"),
    ("Brain Cipher",       "brain4zoadgr6clxecixffvxjsw43cflyprnpfeak72nfh664kqqriyd.onion", "ONLINE"),
    ("Cicada3301",         "cicadabv7vicyvgz5khl7v2x5yygcgow7ryy6yppwmxii4eoobdaztqd.onion", "ONLINE"),
    ("3AM",                "threeamkelxicjsaf2czjyz2lc4q3ngqkxhhlexyfcp2o6raw4rphyad.onion", "ONLINE"),
    ("Embargo",            "embargobe3n5okxyzqphpmk3moinoap2snz5k6765mvtkk7hhi544jid.onion", "ONLINE"),
    ("Mad Liberator",      "k67ivvik3dikqi4gy4ua7xa6idijl4si7k5ad5lotbaeirfcsx4sgbid.onion", "ONLINE"),
    ("Ransomfeed",         "ransom.insicurezzadigitale.com", "CLEARNET"),
    ("RansomLook",         "www.ransomlook.io", "CLEARNET"),
    ("Ransomware.live",    "www.ransomware.live", "CLEARNET"),
    ("RansomWatch",        "ransomwatch.telemetry.ltd", "CLEARNET"),
]

DEEPDARK_SEARCH_ENGINES = [
    ("Ahmia",        "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion", "/search/?q={q}"),
    ("Haystak",      "haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion", "/search?q={q}"),
    ("DarkSearch",   "darkschn4iw2hxvpv2vy2uoxwkvs2padb56t3h4wqztre6upoc5qwgid.onion", "/search?q={q}"),
    ("Torch",        "torchqsxkllrj2eqaitp5xvcgfeg3g5dr3hr2wnuvnj76bbxkxfiwxqd.onion", "/search?query={q}&action=search"),
    ("Tordex",       "tordexu73joywapk2txdr54jed4imqledpcvcuf75qsas2gwdgksvnyd.onion", "/?q={q}"),
    ("Deep Search",  "search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion", "/?q={q}"),
    ("GDark",        "zb2jtkhnbvhkya3d46twv3g7lkobi4s62tjffqmafjibixk6pmq75did.onion", "/search?q={q}"),
    ("Tor66",        "tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion", "/search?q={q}"),
    ("FindTor",      "findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion", "/?q={q}"),
    ("OnionLand",    "3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion", "/search?q={q}"),
]


class DeepDarkSearchBackend:
    """
    Ricerca su motori .onion da deepdarkCTI via Tor.
    Prova i motori in sequenza e restituisce i primi risultati.
    """
    NAME = "DeepDark .onion Search"

    @staticmethod
    def search(kw: str, tor_port: int, timeout: int = 35) -> list[dict]:
        if not tor_port:
            return [{"title": "[Tor non disponibile]", "url": "",
                     "snippet": "Attiva Tor Browser per usare i motori .onion da deepdarkCTI.",
                     "source": "DeepDark", "severity": "info"}]
        try:
            import socks as _test_socks; del _test_socks
        except ImportError:
            return [{"title": "[PySocks mancante]", "url": "",
                     "snippet": "pip install PySocks", "source": "DeepDark", "severity": "error"}]

        import socks as _socks, http.client as _http
        q = urllib.parse.quote_plus(kw)
        all_results = []

        for engine_name, host, path_tpl in DEEPDARK_SEARCH_ENGINES:
            path = path_tpl.replace("{q}", q)
            try:
                sock = _socks.create_connection(
                    (host, 80), timeout,
                    proxy_type=_socks.SOCKS5, proxy_addr="127.0.0.1",
                    proxy_port=tor_port, proxy_rdns=True
                )
                conn = _http.HTTPConnection(host, 80, timeout=timeout)
                conn.sock = sock
                conn.request("GET", path, headers={
                    "Host": host,
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                })
                resp = conn.getresponse()
                html = resp.read().decode("utf-8", errors="replace")
                conn.close()

                if resp.status in (301, 302):
                    continue  # skip redirects for now

                # Parser generico per risultati .onion
                clean = lambda s: re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", s)).strip()
                results = []

                # Cerca link .onion con titolo
                anchors = re.findall(
                    r'<a[^>]+href=["\']([^"\']*\.onion[^"\']*)["\'][^>]*>(.*?)</a>',
                    html, re.DOTALL | re.I
                )
                for url, title_raw in anchors[:15]:
                    title = clean(title_raw)
                    if len(title) < 4 or "javascript" in url:
                        continue
                    # Cerca snippet dopo il link
                    results.append({
                        "title": title,
                        "url":   url if url.startswith("http") else f"http://{url}",
                        "snippet": f"Trovato su {engine_name}",
                        "source": f"DeepDark/{engine_name}",
                        "severity": "info"
                    })

                if results:
                    all_results.extend(results)
                    if len(all_results) >= 20:
                        break

            except Exception:
                continue

        # Dedup
        seen = set()
        deduped = []
        for r in all_results:
            k = r.get("url", "") or r.get("title", "")
            if k not in seen:
                seen.add(k)
                deduped.append(r)

        return deduped or [{"title": "Nessun risultato dai motori .onion", "url": "",
                            "snippet": "Tutti i motori .onion hanno fallito o non hanno trovato risultati.",
                            "source": "DeepDark", "severity": "info"}]


class _DeepDarkUpdateWorker(QThread):
    """Scarica ransomware_gang.md e search_engines.md da GitHub e aggiorna le liste."""
    progress    = pyqtSignal(int)
    status_msg  = pyqtSignal(str)
    ransom_updated  = pyqtSignal(list)   # lista di tuple (name, url, status)
    engines_updated = pyqtSignal(list)   # lista di tuple (name, host, path)
    finished    = pyqtSignal(bool, str)  # success, message

    RANSOM_URL  = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md"
    ENGINES_URL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/search_engines.md"

    def run(self):
        try:
            import urllib.request, ssl, re

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            headers = {
                "User-Agent": "OSINTTool/2.0",
                "Accept": "text/plain"
            }

            # ── Scarica ransomware_gang.md ─────────────────────────────────────
            self.status_msg.emit("Scaricando ransomware_gang.md da GitHub...")
            self.progress.emit(10)

            req = urllib.request.Request(self.RANSOM_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                ransom_md = r.read().decode("utf-8", errors="replace")

            self.progress.emit(40)

            # Parse Markdown table: | Name | Status | ...
            # Riga formato: | [Nome](url_o_testo) | ONLINE/OFFLINE | ...
            ransom_list = []
            for line in ransom_md.splitlines():
                line = line.strip()
                if not line.startswith("|") or "---" in line or "Name" in line:
                    continue
                cols = [c.strip() for c in line.split("|") if c.strip()]
                if len(cols) < 2:
                    continue
                name_col   = cols[0]
                status_col = cols[1].strip() if len(cols) > 1 else "?"

                # Estrai nome e URL dal formato [Nome](url) o testo semplice
                m = re.search(r'\[([^\]]+)\]\(([^)]+)\)', name_col)
                if m:
                    name = m.group(1).strip()
                    url  = m.group(2).strip()
                else:
                    name = re.sub(r"<[^>]+>", "", name_col).strip()
                    url  = ""

                # Pulisci URL: rimuovi http:// per .onion, tieni solo host
                onion_m = re.search(r"([a-z2-7]{16,56}\.onion[^\s\"'<>]*)", url, re.I)
                clear_m = re.search(r"https?://([^\s\"'<>]+)", url)
                if onion_m:
                    host = onion_m.group(1).split("/")[0]
                    tipo = "ONLINE" if "ONLINE" in status_col.upper() else ("OFFLINE" if "OFFLINE" in status_col.upper() else status_col[:10])
                elif clear_m:
                    host = clear_m.group(1).split("/")[0]
                    tipo = "CLEARNET"
                elif url and not url.startswith("http"):
                    host = url
                    tipo = "ONLINE" if "ONLINE" in status_col.upper() else "?"
                else:
                    continue

                if name and host and len(host) > 4 and tipo != "OFFLINE" and "REBRAND" not in status_col.upper():
                    ransom_list.append((name, host, tipo))

            # Dedup per host
            seen_hosts = set()
            deduped_ransom = []
            for entry in ransom_list:
                if entry[1] not in seen_hosts:
                    seen_hosts.add(entry[1])
                    deduped_ransom.append(entry)

            self.ransom_updated.emit(deduped_ransom)
            self.status_msg.emit(f"Ransomware: {len(deduped_ransom)} siti caricati. Scaricando search engines...")
            self.progress.emit(60)

            # ── Scarica search_engines.md ──────────────────────────────────────
            req2 = urllib.request.Request(self.ENGINES_URL, headers=headers)
            with urllib.request.urlopen(req2, timeout=20, context=ctx) as r:
                engines_md = r.read().decode("utf-8", errors="replace")

            self.progress.emit(80)

            engines_list = []
            for line in engines_md.splitlines():
                line = line.strip()
                if not line.startswith("|") or "---" in line or "Name" in line:
                    continue
                cols = [c.strip() for c in line.split("|") if c.strip()]
                if len(cols) < 2:
                    continue
                name_col   = cols[0]
                status_col = cols[1].strip() if len(cols) > 1 else "?"

                if "OFFLINE" in status_col.upper():
                    continue  # salta offline

                m = re.search(r'\[([^\]]+)\]\(([^)]+)\)', name_col)
                if m:
                    name = m.group(1).strip()
                    url  = m.group(2).strip()
                else:
                    continue

                # Estrai host e path
                onion_m = re.search(r"([a-z2-7]{16,56}\.onion)(/[^\s\"'<>]*)?", url, re.I)
                if onion_m:
                    host = onion_m.group(1)
                    path = onion_m.group(2) or "/"
                    # Aggiungi parametro ricerca se non presente
                    if "{q}" not in path:
                        path = path.rstrip("/") + "/?q={q}"
                    engines_list.append((name, host, path))

            self.engines_updated.emit(engines_list)
            self.progress.emit(100)
            self.status_msg.emit(f"Aggiornamento completato: {len(deduped_ransom)} ransomware, {len(engines_list)} motori.")
            self.finished.emit(True, f"Aggiornato: {len(deduped_ransom)} ransomware sites, {len(engines_list)} search engines")

        except Exception as e:
            self.progress.emit(0)
            self.finished.emit(False, f"Errore aggiornamento: {type(e).__name__}: {e}")



def apply_theme(app):


    """Worker per scansione threat intel completa su dominio/brand."""
    result_ready   = pyqtSignal(dict)          # singolo risultato
    source_done    = pyqtSignal(str, int)       # source_name, count
    finished_all   = pyqtSignal(int)            # total
    progress       = pyqtSignal(int)

    def __init__(self, target: str, hibp_key: str = "", tor_port: int = 0,
                 do_hibp=True, do_ransomware=True, do_paste=True, do_tor=True):
        super().__init__()
        self.target       = target
        self.hibp_key     = hibp_key
        self.tor_port     = tor_port
        self.do_hibp      = do_hibp
        self.do_ransomware= do_ransomware
        self.do_paste     = do_paste
        self.do_tor       = do_tor

    def run(self):
        all_results = []
        steps = sum([self.do_hibp*2, self.do_ransomware, self.do_paste, self.do_tor])
        step  = 0

        def emit_results(results, source):
            nonlocal step
            for r in results:
                self.result_ready.emit(r)
                all_results.append(r)
            self.source_done.emit(source, len(results))
            step += 1
            self.progress.emit(int(step/steps*100))

        target = self.target.strip()
        # Estrai dominio se input è email o URL
        domain = re.sub(r'^.*@','', target) if '@' in target else re.sub(r'^https?://','',target).split('/')[0]

        if self.do_hibp:
            emit_results(HIBPBackend.search_domain(domain, self.hibp_key), "HIBP Domain")
            emit_results(HIBPBackend.search_breaches(target), "HIBP Breach DB")
        if self.do_ransomware:
            emit_results(RansomwareBackend.search(domain), "Ransomware")
        if self.do_paste:
            emit_results(PasteBackend.search(domain), "Paste Sites")
        if self.do_tor and self.tor_port:
            # Query mirate per TI su DDG .onion
            queries = [
                f'"{domain}" leak',
                f'"{domain}" credentials dump',
                f'"{domain}" breach',
            ]
            tor_results = []
            for q in queries:
                try:
                    r = TorProxyBackend._ddg_onion_search(q, self.tor_port, 30)
                    tor_results.extend(r)
                except Exception:
                    pass
            # Dedup per URL
            seen = set()
            deduped = []
            for r in tor_results:
                key = r.get("url") or r.get("title")
                if key not in seen:
                    seen.add(key); deduped.append(r)
            emit_results(deduped, "DDG .onion TI")

        self.progress.emit(100)
        self.finished_all.emit(len(all_results))


    app.setStyle("Fusion")
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window,          QColor(18,18,24))
    p.setColor(QPalette.ColorRole.WindowText,      QColor(220,220,230))
    p.setColor(QPalette.ColorRole.Base,            QColor(28,28,38))
    p.setColor(QPalette.ColorRole.AlternateBase,   QColor(38,38,52))
    p.setColor(QPalette.ColorRole.Text,            QColor(220,220,230))
    p.setColor(QPalette.ColorRole.Button,          QColor(38,38,52))
    p.setColor(QPalette.ColorRole.ButtonText,      QColor(220,220,230))
    p.setColor(QPalette.ColorRole.Highlight,       QColor(0,180,140))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor(10,10,16))
    app.setPalette(p)
    app.setStyleSheet("""
        QMainWindow{background:#12121A}
        QTabWidget::pane{border:1px solid #2A2A3E;background:#12121A}
        QTabBar::tab{background:#1C1C26;color:#9090AA;padding:8px 20px;border:1px solid #2A2A3E;
            border-bottom:none;font-family:Consolas,monospace;font-size:11px;letter-spacing:1px}
        QTabBar::tab:selected{background:#12121A;color:#00C8A0;border-bottom:2px solid #00C8A0}
        QTabBar::tab:hover{background:#22223A;color:#DCDCE6}
        QGroupBox{font-family:Consolas,monospace;font-size:10px;color:#00C8A0;border:1px solid #2A2A3E;
            border-radius:4px;margin-top:12px;padding-top:8px;letter-spacing:2px}
        QGroupBox::title{subcontrol-origin:margin;left:10px;top:-6px;padding:0 4px}
        QLineEdit{background:#1C1C26;border:1px solid #2A2A3E;color:#DCDCE6;padding:6px 10px;
            border-radius:3px;font-family:Consolas,monospace;font-size:12px}
        QLineEdit:focus{border:1px solid #00C8A0}
        QPushButton{background:#1C1C26;border:1px solid #3A3A52;color:#DCDCE6;padding:7px 18px;
            border-radius:3px;font-family:Consolas,monospace;font-size:11px;letter-spacing:1px}
        QPushButton:hover{background:#26263A;border-color:#00C8A0;color:#00C8A0}
        QPushButton:pressed{background:#00C8A0;color:#0A0A10}
        QPushButton#searchBtn{background:#003D32;border:1px solid #00C8A0;color:#00C8A0;
            font-weight:bold;padding:8px 24px;font-size:12px;letter-spacing:2px}
        QPushButton#searchBtn:hover{background:#00C8A0;color:#0A0A10}
        QPushButton#dangerBtn{border-color:#FF4444;color:#FF4444}
        QPushButton#dangerBtn:hover{background:#FF4444;color:#0A0A10}
        QTableWidget{background:#12121A;alternate-background-color:#1A1A26;gridline-color:#2A2A3E;
            color:#DCDCE6;font-family:Consolas,monospace;font-size:11px;border:1px solid #2A2A3E}
        QTableWidget::item:selected{background:#003D32;color:#00C8A0}
        QHeaderView::section{background:#1C1C26;color:#00C8A0;border:none;
            border-right:1px solid #2A2A3E;border-bottom:1px solid #2A2A3E;
            padding:6px;font-family:Consolas,monospace;font-size:10px;letter-spacing:1px}
        QTextEdit{background:#0E0E18;border:1px solid #2A2A3E;color:#00FF88;
            font-family:Consolas,monospace;font-size:11px;padding:8px}
        QProgressBar{background:#1C1C26;border:1px solid #2A2A3E;text-align:center;color:#00C8A0;height:6px}
        QProgressBar::chunk{background:#00C8A0}
        QComboBox{background:#1C1C26;border:1px solid #2A2A3E;color:#DCDCE6;padding:5px 10px;
            font-family:Consolas,monospace;font-size:11px}
        QComboBox QAbstractItemView{background:#1C1C26;color:#DCDCE6;selection-background-color:#003D32}
        QCheckBox{color:#9090AA;font-family:Consolas,monospace;font-size:11px}
        QCheckBox::indicator:checked{background:#00C8A0;border:1px solid #00C8A0}
        QCheckBox::indicator:unchecked{background:#1C1C26;border:1px solid #3A3A52}
        QScrollBar:vertical{background:#12121A;width:8px}
        QScrollBar::handle:vertical{background:#3A3A52;border-radius:4px;min-height:20px}
        QScrollBar::handle:vertical:hover{background:#00C8A0}
        QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}
        QListWidget{background:#12121A;border:1px solid #2A2A3E;color:#DCDCE6;
            font-family:Consolas,monospace;font-size:11px}
        QStatusBar{background:#0E0E18;color:#5A5A7A;font-family:Consolas,monospace;font-size:10px}
        QLabel#H{color:#00C8A0;font-size:20px;font-family:Consolas,monospace;font-weight:bold;letter-spacing:4px}
        QLabel#S{color:#5A5A7A;font-size:10px;font-family:Consolas,monospace;letter-spacing:2px}
        QSplitter::handle{background:#2A2A3E;width:2px}
        QSpinBox{background:#1C1C26;border:1px solid #2A2A3E;color:#DCDCE6;padding:4px;font-family:Consolas,monospace}
    """)

# ─── Main Window ───────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("OSINTTool","DarkWebOSINT")
        self.current_results = []
        self._current_search_id = None
        self._init_ui()
        self._load_settings()
        self._start_monitor()

    def _now(self): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _init_ui(self):
        self.setWindowTitle("DarkWeb OSINT Intelligence Tool  //  v1.1  —  Developed by Marco Bonometti, CISO")
        self.setMinimumSize(1100,750); self.resize(1280,820)
        cw = QWidget(); self.setCentralWidget(cw)
        root = QVBoxLayout(cw); root.setContentsMargins(16,12,16,8); root.setSpacing(8)

        # Header
        hr = QHBoxLayout()
        lh = QLabel("◈  DARKWEB OSINT TOOL"); lh.setObjectName("H")
        ls = QLabel("THREAT INTELLIGENCE  //  SEARCH ENGINE  //  CLEARNET + TOR + API"); ls.setObjectName("S")
        ls.setAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
        hr.addWidget(lh); hr.addStretch(); hr.addWidget(ls)
        root.addLayout(hr)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine); sep.setStyleSheet("color:#2A2A3E"); root.addWidget(sep)

        # Search box
        sg = QGroupBox("Ricerca"); sl = QVBoxLayout(sg)
        kr = QHBoxLayout()
        self.kw = QLineEdit(); self.kw.setPlaceholderText("Keywords (es: ransomware leak, credential dump, azienda, dominio...)"); self.kw.returnPressed.connect(self._search)
        self.btn_search = QPushButton("⚡  AVVIA RICERCA"); self.btn_search.setObjectName("searchBtn"); self.btn_search.clicked.connect(self._search)
        kr.addWidget(self.kw,1); kr.addWidget(self.btn_search); sl.addLayout(kr)
        br = QHBoxLayout(); br.addWidget(QLabel("Backend attivi:"))
        self.chk_ahmia = QCheckBox("Ahmia.fi (clearnet)"); self.chk_ahmia.setChecked(True)
        self.chk_tor   = QCheckBox("Tor Proxy (locale)");  self.chk_tor.setChecked(True)
        self.chk_api   = QCheckBox("API Commerciale")
        br.addWidget(self.chk_ahmia); br.addWidget(self.chk_tor); br.addWidget(self.chk_api); br.addStretch()
        sl.addLayout(br)
        self.prog = QProgressBar(); self.prog.setValue(0); self.prog.setFixedHeight(5); sl.addWidget(self.prog)
        root.addWidget(sg)

        self.tabs = QTabWidget(); root.addWidget(self.tabs,1)
        # Settings tab PRIMA degli altri — crea self.hibp_key_input e altri widget
        # che vengono referenziati da _load_settings() e da altri tab
        settings_tab = self._tab_settings()
        self.tabs.addTab(self._tab_results(),      "  RISULTATI  ")
        self.tabs.addTab(self._tab_threat_intel(), "  ⚠ THREAT INTEL  ")
        self.tabs.addTab(self._tab_deepdark(),     "  🌐 DEEPDARK CTI  ")
        self.tabs.addTab(self._tab_history(),      "  STORICO  ")
        self.tabs.addTab(self._tab_alerts(),       "  ALERT MONITOR  ")
        self.tabs.addTab(self._tab_log(),          "  LOG  ")
        self.tabs.addTab(settings_tab,             "  IMPOSTAZIONI  ")

        self.statusBar().setStyleSheet("background:#0E0E18;color:#5A5A7A;font-family:Consolas;font-size:10px")
        self.statusBar().showMessage("  Pronto.")

    # ── Tabs ───────────────────────────────────────────────────────────────────
    def _tab_results(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(0,6,0,0)
        tb = QHBoxLayout()
        self.lbl_count = QLabel("0 risultati"); self.lbl_count.setStyleSheet("color:#5A5A7A;font-family:Consolas;font-size:11px")
        tb.addWidget(self.lbl_count); tb.addStretch()
        for lbl,fmt in [("⬇  Export CSV","csv"),("⬇  Export JSON","json")]:
            b = QPushButton(lbl); b.clicked.connect(lambda _,f=fmt: self._export(f)); tb.addWidget(b)
        bc = QPushButton("✕  Pulisci"); bc.clicked.connect(self._clear); tb.addWidget(bc)
        lay.addLayout(tb)
        spl = QSplitter(Qt.Orientation.Vertical)
        self.tbl = QTableWidget(0,4)
        self.tbl.setHorizontalHeaderLabels(["TITOLO","URL","FONTE","SNIPPET"])
        self.tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        self.tbl.setAlternatingRowColors(True); self.tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl.verticalHeader().setVisible(False); self.tbl.cellClicked.connect(self._show_detail)
        spl.addWidget(self.tbl)
        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("// seleziona un risultato per il dettaglio completo")
        self.detail.setMaximumHeight(160); spl.addWidget(self.detail)
        lay.addWidget(spl); return w

    def _tab_deepdark(self):
        """Tab con risorse DeepDarkCTI: directory siti .onion + ricerca multi-motore."""
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(0,6,0,0)

        # Header con pulsante aggiornamento
        hr = QHBoxLayout()
        info = QLabel("Risorse da github.com/fastfire/deepdarkCTI — clicca URL per copiare negli appunti (poi apri in Tor Browser)")
        info.setStyleSheet("color:#5A5A7A;font-family:Consolas;font-size:10px")
        info.setWordWrap(True)
        self.dd_update_btn = QPushButton("↺  Aggiorna da GitHub")
        self.dd_update_btn.setFixedWidth(180)
        self.dd_update_btn.clicked.connect(self._run_deepdark_update)
        self.dd_update_lbl = QLabel("")
        self.dd_update_lbl.setStyleSheet("color:#5A5A7A;font-family:Consolas;font-size:9px")
        hr.addWidget(info, 1)
        hr.addWidget(self.dd_update_lbl)
        hr.addWidget(self.dd_update_btn)
        lay.addLayout(hr)

        # Ricerca multi-motore .onion
        sr = QHBoxLayout()
        sr.addWidget(QLabel("Cerca su motori .onion:"))
        self.dd_search = QLineEdit()
        self.dd_search.setPlaceholderText("keyword da cercare su Torch, Haystak, DarkSearch, Tor66...")
        self.dd_search.returnPressed.connect(self._run_deepdark_search)
        self.dd_btn = QPushButton("🔍  CERCA")
        self.dd_btn.setObjectName("searchBtn")
        self.dd_btn.clicked.connect(self._run_deepdark_search)
        sr.addWidget(self.dd_search, 1)
        sr.addWidget(self.dd_btn)
        lay.addLayout(sr)

        self.dd_prog = QProgressBar(); self.dd_prog.setValue(0); self.dd_prog.setFixedHeight(5)
        lay.addWidget(self.dd_prog)

        # Splitter: directory a sinistra, risultati ricerca a destra
        spl = QSplitter(Qt.Orientation.Horizontal)

        # Directory ransomware sites
        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0,0,4,0)
        ll.addWidget(QLabel("Ransomware Leak Sites (deepdarkCTI):"))
        self.dd_ransom_tbl = QTableWidget(0, 3)
        self.dd_ransom_tbl.setHorizontalHeaderLabels(["GRUPPO", "URL", "TIPO"])
        self.dd_ransom_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.dd_ransom_tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.dd_ransom_tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.dd_ransom_tbl.setAlternatingRowColors(True)
        self.dd_ransom_tbl.verticalHeader().setVisible(False)
        self.dd_ransom_tbl.cellClicked.connect(self._dd_ransom_click)
        for name, url, status in DEEPDARK_RANSOMWARE:
            row = self.dd_ransom_tbl.rowCount()
            self.dd_ransom_tbl.insertRow(row)
            for col, val in enumerate([name, url, status]):
                item = QTableWidgetItem(val)
                item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
                if col == 1 and ".onion" in val:
                    item.setForeground(QColor(0, 200, 160))
                if col == 2 and val == "ONLINE":
                    item.setForeground(QColor(0, 200, 140))
                elif col == 2 and val == "CLEARNET":
                    item.setForeground(QColor(100, 180, 255))
                self.dd_ransom_tbl.setItem(row, col, item)
        ll.addWidget(self.dd_ransom_tbl)
        spl.addWidget(left)

        # Risultati ricerca multi-motore
        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(4,0,0,0)
        rl.addWidget(QLabel("Risultati ricerca multi-motore .onion:"))
        self.dd_results_tbl = QTableWidget(0, 3)
        self.dd_results_tbl.setHorizontalHeaderLabels(["TITOLO", "URL", "MOTORE"])
        self.dd_results_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.dd_results_tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.dd_results_tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.dd_results_tbl.setAlternatingRowColors(True)
        self.dd_results_tbl.verticalHeader().setVisible(False)
        self.dd_results_tbl.cellClicked.connect(self._dd_result_click)
        rl.addWidget(self.dd_results_tbl)
        spl.addWidget(right)

        spl.setSizes([500, 700])
        lay.addWidget(spl, 1)

        self.dd_status = QLabel("Tor richiesto per la ricerca multi-motore.")
        self.dd_status.setStyleSheet("color:#5A5A7A;font-family:Consolas;font-size:10px;padding:2px")
        lay.addWidget(self.dd_status)
        return w

    def _run_deepdark_update(self):
        """Scarica aggiornamenti da GitHub e aggiorna le tabelle DeepDark."""
        try:
            self.dd_update_btn.setEnabled(False)
            self.dd_update_lbl.setText("Scaricando...")
            self.dd_prog.setValue(0)

            self._dd_update_worker = _DeepDarkUpdateWorker()
            self._dd_update_worker.progress.connect(self.dd_prog.setValue)
            self._dd_update_worker.status_msg.connect(lambda m: self.dd_update_lbl.setText(m[:60]))
            self._dd_update_worker.ransom_updated.connect(self._dd_refresh_ransom_table)
            self._dd_update_worker.engines_updated.connect(self._dd_refresh_engines)
            self._dd_update_worker.finished.connect(self._dd_update_done)
            self._dd_update_worker.start()
        except Exception as e:
            self.dd_update_btn.setEnabled(True)
            self._log(f"[ERRORE aggiornamento] {e}")

    def _dd_refresh_ransom_table(self, ransom_list: list):
        """Aggiorna tabella ransomware con dati freschi da GitHub."""
        try:
            self.dd_ransom_tbl.setRowCount(0)
            for name, url, status in ransom_list:
                row = self.dd_ransom_tbl.rowCount()
                self.dd_ransom_tbl.insertRow(row)
                for col, val in enumerate([name, url, status]):
                    item = QTableWidgetItem(val)
                    item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
                    if col == 1 and ".onion" in val:
                        item.setForeground(QColor(0, 200, 160))
                    if col == 2 and val == "ONLINE":
                        item.setForeground(QColor(0, 200, 140))
                    elif col == 2 and val == "CLEARNET":
                        item.setForeground(QColor(100, 180, 255))
                    elif col == 2 and val == "OFFLINE":
                        item.setForeground(QColor(100, 100, 100))
                    self.dd_ransom_tbl.setItem(row, col, item)
            self._log(f"[{self._now()}] DeepDark: tabella ransomware aggiornata ({len(ransom_list)} siti)")
        except Exception as e:
            self._log(f"[ERRORE refresh ransom] {e}")

    def _dd_refresh_engines(self, engines_list: list):
        """Aggiorna lista motori di ricerca .onion."""
        try:
            # Aggiorna la lista globale DEEPDARK_SEARCH_ENGINES per ricerche future
            global DEEPDARK_SEARCH_ENGINES
            if engines_list:
                DEEPDARK_SEARCH_ENGINES = engines_list
            self._log(f"[{self._now()}] DeepDark: {len(engines_list)} motori .onion aggiornati")
        except Exception as e:
            self._log(f"[ERRORE refresh engines] {e}")

    def _dd_update_done(self, success: bool, msg: str):
        """Callback fine aggiornamento."""
        try:
            self.dd_update_btn.setEnabled(True)
            ts = self._now()
            if success:
                self.dd_update_lbl.setText(f"Aggiornato: {ts[:16]}")
                self.dd_status.setText(msg)
                self._log(f"[{ts}] {msg}")
            else:
                self.dd_update_lbl.setText("Errore aggiornamento")
                self.dd_status.setText(msg)
                self._log(f"[ERRORE] {msg}")
        except Exception as e:
            self._log(f"[ERRORE callback] {e}")

    def _dd_ransom_click(self, row, col):
        """Click su URL ransomware: copia negli appunti."""
        try:
            url_item = self.dd_ransom_tbl.item(row, 1)
            tipo_item = self.dd_ransom_tbl.item(row, 2)
            if not url_item: return
            url = url_item.text()
            tipo = tipo_item.text() if tipo_item else ""
            if ".onion" in url:
                full_url = f"http://{url}" if not url.startswith("http") else url
                QApplication.clipboard().setText(full_url)
                self.dd_status.setText(f"🧅 Copiato: {full_url} — incolla in Tor Browser (Cmd+V)")
                self._log(f"🧅 DeepDark copiato: {full_url}")
            elif tipo == "CLEARNET":
                full_url = f"https://{url}" if not url.startswith("http") else url
                import subprocess
                subprocess.Popen(["open", full_url])
                self._log(f"🔗 Aperto clearnet: {full_url}")
        except Exception as e:
            self._log(f"[ERRORE click deepdark] {e}")

    def _dd_result_click(self, row, col):
        """Click su URL risultato ricerca."""
        try:
            url_item = self.dd_results_tbl.item(row, 1)
            if not url_item: return
            url = url_item.text()
            if url:
                self._open_url(url)
        except Exception as e:
            self._log(f"[ERRORE click deepdark result] {e}")

    def _run_deepdark_search(self):
        """Ricerca multi-motore .onion via DeepDarkSearchBackend."""
        try:
            kw = self.dd_search.text().strip()
            if not kw: return
            tor_port = TorProxyBackend._tor_port()
            if not tor_port:
                self.dd_status.setText("Tor non disponibile — avvia Tor Browser prima di cercare.")
                return
            self.dd_btn.setEnabled(False)
            self.dd_prog.setValue(0)
            self.dd_results_tbl.setRowCount(0)
            self.dd_status.setText(f"Ricerca in corso su motori .onion: {kw}...")
            self._log(f"[{self._now()}] DeepDark search: {kw}")

            self._dd_worker = _DeepDarkWorker(kw, tor_port)
            self._dd_worker.result_ready.connect(self._dd_add_result)
            self._dd_worker.progress.connect(self.dd_prog.setValue)
            self._dd_worker.finished.connect(lambda n: (
                self.dd_btn.setEnabled(True),
                self.dd_status.setText(f"Completato: {n} risultati trovati."),
                self._log(f"DeepDark completato: {n} risultati")
            ))
            self._dd_worker.start()
        except Exception as e:
            self.dd_btn.setEnabled(True)
            self._log(f"[ERRORE DeepDark] {e}")

    def _dd_add_result(self, r: dict):
        row = self.dd_results_tbl.rowCount()
        self.dd_results_tbl.insertRow(row)
        for col, val in enumerate([r.get("title",""), r.get("url",""), r.get("source","")]):
            item = QTableWidgetItem(val)
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            if col == 1 and ".onion" in val:
                item.setForeground(QColor(0, 200, 160))
            self.dd_results_tbl.setItem(row, col, item)

    def _tab_history(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(0,6,0,0)
        tb = QHBoxLayout()
        br = QPushButton("↺  Aggiorna"); br.clicked.connect(self._load_history); tb.addWidget(br); tb.addStretch()
        bc = QPushButton("✕  Cancella storico"); bc.setObjectName("dangerBtn"); bc.clicked.connect(self._clear_history); tb.addWidget(bc)
        lay.addLayout(tb)
        self.htbl = QTableWidget(0,5)
        self.htbl.setHorizontalHeaderLabels(["DATA/ORA","KEYWORDS","BACKEND","RISULTATI","ID"])
        self.htbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self.htbl.setAlternatingRowColors(True); self.htbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.htbl.verticalHeader().setVisible(False); self.htbl.itemDoubleClicked.connect(self._history_reload)
        lay.addWidget(self.htbl); self._load_history(); return w

    def _tab_alerts(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(0,6,0,0)
        inf = QLabel("Monitora keyword in background tramite Ahmia.fi. Intervallo configurabile.")
        inf.setStyleSheet("color:#5A5A7A;font-family:Consolas;font-size:10px;padding:4px"); lay.addWidget(inf)
        ar = QHBoxLayout()
        self.alert_in = QLineEdit(); self.alert_in.setPlaceholderText("Keyword da monitorare..."); self.alert_in.returnPressed.connect(self._add_alert)
        ba = QPushButton("+ Aggiungi Alert"); ba.clicked.connect(self._add_alert)
        ar.addWidget(self.alert_in,1); ar.addWidget(ba); lay.addLayout(ar)
        ir = QHBoxLayout(); ir.addWidget(QLabel("Intervallo (minuti):"))
        self.alert_int = QSpinBox(); self.alert_int.setRange(5,1440); self.alert_int.setValue(30)
        self.alert_int.valueChanged.connect(self._start_monitor)
        ir.addWidget(self.alert_int); ir.addStretch(); lay.addLayout(ir)
        self.atbl = QTableWidget(0,5)
        self.atbl.setHorizontalHeaderLabels(["KEYWORD","ATTIVO","CREATO","ULTIMO TRIGGER","CONTEGGIO"])
        self.atbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        self.atbl.setAlternatingRowColors(True); self.atbl.verticalHeader().setVisible(False)
        lay.addWidget(self.atbl)
        bd = QPushButton("✕  Rimuovi selezionato"); bd.setObjectName("dangerBtn"); bd.clicked.connect(self._del_alert)
        lay.addWidget(bd); self._load_alerts(); return w

    def _tab_log(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(0,6,0,0)
        tb = QHBoxLayout(); bc = QPushButton("✕  Pulisci"); bc.clicked.connect(lambda: self.log.clear())
        tb.addStretch(); tb.addWidget(bc); lay.addLayout(tb)
        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setFont(QFont("Consolas",10))
        lay.addWidget(self.log); return w

    def _tab_threat_intel(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(0,6,0,0)

        # Target input
        tr = QHBoxLayout()
        tr.addWidget(QLabel("Target (dominio / brand / email):"))
        self.ti_target = QLineEdit(); self.ti_target.setPlaceholderText("es: acme.com  oppure  keyword  oppure  info@example.com")
        self.ti_target.returnPressed.connect(self._run_ti)
        self.ti_btn = QPushButton("🔍  SCAN THREAT INTEL"); self.ti_btn.setObjectName("searchBtn")
        self.ti_btn.clicked.connect(self._run_ti)
        tr.addWidget(self.ti_target, 1); tr.addWidget(self.ti_btn); lay.addLayout(tr)

        # Query preset
        qr = QHBoxLayout()
        qr.addWidget(QLabel("Query preset:"))
        self._ti_presets = {
            "Credential leak":   '"{domain}" credentials leaked password',
            "Data breach":       '"{domain}" data breach database dump',
            "Ransomware":        '"{domain}" ransomware attack',
            "Brand abuse":       '"{domain}" phishing spoofing fake site',
            "Paste sites":       'site:pastebin.com "{domain}" password',
            "Dark web mention":  '"{domain}" darkweb forum underground',
        }
        for label, query_tpl in self._ti_presets.items():
            btn = QPushButton(label)
            btn.setStyleSheet("font-size:9px; padding:3px 8px; letter-spacing:0")
            btn.clicked.connect(lambda _, q=query_tpl: self._ti_apply_preset(q))
            qr.addWidget(btn)
        qr.addStretch()
        lay.addLayout(qr)

        # Checkboxes fonti
        sr = QHBoxLayout(); sr.addWidget(QLabel("Fonti:"))
        self.ti_hibp  = QCheckBox("HIBP (breach)");     self.ti_hibp.setChecked(True)
        self.ti_ransom= QCheckBox("Ransomware sites");   self.ti_ransom.setChecked(True)
        self.ti_paste = QCheckBox("Paste sites");        self.ti_paste.setChecked(True)
        self.ti_tor   = QCheckBox("DDG .onion");         self.ti_tor.setChecked(True)
        for c in [self.ti_hibp, self.ti_ransom, self.ti_paste, self.ti_tor]: sr.addWidget(c)
        sr.addStretch(); lay.addLayout(sr)

        self.ti_prog = QProgressBar(); self.ti_prog.setValue(0); self.ti_prog.setFixedHeight(5)
        lay.addWidget(self.ti_prog)

        # Tabella risultati TI
        self.ti_tbl = QTableWidget(0, 5)
        self.ti_tbl.setHorizontalHeaderLabels(["SEVERITY","TITOLO","URL","FONTE","SNIPPET"])
        self.ti_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.ti_tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.ti_tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.ti_tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.ti_tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.ti_tbl.setAlternatingRowColors(True)
        self.ti_tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ti_tbl.verticalHeader().setVisible(False)
        self.ti_tbl.cellClicked.connect(self._ti_cell_clicked)
        lay.addWidget(self.ti_tbl, 1)

        # Dettaglio
        self.ti_detail = QTextEdit(); self.ti_detail.setReadOnly(True)
        self.ti_detail.setMaximumHeight(120)
        self.ti_detail.setPlaceholderText("// seleziona un risultato per il dettaglio")
        lay.addWidget(self.ti_detail)

        tb = QHBoxLayout()
        self.ti_lbl = QLabel("—"); self.ti_lbl.setStyleSheet("color:#5A5A7A;font-family:Consolas;font-size:11px")
        btn_exp = QPushButton("⬇  Export JSON"); btn_exp.clicked.connect(self._ti_export)
        tb.addWidget(self.ti_lbl); tb.addStretch(); tb.addWidget(btn_exp)
        lay.addLayout(tb)

        self._ti_results = []
        return w

    def _ti_apply_preset(self, query_tpl: str):
        """Applica un preset di query sostituendo {domain} con il target inserito."""
        target = self.ti_target.text().strip()
        if not target:
            self.statusBar().showMessage("  Inserisci prima un dominio o brand nel campo Target.")
            return
        domain = re.sub(r'^.*@', '', target) if '@' in target else re.sub(r'^https?://', '', target).split('/')[0]
        query = query_tpl.replace("{domain}", domain)
        # Lancia ricerca DDG con la query preset nella tab Risultati
        self.kw.setText(query)
        self.chk_ahmia.setChecked(False)
        self.chk_tor.setChecked(True)
        self.chk_api.setChecked(False)
        self.tabs.setCurrentIndex(0)  # vai a tab Risultati
        self._search()

    def _run_ti(self):
        try:
            target = self.ti_target.text().strip()
            if not target: return
            self.ti_btn.setEnabled(False)
            self.ti_prog.setValue(0)
            self.ti_tbl.setRowCount(0)
            self.ti_detail.clear()
            self._ti_results = []
            tor_port = TorProxyBackend._tor_port() if self.ti_tor.isChecked() else 0
            self._log(f"[{self._now()}] THREAT INTEL: '{target}'")
            self.ti_lbl.setText("Scansione in corso...")

            self._ti_worker = ThreatIntelWorker(
                target,
                hibp_key     = self.hibp_key_input.text().strip(),
                tor_port     = tor_port,
                do_hibp      = self.ti_hibp.isChecked(),
                do_ransomware= self.ti_ransom.isChecked(),
                do_paste     = self.ti_paste.isChecked(),
                do_tor       = self.ti_tor.isChecked(),
            )
            self._ti_worker.result_ready.connect(self._ti_add_row)
            self._ti_worker.source_done.connect(lambda src, n: self._log(f"  ↳ {src}: {n} risultati"))
            self._ti_worker.progress.connect(self.ti_prog.setValue)
            self._ti_worker.finished_all.connect(self._ti_done)
            self._ti_worker.start()
        except Exception as e:
            self.ti_btn.setEnabled(True)
            self._log(f"[ERRORE TI] {type(e).__name__}: {e}")
            self.ti_lbl.setText(f"Errore: {e}")

    def _ti_add_row(self, r: dict):
        self._ti_results.append(r)
        row = self.ti_tbl.rowCount(); self.ti_tbl.insertRow(row)
        sev = r.get("severity","info")
        sev_colors = {"critical":"#FF4444","high":"#FF8800","medium":"#FFCC00","ok":"#00C8A0","info":"#9090AA","error":"#FF4444"}
        col = sev_colors.get(sev,"#9090AA")
        url_val = r.get("url","") or ""
        for c, val in enumerate([sev.upper(), r["title"], url_val, r["source"], r.get("snippet","")]):
            item = QTableWidgetItem(val)
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            if c == 0: item.setForeground(QColor(col))
            if c == 1 and sev == "critical": item.setForeground(QColor("#FF4444"))
            if c == 2:
                if ".onion" in val:
                    item.setForeground(QColor(0, 200, 160))  # verde per .onion
                elif val.startswith("http"):
                    item.setForeground(QColor(100, 180, 255))  # blu per clearweb
            self.ti_tbl.setItem(row, c, item)

    def _ti_cell_clicked(self, row, col):
        """Gestisce click sulla tabella TI — colonna URL apre Tor Browser."""
        try:
            if row >= len(self._ti_results):
                return
            r = self._ti_results[row]
            url = r.get("url", "") or ""

            # Colonna 2 = URL → apri con Tor Browser o browser di sistema
            if col == 2 and url:
                self._open_url(url)
                return

            # Qualsiasi altra colonna → mostra dettaglio
            self._ti_show_detail(row)
        except Exception as e:
            self._log(f"[ERRORE click] {e}")

    def _open_url(self, url: str):
        """
        - .onion → copia negli appunti + apre Tor Browser (incolla nella barra)
        - clearweb → apre nel browser di sistema
        """
        try:
            import subprocess
            if ".onion" in url:
                # Copia URL negli appunti
                QApplication.clipboard().setText(url)
                # Apri Tor Browser (senza URL — l'utente incolla)
                subprocess.Popen(["open", "-a", "Tor Browser"])
                self._log(f"🧅 URL copiato negli appunti: {url}")
                self.statusBar().showMessage(f"  🧅 URL .onion copiato — incolla in Tor Browser (⌘V)")
                QMessageBox.information(self, "URL .onion copiato",
                    "Indirizzo copiato negli appunti:\n\n" + url +
                    "\n\nIncollalo nella barra di Tor Browser (Cmd+V)")
            else:
                import urllib.parse as _up
                parsed = _up.urlparse(url)
                if parsed.scheme in ("http", "https"):
                    subprocess.Popen(["open", url])
                    self._log(f"🔗 Aperto: {url}")
        except Exception as e:
            self._log(f"[ERRORE apertura URL] {e}")

    def _ti_show_detail(self, row):
        try:
            if row >= len(self._ti_results):
                return
            r = self._ti_results[row]
            sev_colors = {"critical":"#FF4444","high":"#FF8800","medium":"#FFCC00","ok":"#00C8A0","info":"#9090AA","error":"#FF4444"}
            col = sev_colors.get(r.get("severity","info"), "#9090AA")
            url = r.get("url","") or ""

            if ".onion" in url:
                url_display = f"🧅 {url}  <i style='color:#5A5A7A;font-size:9px'>(clicca colonna URL per aprire in Tor Browser)</i>"
                url_color = "#00C8A0"
            elif url.startswith("http"):
                url_display = url + "  <i style='color:#5A5A7A;font-size:9px'>(clicca colonna URL per aprire)</i>"
                url_color = "#00FF88"
            else:
                url_display = url or "—"
                url_color = "#5A5A7A"

            # Escape HTML nel titolo e snippet per sicurezza
            def esc(s):
                return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

            self.ti_detail.setHtml(
                f"<span style='color:{col};font-family:Consolas;font-weight:bold'>"
                f"[{esc(r.get('severity','info')).upper()}]</span>&nbsp;"
                f"<span style='color:#DCDCE6;font-family:Consolas'>{esc(r.get('title',''))}</span><br><br>"
                f"<span style='color:#00C8A0;font-family:Consolas'>URL: </span>"
                f"<span style='color:{url_color};font-family:Consolas;font-size:10px'>{url_display}</span><br><br>"
                f"<span style='color:#00C8A0;font-family:Consolas'>FONTE: </span>"
                f"<span style='color:#9090AA;font-family:Consolas'>{esc(r.get('source',''))}</span><br><br>"
                f"<span style='color:#AAAACC;font-family:Consolas;font-size:10px'>{esc(r.get('snippet',''))}</span>"
            )
        except Exception as e:
            self._log(f"[ERRORE dettaglio] {e}")

    def _ti_done(self, total: int):
        self.ti_btn.setEnabled(True)
        critical = sum(1 for r in self._ti_results if r.get("severity") == "critical")
        high     = sum(1 for r in self._ti_results if r.get("severity") == "high")
        self.ti_lbl.setText(f"{total} risultati — 🔴 {critical} critical  🟠 {high} high")
        self._log(f"[{self._now()}] Threat Intel completato: {total} risultati, {critical} critical")

    def _ti_export(self):
        if not self._ti_results: return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(self, "Salva Threat Intel",
            str(Path.home()/"Downloads"/f"threat_intel_{ts}.json"), "*.json")
        if path:
            with open(path,"w",encoding="utf-8") as f:
                json.dump(self._ti_results, f, ensure_ascii=False, indent=2)
            self._log(f"Export TI → {path}")

    def _tab_settings(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(8,8,8,8)
        hg = QGroupBox("Have I Been Pwned API")
        hf = QFormLayout(hg)
        self.hibp_key_input = QLineEdit(); self.hibp_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.hibp_key_input.setPlaceholderText("API key da haveibeenpwned.com (€3.50/mese)")
        hf.addRow("HIBP API Key:", self.hibp_key_input); lay.addWidget(hg)
        ag = QGroupBox("API Commerciale (DarkOwl / Flashpoint / Intel 471 / custom)")
        af = QFormLayout(ag)
        self.api_key = QLineEdit(); self.api_key.setEchoMode(QLineEdit.EchoMode.Password); self.api_key.setPlaceholderText("Bearer token o API key")
        self.api_ep  = QLineEdit(); self.api_ep.setPlaceholderText("https://api.example.com/v1")
        af.addRow("API Key:",  self.api_key); af.addRow("Endpoint:", self.api_ep); lay.addWidget(ag)
        tg = QGroupBox("Proxy Tor"); tf = QFormLayout(tg)
        self.tor_host = QLineEdit("127.0.0.1"); self.tor_port_s = QLineEdit("9150")
        tf.addRow("Host:", self.tor_host); tf.addRow("Porta:", self.tor_port_s); lay.addWidget(tg)
        eg = QGroupBox("Export"); ef = QFormLayout(eg)
        self.exp_path = QLineEdit(); self.exp_path.setPlaceholderText(str(Path.home()/"Downloads"))
        bb = QPushButton("Sfoglia..."); bb.clicked.connect(self._browse)
        er = QHBoxLayout(); er.addWidget(self.exp_path); er.addWidget(bb)
        ef.addRow("Cartella:", er); lay.addWidget(eg)
        bs = QPushButton("💾  Salva impostazioni"); bs.clicked.connect(self._save_settings)
        lay.addWidget(bs); lay.addStretch(); return w

    # ── Search ─────────────────────────────────────────────────────────────────
    def _search(self):
        kw = self.kw.text().strip()
        if not kw: return
        backends = ([b.text().split(" (")[0] for b, c in [(self.chk_ahmia,"Ahmia.fi"),(self.chk_tor,"Tor Proxy (locale)"),(self.chk_api,"API Commerciale")]
                     if b.isChecked()])
        backends = []
        if self.chk_ahmia.isChecked(): backends.append("Ahmia.fi")
        if self.chk_tor.isChecked():   backends.append("Tor Proxy (locale)")
        if self.chk_api.isChecked():   backends.append("API Commerciale")
        if not backends: self._log("⚠ Nessun backend selezionato."); return
        self.btn_search.setEnabled(False); self.prog.setValue(0)
        self.current_results = []; self._clear()
        self._log(f"[{self._now()}] RICERCA: '{kw}' | {', '.join(backends)}")
        self.statusBar().showMessage(f"  Ricerca: {kw}  →  {', '.join(backends)}")
        with get_db() as c:
            cur = c.execute("INSERT INTO searches(timestamp,keywords,backend,result_count) VALUES(?,?,?,0)",
                            (self._now(), kw, ", ".join(backends)))
            self._current_search_id = cur.lastrowid
        self.worker = SearchWorker(kw, backends, self.api_key.text(), self.api_ep.text())
        self.worker.results_ready.connect(self._on_results)
        self.worker.error.connect(lambda e: self._log(f"[ERR] {e}"))
        self.worker.progress.connect(self.prog.setValue)
        self.worker.finished.connect(self._on_done)
        self.worker.start()

    def _on_results(self, results, backend):
        self._log(f"  ↳ {backend}: {len(results)} risultati")
        with get_db() as c:
            for r in results:
                c.execute("INSERT INTO results(search_id,title,url,snippet,source,found_at) VALUES(?,?,?,?,?,?)",
                          (self._current_search_id, r["title"],r["url"],r["snippet"],r["source"],self._now()))
            c.execute("UPDATE searches SET result_count=result_count+? WHERE id=?",
                      (len(results), self._current_search_id))
        self.current_results.extend(results)
        for r in results: self._add_row(r)
        self._check_alert_match(results)
        self.lbl_count.setText(f"{len(self.current_results)} risultati")

    def _on_done(self):
        self.btn_search.setEnabled(True)
        self.statusBar().showMessage(f"  Completato — {len(self.current_results)} risultati.")
        self._load_history()

    def _add_row(self, r):
        row = self.tbl.rowCount(); self.tbl.insertRow(row)
        for col, val in enumerate([r["title"],r["url"],r["source"],r["snippet"]]):
            item = QTableWidgetItem(val)
            item.setFlags(Qt.ItemFlag.ItemIsSelectable|Qt.ItemFlag.ItemIsEnabled)
            if col==1 and ".onion" in val: item.setForeground(QColor(0,200,160))
            self.tbl.setItem(row,col,item)

    def _show_detail(self, row, col):
        try:
            if row >= len(self.current_results):
                return
            r = self.current_results[row]
            url = r.get("url","") or ""
            # Colonna 1 = URL → apri
            if col == 1 and url:
                self._open_url(url)
                return
            def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            self.detail.setHtml(
                f"<span style='color:#00C8A0;font-family:Consolas'>TITOLO:</span> "
                f"<span style='color:#DCDCE6;font-family:Consolas'>{esc(r.get('title',''))}</span><br>"
                f"<span style='color:#00C8A0;font-family:Consolas'>URL:</span> "
                f"<span style='color:#00FF88;font-family:Consolas'>{esc(url) or '—'}"
                f"{'  <i style=color:#5A5A7A;font-size:9px>(clicca colonna URL)</i>' if url else ''}</span><br>"
                f"<span style='color:#00C8A0;font-family:Consolas'>FONTE:</span> "
                f"<span style='color:#DCDCE6;font-family:Consolas'>{esc(r.get('source',''))}</span><br>"
                f"<span style='color:#00C8A0;font-family:Consolas'>SNIPPET:</span><br>"
                f"<span style='color:#AAAACC;font-family:Consolas;font-size:10px'>{esc(r.get('snippet','') or '—')}</span>")
        except Exception as e:
            self._log(f"[ERRORE dettaglio] {e}")

    def _clear(self):
        self.tbl.setRowCount(0); self.detail.clear(); self.lbl_count.setText("0 risultati")

    # ── Export ─────────────────────────────────────────────────────────────────
    def _export(self, fmt):
        if not self.current_results: return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default = str(Path(self.exp_path.text() or str(Path.home()/"Downloads")) / f"osint_{ts}.{fmt}")
        path, _ = QFileDialog.getSaveFileName(self,"Salva",default,f"*.{fmt}")
        if not path: return
        if fmt=="csv":
            with open(path,"w",newline="",encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=["title","url","source","snippet"]).writeheader()
                csv.DictWriter(f, fieldnames=["title","url","source","snippet"]).writerows(self.current_results)
        else:
            with open(path,"w",encoding="utf-8") as f: json.dump(self.current_results,f,ensure_ascii=False,indent=2)
        self._log(f"[{self._now()}] Export {fmt.upper()} → {path}")

    # ── History ────────────────────────────────────────────────────────────────
    def _load_history(self):
        self.htbl.setRowCount(0)
        with get_db() as c:
            for r in c.execute("SELECT * FROM searches ORDER BY id DESC LIMIT 200").fetchall():
                row = self.htbl.rowCount(); self.htbl.insertRow(row)
                for col,val in enumerate([r["timestamp"],r["keywords"],r["backend"],str(r["result_count"]),str(r["id"])]):
                    item = QTableWidgetItem(val); item.setFlags(Qt.ItemFlag.ItemIsSelectable|Qt.ItemFlag.ItemIsEnabled)
                    self.htbl.setItem(row,col,item)

    def _clear_history(self):
        if QMessageBox.question(self,"Conferma","Cancellare tutto lo storico?",
           QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            with get_db() as c: c.execute("DELETE FROM results"); c.execute("DELETE FROM searches")
            self._load_history()

    def _history_reload(self, item):
        kw = self.htbl.item(item.row(),1)
        if kw: self.kw.setText(kw.text()); self.tabs.setCurrentIndex(0)

    # ── Alerts ─────────────────────────────────────────────────────────────────
    def _add_alert(self):
        kw = self.alert_in.text().strip()
        if not kw: return
        with get_db() as c: c.execute("INSERT OR IGNORE INTO alerts(keyword,created_at) VALUES(?,?)",(kw,self._now()))
        self.alert_in.clear(); self._load_alerts(); self._log(f"Alert aggiunto: '{kw}'")

    def _del_alert(self):
        row = self.atbl.currentRow()
        if row < 0: return
        kw = self.atbl.item(row,0)
        if kw:
            with get_db() as c: c.execute("DELETE FROM alerts WHERE keyword=?",(kw.text(),))
            self._load_alerts()

    def _load_alerts(self):
        self.atbl.setRowCount(0)
        with get_db() as c:
            for r in c.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall():
                row = self.atbl.rowCount(); self.atbl.insertRow(row)
                for col,val in enumerate([r["keyword"],"✓ Attivo" if r["active"] else "✗",r["created_at"] or "—",r["last_triggered"] or "Mai",str(r["trigger_count"])]):
                    item = QTableWidgetItem(val); item.setFlags(Qt.ItemFlag.ItemIsSelectable|Qt.ItemFlag.ItemIsEnabled)
                    if col==1 and r["active"]: item.setForeground(QColor(0,200,160))
                    self.atbl.setItem(row,col,item)

    def _check_alert_match(self, results):
        with get_db() as c:
            kws = [a["keyword"].lower() for a in c.execute("SELECT keyword FROM alerts WHERE active=1").fetchall()]
        for r in results:
            txt = (r["title"]+r["snippet"]).lower()
            for kw in kws:
                if kw in txt: self._log(f"🚨 ALERT MATCH: '{kw}' → {r['title'][:60]}")

    def _start_monitor(self):
        if hasattr(self,"_monitor") and self._monitor: self._monitor.stop()
        self._monitor = AlertMonitor(self.alert_int.value() if hasattr(self,"alert_int") else 30)
        self._monitor.alert_triggered.connect(lambda kw,rs: (self._log(f"🚨 ALERT: '{kw}' — {len(rs)} hit"), self._load_alerts()))
        self._monitor.start()

    # ── Settings ───────────────────────────────────────────────────────────────
    def _save_settings(self):
        for k,w in [("api_key",self.api_key),("api_ep",self.api_ep),("tor_host",self.tor_host),
                    ("tor_port",self.tor_port_s),("exp_path",self.exp_path),("hibp_key",self.hibp_key_input)]:
            self.settings.setValue(k,w.text())
        self.statusBar().showMessage("  Impostazioni salvate.")

    def _load_settings(self):
        for k,w in [("api_key",self.api_key),("api_ep",self.api_ep),("tor_host",self.tor_host),
                    ("tor_port",self.tor_port_s),("exp_path",self.exp_path),("hibp_key",self.hibp_key_input)]:
            w.setText(self.settings.value(k,""))

    def _browse(self):
        p = QFileDialog.getExistingDirectory(self,"Seleziona cartella")
        if p: self.exp_path.setText(p)

    # ── Log ────────────────────────────────────────────────────────────────────
    def _log(self, msg):
        self.log.append(f"<span style='color:#5A5A7A'>[SYS]</span> <span style='color:#00FF88'>{msg}</span>")
        c = self.log.textCursor(); c.movePosition(QTextCursor.MoveOperation.End); self.log.setTextCursor(c)

    def closeEvent(self, e):
        if hasattr(self,"_monitor") and self._monitor: self._monitor.stop()
        e.accept()

# ─── Entry point ───────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("DarkWeb OSINT Tool")
    apply_theme(app)
    w = MainWindow(); w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

class _DeepDarkWorker(QThread):
    result_ready = pyqtSignal(dict)
    progress     = pyqtSignal(int)
    finished     = pyqtSignal(int)

    def __init__(self, kw: str, tor_port: int):
        super().__init__()
        self.kw = kw
        self.tor_port = tor_port

    def run(self):
        results = DeepDarkSearchBackend.search(self.kw, self.tor_port)
        total = len(results)
        for i, r in enumerate(results):
            self.result_ready.emit(r)
            self.progress.emit(int((i+1)/max(total,1)*100))
        self.progress.emit(100)
        self.finished.emit(total)
