#!/usr/bin/env python3
"""
Script di debug: scarica l'HTML di Ahmia e lo salva su file.
Esegui nel venv: python3 debug_ahmia.py facebook
"""
import sys, urllib.request, urllib.parse, ssl
from pathlib import Path

kw = sys.argv[1] if len(sys.argv) > 1 else "test"
q  = urllib.parse.quote_plus(kw)
url = f"https://ahmia.fi/search/?q={q}"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

req = urllib.request.Request(url, headers={
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "identity",
})
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
with opener.open(req, timeout=15) as r:
    html = r.read().decode("utf-8", errors="replace")

out = Path.home() / "Desktop" / "OSINT DarkWeb" / "ahmia_debug.html"
out.write_text(html, encoding="utf-8")
print(f"Salvato: {out}  ({len(html)} caratteri)")
print()
print("=== SNIPPET classi CSS presenti ===")
import re
classes = re.findall(r'class=["\']([^"\']+)["\']', html)
from collections import Counter
for cls, n in Counter(classes).most_common(20):
    print(f"  {n:3d}x  .{cls}")
