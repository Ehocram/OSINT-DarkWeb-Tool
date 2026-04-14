#!/usr/bin/env python3
"""
Debug Tor connectivity e Ahmia endpoints.
Esegui con venv attivo e Tor Browser aperto:
    python3 debug_tor.py
"""
import socket, urllib.parse, urllib.request, ssl, json, http.client

ONION = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
KW    = urllib.parse.quote_plus("facebook")

def tor_port():
    for p in (9150, 9050):
        try:
            s = socket.create_connection(("127.0.0.1", p), timeout=3); s.close(); return p
        except: pass
    return 0

def fetch_via_tor(url, port, timeout=30):
    import socks as _socks
    parsed  = urllib.parse.urlparse(url)
    host    = parsed.hostname
    is_ssl  = parsed.scheme == "https"
    p       = parsed.port or (443 if is_ssl else 80)
    path    = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    sock = _socks.create_connection(
        (host, p), timeout,
        proxy_type=_socks.SOCKS5, proxy_addr="127.0.0.1",
        proxy_port=port, proxy_rdns=True
    )
    if is_ssl:
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    conn = (http.client.HTTPSConnection if is_ssl else http.client.HTTPConnection)(host, p, timeout=timeout)
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
    data = resp.read()
    conn.close()
    return resp.status, resp.getheaders(), data.decode("utf-8", errors="replace")

port = tor_port()
print(f"Tor port: {port}")
if not port:
    print("Tor non disponibile!"); exit(1)

tests = [
    f"https://ahmia.fi/search/json/?q={KW}",
    f"https://ahmia.fi/api/search/?q={KW}",
    f"https://ahmia.fi/search/?q={KW}&output=json",
    f"http://{ONION}/search/?q={KW}",
    f"http://{ONION}/search/json/?q={KW}",
]

for url in tests:
    print(f"\n{'='*60}")
    print(f"URL: {url}")
    try:
        status, headers, body = fetch_via_tor(url, port, timeout=40)
        print(f"STATUS: {status}")
        print(f"HEADERS: {dict(headers)}")
        print(f"BODY ({len(body)} chars): {body[:500]}")
    except Exception as e:
        print(f"ERRORE: {type(e).__name__}: {e}")
