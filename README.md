# DarkWeb OSINT Intelligence Tool  //  v1.0

Tool di Threat Intelligence per ricerche OSINT su risorse .onion e aggregatori clearnet.
**Uso legittimo**: SOC team, CISO, ricercatori di sicurezza, pen tester.

---

## Requisiti

- Python 3.10+
- PyQt6
- PySocks (opzionale, solo per backend Tor)

---

## Installazione

```bash
pip install PyQt6
pip install PySocks       # opzionale, per routing Tor
python darkweb_osint.py
```

---

## Backend disponibili

### 1. Ahmia.fi (consigliato — clearnet, gratuito)
- Motore di ricerca clearnet che indicizza siti .onion legali
- Nessuna configurazione necessaria
- Accesso diretto tramite HTTPS

### 2. Tor Proxy (locale)
- Richiede Tor Browser o il daemon `tor` attivo su `127.0.0.1:9050`
- Richiede `PySocks`: `pip install PySocks`
- Configura host/porta in Impostazioni se necessario

### 3. API Commerciale
- Compatibile con DarkOwl, Flashpoint, Intel 471, Recorded Future, o endpoint custom
- Inserisci API Key + Endpoint REST in **Impostazioni → API Commerciale**
- Formato risposta atteso: `{ "results": [ { "title", "url", "snippet" } ] }`

---

## Funzionalità

| Feature              | Descrizione                                              |
|----------------------|----------------------------------------------------------|
| Ricerca multi-backend| Ahmia.fi + Tor Proxy + API Commerciale in parallelo      |
| Export CSV / JSON    | File scaricabili con tutti i risultati della sessione    |
| Storico ricerche     | Persistito in SQLite in `~/.darkweb_osint/osint.db`      |
| Alert Monitor        | Polling automatico su keyword sensibili (intervallo custom)|
| Log operativo        | Tab dedicato con timestamp e dettaglio per ogni evento   |
| Impostazioni        | API key, endpoint, path export, host/porta Tor           |

---

## Database

Il DB SQLite viene creato automaticamente in:
```
~/.darkweb_osint/osint.db
```
Tabelle: `searches`, `results`, `alerts`

---

## Note legali

Questo strumento è progettato per attività di Threat Intelligence legittima.
L'uso è responsabilità dell'operatore. Non accedere a contenuti illeciti.
Ahmia.fi filtra attivamente contenuti CSAM dalla propria indicizzazione.
