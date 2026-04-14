# OSINT-DarkWeb-Tool
DarkWeb Tool
# 🧅 DarkWeb OSINT Intelligence Tool

> **Threat Intelligence & Dark Web monitoring platform for security professionals.**
>
> Developed by **Marco Bonometti — CISO**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![PyQt6](https://img.shields.io/badge/UI-PyQt6-41CD52?logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![License](https://img.shields.io/badge/License-Private-red)](#disclaimer)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-blue)]()

---

## 📋 Overview

DarkWeb OSINT Intelligence Tool è una piattaforma desktop per **Threat Intelligence e monitoraggio del dark web**, progettata per CISO, SOC team, penetration tester e ricercatori di sicurezza.

Il tool consente di cercare informazioni su domini, brand, email e keyword attraverso molteplici fonti — aggregatori clearnet, motori di ricerca .onion via Tor, API di breach database e ransomware leak sites — tutto da un'unica interfaccia grafica con dark theme professionale.

---

## ✨ Funzionalità principali

### 🔍 Ricerca multi-backend
- **Ahmia.fi / Clearnet Aggregators** — ricerca su aggregatori clearnet che indicizzano siti .onion (HiddenSearch, Tor.link, Onion.live)
- **Tor Proxy (locale)** — ricerca diretta su DuckDuckGo .onion via SOCKS5 proxy (richiede Tor Browser o daemon `tor`)
- **API Commerciale** — compatibilità con DarkOwl, Flashpoint, Intel 471, Recorded Future o endpoint REST custom

### ⚠️ Threat Intelligence automatizzata
Tab dedicato con scansione multi-fonte su un target (dominio, email o brand):
- **Have I Been Pwned (HIBP)** — verifica breach per dominio aziendale e ricerca nel database breach pubblici
- **Ransomware Leak Sites** — monitoraggio via RansomLook API e RansomWatch per verificare se il target è stato pubblicato da gruppi ransomware
- **Paste Sites** — ricerca su Pastebin (via psbdmp.ws), IntelX e DuckDuckGo paste search
- **DDG .onion TI** — query mirate su DuckDuckGo .onion per credential leak, data breach, password dump
- **Query Preset** — bottoni rapidi per ricerche preconfigurate (Credential leak, Data breach, Ransomware, Brand abuse, Paste sites, Dark web mention)

### 🌐 DeepDarkCTI Integration
Tab con risorse dal progetto [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI):
- **Directory Ransomware Leak Sites** — tabella navigabile con 30+ gruppi ransomware attivi (LockBit, BlackBasta, Akira, Medusa, Play, Cl0p, RansomHub, ecc.) con URL .onion e stato
- **Ricerca multi-motore .onion** — ricerca parallela su Torch, Haystak, DarkSearch, Tordex, Tor66, FindTor, OnionLand, GDark, Deep Search
- **Aggiornamento live da GitHub** — scarica e aggiorna automaticamente le liste ransomware e i motori di ricerca dal repository deepdarkCTI

### 🔔 Alert Monitor
- Monitoraggio automatico in background su keyword sensibili
- Intervallo di polling configurabile (5–1440 minuti)
- Notifica in-app quando una keyword viene trovata
- Contatore trigger e timestamp ultimo match

### 📊 Gestione risultati
- Tabella risultati con colonne TITOLO, URL, FONTE, SNIPPET
- Pannello dettaglio con evidenziazione severity (CRITICAL, HIGH, MEDIUM, OK, INFO)
- Click su URL .onion → copia automatica negli appunti + apertura Tor Browser
- Click su URL clearweb → apertura nel browser di sistema
- Colori differenziati: verde per .onion, blu per clearweb, rosso per critical

### 💾 Export & storico
- **Export CSV** — tutti i risultati della sessione in formato CSV
- **Export JSON** — export strutturato per integrazione con SIEM/SOAR
- **Storico ricerche** — persistito in database SQLite locale (`~/.darkweb_osint/osint.db`)
- Double-click sullo storico per ricaricare una ricerca precedente

### 🛠️ Impostazioni
- API Key HIBP (Have I Been Pwned)
- API Key + Endpoint per servizi commerciali
- Host e porta proxy Tor (default: 127.0.0.1:9150)
- Cartella export personalizzabile
- Persistenza impostazioni tra sessioni

### 🎨 Interfaccia
- Dark theme professionale (Fusion + palette custom)
- Font monospace Consolas
- Layout a tab: RISULTATI, THREAT INTEL, DEEPDARK CTI, STORICO, ALERT MONITOR, LOG, IMPOSTAZIONI
- Progress bar per ogni operazione
- Status bar con feedback real-time
- Log operativo con timestamp per ogni evento

---

## 🚀 Installazione

### Prerequisiti
- **Python 3.10+** ([download](https://python.org/downloads/))
- **Tor Browser** (opzionale, per ricerche .onion) — [download](https://www.torproject.org/download/)

### Setup

```bash
# 1. Clona il repository
git clone https://github.com/YOUR_USERNAME/darkweb-osint-tool.git
cd darkweb-osint-tool

# 2. Crea il virtual environment
python3 -m venv venv

# 3. Attiva il venv
source venv/bin/activate        # macOS / Linux
# oppure
venv\Scripts\activate           # Windows

# 4. Installa le dipendenze
pip3 install -r requirements.txt

# 5. Avvia il tool
python3 darkweb_osint.py
```

### Dipendenze

| Pacchetto | Versione | Note |
|-----------|----------|------|
| `PyQt6` | ≥ 6.5.0 | UI framework |
| `PySocks` | ≥ 1.7.1 | Opzionale — routing SOCKS5 per Tor |

Tutte le altre dipendenze (`sqlite3`, `urllib`, `json`, `csv`, `re`, `socket`, `ssl`) sono incluse nella libreria standard Python.

---

## 📖 Guida rapida

### Ricerca base (senza Tor)
1. Avvia il tool
2. Inserisci una keyword nella barra di ricerca (es: `ransomware leak`, `credential dump`)
3. Seleziona il backend **Ahmia.fi (clearnet)**
4. Clicca **⚡ AVVIA RICERCA**
5. I risultati appaiono nella tab RISULTATI

### Ricerca via Tor
1. Avvia **Tor Browser** (deve restare aperto in background)
2. Nel tool, seleziona il backend **Tor Proxy (locale)**
3. Il tool si connette automaticamente sulla porta 9150 (Tor Browser) o 9050 (daemon tor)
4. La ricerca viene instradata su DuckDuckGo .onion via circuito Tor

### Threat Intelligence su un target
1. Vai alla tab **⚠ THREAT INTEL**
2. Inserisci il dominio, l'email o il brand nel campo Target
3. Seleziona le fonti da interrogare (HIBP, Ransomware, Paste, DDG .onion)
4. Clicca **🔍 SCAN THREAT INTEL**
5. I risultati vengono classificati per severity: CRITICAL, HIGH, MEDIUM, OK
6. Usa i **Query Preset** per ricerche mirate (Credential leak, Brand abuse, ecc.)

### DeepDarkCTI
1. Vai alla tab **🌐 DEEPDARK CTI**
2. Consulta la directory dei ransomware leak sites
3. Clicca su un URL .onion per copiarlo negli appunti → incolla in Tor Browser
4. Usa la barra di ricerca per cercare su tutti i motori .onion contemporaneamente
5. Clicca **↺ Aggiorna da GitHub** per scaricare le liste aggiornate

### Alert Monitor
1. Vai alla tab **ALERT MONITOR**
2. Inserisci una keyword da monitorare (es: il tuo dominio aziendale)
3. Configura l'intervallo di polling (default: 30 minuti)
4. Il tool controlla periodicamente Ahmia.fi e logga i match

### HIBP (Have I Been Pwned)
1. Vai su [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) e acquista una API key (€3.50/mese)
2. Inseriscila nella tab **IMPOSTAZIONI → HIBP API Key**
3. Il Threat Intel scanner userà HIBP per verificare breach sul dominio target

---

## 🗂️ Struttura progetto

```
darkweb-osint-tool/
├── darkweb_osint.py          # Applicazione principale (1850+ righe)
├── requirements.txt          # Dipendenze Python
├── README.md                 # Questo file
├── venv/                     # Virtual environment (non versionare)
└── ~/.darkweb_osint/
    └── osint.db              # Database SQLite (creato automaticamente)
```

---

## 🔧 Backend & fonti dati

| Backend | Tipo | Auth | Descrizione |
|---------|------|------|-------------|
| Ahmia.fi | Clearnet | No | Aggregatori clearnet per siti .onion |
| DuckDuckGo .onion | Tor | No | Ricerca server-side via /html/ (no JavaScript) |
| HIBP API v3 | Clearnet | API Key | Breach database per dominio ed email |
| RansomLook API | Clearnet | No | Aggregatore post ransomware group |
| RansomWatch | Clearnet | No | Fallback per monitoraggio ransomware |
| Psbdmp.ws | Clearnet | No | Aggregatore Pastebin |
| IntelX | Clearnet | No | Ricerca paste (risultati limitati senza auth) |
| DeepDarkCTI | Tor | No | 10+ motori di ricerca .onion |
| API Commerciale | Clearnet | API Key | DarkOwl, Flashpoint, Intel 471, Recorded Future |

---

## 🗃️ Database

Il database SQLite viene creato automaticamente in `~/.darkweb_osint/osint.db` con tre tabelle:

| Tabella | Descrizione |
|---------|-------------|
| `searches` | Storico ricerche (timestamp, keywords, backend, conteggio risultati) |
| `results` | Risultati individuali collegati alle ricerche |
| `alerts` | Keyword monitorate con stato, timestamp creazione/trigger, contatore |

---

## ⚙️ Configurazione avanzata

### Tor daemon (alternativa a Tor Browser)

Se preferisci usare il daemon `tor` anziché Tor Browser:

```bash
# macOS (Homebrew)
brew install tor
tor &

# Il daemon ascolta su 127.0.0.1:9050
# Il tool lo rileva automaticamente
```

### API Commerciale

Per integrare un servizio di threat intelligence commerciale:

1. Vai su **IMPOSTAZIONI → API Commerciale**
2. Inserisci l'API Key (Bearer token)
3. Inserisci l'endpoint REST (es: `https://api.darkowl.com/v1`)
4. Il tool si aspetta una risposta JSON nel formato:

```json
{
  "results": [
    {
      "title": "Risultato esempio",
      "url": "http://example.onion/page",
      "snippet": "Descrizione del risultato"
    }
  ]
}
```

---

## 🛡️ Disclaimer

Questo strumento è progettato **esclusivamente per attività di Threat Intelligence legittima** — vulnerability assessment, brand monitoring, incident response e ricerca di sicurezza.

- L'uso è responsabilità dell'operatore
- Non accedere a contenuti illeciti
- Ahmia.fi filtra attivamente contenuti CSAM dalla propria indicizzazione
- Rispettare le leggi vigenti nel proprio paese e le policy aziendali
- Lo strumento non memorizza né scarica contenuti dai siti .onion — fornisce solo metadati di ricerca (titolo, URL, snippet)

---

## 👤 Autore

**Marco Bonometti** — CISO

---

## 📄 License

Private — All rights reserved.
