# ⚡ AgentForge – No-Code AI Agenten Builder

Web-App mit der Endnutzer ohne eine Zeile Code eigene KI-Agenten zusammenstellen, konfigurieren, testen und teilen können. Mit Login, Refresh-Token, Rate-Limit, Passwort-Reset, Share-Links, Function Calling, Streaming, Kosten-Tracking und Backend-Proxy.

## ✨ Features v5

| Bereich | Funktion |
|---|---|
| **🔐 Auth** | Register / Login · JWT Access (15 min) + Refresh (30 d) · bcrypt · auto-Refresh im Client · Server-seitige Refresh-Revocation · Reset-Passwort per Mail (oder Token im PREVIEW-Modus) |
| **🛡 Rate-Limit** | `express-rate-limit` auf allen Auth-Routen (Default 10/min) und API-Routen (120/min) – pro IP **oder** pro User-ID nach Login |
| **☁ Cloud** | Pro-User-Agent-CRUD in SQLite (better-sqlite3) – User sehen nur ihre eigenen Agenten |
| **🔗 Share-Link** | Lese-only-Tokens, 7 Tage Standardablauf, eigenes TTL, öffentlich abrufbar ohne Login |
| **🛠 Tools** | Function Calling: Websuche, Code-Ausführung, Datum/Uhrzeit, Notizen-DB – Provider-agnostisch |
| **💬 Chat** | Streaming (OpenAI-kompatibel), Tool-Aufrufe sichtbar, Kosten-Metadaten pro Nachricht |
| **💰 Kosten** | Token-Tarife pro Modell, Header-Pille, pro Agent akkumuliert, Reset-Klick |
| **🖥 LLM-Proxy** | OpenAI / Anthropic / Gemini im OpenAI-Format, Anthropic & Gemini → OpenAI-Response-Format übersetzt |
| **🚀 Deploy** | Vordefinierte Configs für Render, Fly.io, Docker – keine Codeänderung nötig |

## 🚀 Schnellstart lokal

```bash
cd agent-builder
npm install
cp .env.example .env
# in .env: JWT_SECRET=<lang+random>  + OPENAI_API_KEY=sk-...
node server.js
# → http://localhost:8787
```

Im Browser oben rechts **„🔓 Anmelden"** klicken – fertig.

### Passwort zurücksetzen
- Im Auth-Modal Tab **„🔑 Passwort"** wählen → E-Mail eingeben → Reset-Link anfordern.
- **PREVIEW-Modus** (kein SMTP gesetzt): Der Link und das Token werden direkt im Reply angezeigt (`reset_link`, `reset_token`) – auch auf der Server-Konsole.
- **Mit SMTP** (in `.env`): Echter Versand via `nodemailer`. Beispiel Resend:
  ```
  SMTP_HOST=smtp.resend.com
  SMTP_PORT=587
  SMTP_USER=resend
  SMTP_PASS=re_xxxx
  SMTP_FROM=noreply@firma.de
  ```
- Nach Reset sind **alle** Refresh-Tokens des Users automatisch widerrufen.

### Share-Link erzeugen
- Login → Cloud-Agent auswählen → auf das **🔗-Tag** klicken.
- Link wird im Modal angezeigt, ist `read_only`. Andere sehen den Agent, können ihn aber nicht speichern oder ausführen.

## 🌐 API-Endpunkte v5

| Methode | Pfad | Auth | Zweck |
|---|---|---|---|
| POST | `/api/auth/register` | – (Rate-Limit) | Konto + Access+Refresh |
| POST | `/api/auth/login` | – (Rate-Limit) | Login, Access+Refresh |
| POST | `/api/auth/refresh` | – (Rate-Limit) | Frischen Access holen |
| POST | `/api/auth/logout` | ✅ | Refresh-Token widerrufen |
| POST | `/api/auth/forgot-password` | – (Rate-Limit) | Reset auslösen |
| POST | `/api/auth/reset-password` | – (Rate-Limit) | Neues Passwort setzen |
| GET | `/api/auth/me` | ✅ | Aktueller User |
| GET | `/api/agents` | ✅ (Rate-Limit) | Eigene Agenten |
| POST | `/api/agents` | ✅ (Rate-Limit) | Speichern |
| PUT | `/api/agents/:id` | ✅ (Rate-Limit) | Aktualisieren |
| DELETE | `/api/agents/:id` | ✅ (Rate-Limit) | Löschen |
| POST | `/api/agents/:id/share` | ✅ (Rate-Limit) | Share-Link erzeugen (Default 7 Tage) |
| GET | `/api/share/:token` | – (öffentlich) | Share-Config abrufen |
| POST | `/v1/chat/completions` | optional | LLM-Proxy (OpenAI-kompatibel) |
| GET | `/health` | – | Status + Refresh-/Share-Counts |

**Rate-Limits**: Default 10/min für Auth, 120/min für API – über `.env` (`RATE_LIMIT_AUTH`, `RATE_LIMIT_API`) anpassbar. Counter wird von `express-rate-limit` im RAM gehalten; bei Serverneustart zurückgesetzt.

## 🚢 Hosting (1-Click-Style)

### Option A: Render.com (kostenloses free tier)
1. Repo nach GitHub pushen.
2. Auf https://render.com → **New → Blueprint** → Repo auswählen.
3. `render.yaml` wird automatisch erkannt.
4. Im Dashboard bei `OPENAI_API_KEY` (und co.) auf **Add Secret** klicken und Wert eintragen.
5. **Apply** → Live unter `https://agentforge.onrender.com`.

`render.yaml` setzt `JWT_SECRET` automatisch (Random), `ALLOWED_ORIGIN=*` (Test), und nutzt Node-Bordmittel ohne Extra-Deps.

### Option B: Fly.io (kostenlose 3 shared VMs)
```bash
brew install flyctl        # oder https://fly.io/docs/hands-on/install-flyctl/
fly launch --copy-config   # erkennt fly.toml
fly secrets set JWT_SECRET=$(openssl rand -hex 32)
fly secrets set OPENAI_API_KEY=sk-...
fly deploy
```

### Option C: Docker (überall)
```bash
docker build -t agentforge .
docker run -p 8787:8787 \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  -e OPENAI_API_KEY=sk-... \
  -v $PWD/data:/app/data \
  agentforge
```

### SQLite-Persistenz
- Auf Render Free: Persistente Disk via Render-Disks (in `render.yaml` `disk:`-Key ergänzen)
- Auf Fly.io: Volume `flyctl volumes create agent_data`
- Docker: `-v $PWD/data:/app/data`

## 🔒 Sicherheit

- Passwörter → bcrypt (10 Rounds), nie im Klartext persistiert
- Access-Tokens (15 min) und Refresh-Tokens (30 d) sind **separate JWT-Secrets** (`JWT_SECRET` vs `JWT_SECRET:refresh`)
- Jeder Refresh-Token hat eine eindeutige `jti` (DB-Tabelle `refresh_tokens`), serverseitig prüfbar und widerrufbar
- Rate-Limit schützt vor Brute-Force (Auth: 10/min, Standard für Passwort-Reset inkl.)
- Passwort-Reset antwortet immer 200 (keine User-Enumeration)
- Nach Reset: alle Refresh-Tokens des Users werden widerrufen
- Agent-CRUD filtert strikt per `user_id`; Share-Tokens sind `crypto.randomBytes(24).toString('base64url')` mit eigenem `expires_at`
- Share-Endpoint validiert Ablauf (HTTP 410 Gone)
- E-Mail-Bestätigung beim Reset aus Sicherheits-Sicht empfohlen (TODO) – aktuell reicht Token-Besitz
- `.env` und `data.db` sind in `.gitignore`

## 🛠 Echte Werkzeuge

| Tool | Ausführung |
|---|---|
| 🔍 Websuche | DuckDuckGo Instant-Answer |
| 💻 Code-Ausführung | Sicheres `new Function(code)` im Browser |
| 📅 Datum & Uhrzeit | `Date.toLocaleString` |
| 🗄️ Notizen (Mini-DB) | localStorage-Key-Value (kein Server-State – auf Wunsch erweiterbar) |

## 📂 Dateien

| Datei | Zweck |
|---|---|
| `index.html` | Komplette Single-File-Web-App (Frontend) |
| `server.js` | Express-Backend (Auth, CRUD, Share, LLM-Proxy) |
| `package.json` | Dependencies: express, cors, bcryptjs, jsonwebtoken, better-sqlite3, express-rate-limit, nodemailer |
| `.env.example` | Alle ENV-Variablen mit Dokumentation |
| `render.yaml` | Render-Blueprint für 1-Click-Deploy |
| `fly.toml` | Fly.io-Konfiguration |
| `Dockerfile` | Universal-Docker-Build |
| `data.db` | SQLite-DB (automatisch angelegt, **nicht committen**) |

## 📜 Lizenz
MIT – gerne weiterverwenden.
