# 🔥 Project Phoenix — Automated Log Forensics Engine

> **Real-time security log parsing, threat detection, attacker correlation, and forensic report generation — powered entirely by deterministic regex rules, no AI.**

[![Live Frontend](https://img.shields.io/badge/🌐_Live_Frontend-Render-4351e8?style=for-the-badge)](https://devwrapfinalfrontend.onrender.com)
[![Live Backend](https://img.shields.io/badge/⚙️_Live_Backend-Render-4351e8?style=for-the-badge)](https://devwrapfinal.onrender.com/api/health)
[![API Docs](https://img.shields.io/badge/📖_Swagger_Docs-OpenAPI-85EA2D?style=for-the-badge)](https://devwrapfinal.onrender.com/api-docs)
[![Tests](https://img.shields.io/badge/Tests-144_Passing-brightgreen?style=for-the-badge)]()

---

## 📑 Table of Contents

- [How It Works](#-how-it-works)
- [What Files Does It Read?](#-what-files-does-it-read)
- [Expected Output](#-expected-output)
- [Verify It Yourself](#-verify-it-yourself--judges)
- [Live API Endpoints](#-live-api-endpoints)
- [Architecture](#-architecture)
- [Running Locally](#-running-locally)
- [Test Coverage](#-test-coverage)
- [Requirements Coverage](#-requirements-coverage)

---

## 🧠 How It Works

Project Phoenix reads **real log files** (nginx access logs, Linux auth logs, and JSON structured events), processes them through a multi-stage pipeline, and produces forensic incident reports with attacker profiles.

```
Real Log Files → Parse → Deobfuscate → Detect Threats → Correlate Attacks → Enrich IPs → Generate Reports
```

### The Pipeline (5 stages)

| Stage | What Happens | Output |
|-------|-------------|--------|
| **1. Ingestion** | Auto-detects log format (nginx/auth/JSON), parses each line into structured events | `NormalizedEvent[]` — timestamp, IP, method, endpoint, status |
| **2. Deobfuscation** | Decodes URL-encoded, Base64, and Unicode-obfuscated payloads before detection | Clean request strings for accurate rule matching |
| **3. Detection** | Runs **28 regex rules** across 5 attack categories on every event | `Alert[]` — rule ID, severity (CRITICAL/HIGH/MEDIUM/LOW), category |
| **4. Correlation** | Groups events by IP, builds attack chains via sliding window, identifies multi-stage attacks | `AttackerProfile[]`, `AttackChain[]`, blast radius graph |
| **5. Reporting** | Generates forensic reports with timeline, attacker profiles, evidence blocks | Markdown & PDF reports |

### Detection Rules (28 total)

| Category | Rules | Examples |
|----------|-------|---------|
| SQL Injection | 9 | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `SLEEP()`, `INFORMATION_SCHEMA` |
| XSS | 6 | `<script>`, `onerror=`, `javascript:`, SVG XSS, `data:` URI |
| Path Traversal | 5 | `../../../`, `/etc/passwd`, `/proc`, `.env`, `.git/config` |
| Command Injection | 5 | `;cmd`, `|pipe`, `` `backtick` ``, `$()`, reverse shell |
| Brute Force | 3 | 5+ failures/5min, max auth attempts, rapid login requests |

---

## 📂 What Files Does It Read?

The backend reads **real log files** from the `sample-logs/` directory. These files are committed to this public repository — **not mock data**.

### Log Files (3 files, all in [`sample-logs/`](sample-logs/))

| File | Format | Lines | Contents |
|------|--------|-------|----------|
| [`nginx-access.log`](sample-logs/nginx-access.log) | Nginx combined | 23 | Brute-force login attempts, SQL injection payloads (`UNION SELECT`, `OR 1=1`), path traversal (`../../etc/passwd`), XSS attempts, normal traffic |
| [`auth.log`](sample-logs/auth.log) | Linux syslog | 21 | SSH brute-force attacks, failed/successful password auth, PAM session events, sudo privilege escalation, max auth attempts exceeded |
| [`app-events.json`](sample-logs/app-events.json) | JSON structured | 12 | Application-level events: login success, access denied, SQL injection detected by WAF, XSS blocked, health checks |

### How the Backend Reads Them

1. **On startup** — The server checks if the incident store is empty. If it is, it reads all 3 files from `sample-logs/`, runs the full pipeline, and stores the resulting incidents. This happens automatically on every fresh deploy.

2. **Via API** — The `GET /api/sample-logs` endpoint reads the files from disk and returns their contents with metadata. The `GET /api/sample-logs/github-fetch/:filename` endpoint fetches files **live from this GitHub repository** to prove they're real.

3. **Via file upload** — Judges can upload their own log files through the frontend Upload page or the `POST /api/analyze` endpoint.

4. **Real-time monitoring** — The `LiveWatchdog` watches the `server/watched-logs/` directory. Dropping a log file there triggers automatic parsing, detection, and WebSocket broadcast to all connected clients.

### File Locations on the Deployed Server

```
/opt/render/project/src/              ← Render workspace root
├── sample-logs/                       ← Log files read by the pipeline
│   ├── nginx-access.log               ← 23 nginx entries with encoded attack payloads
│   ├── auth.log                       ← 21 auth entries: brute force, SSH, sudo
│   └── app-events.json                ← 12 structured JSON events
├── server/
│   ├── data/incidents/                ← Stored incident JSON files (auto-generated)
│   └── watched-logs/                  ← Drop files here for real-time monitoring
```

---

## 📊 Expected Output

When the pipeline processes the 3 sample log files, here's what it produces:

### Incidents Generated (4 total on startup)

| Incident | Source File(s) | Events | Alerts | Threat Score | Top Attacker |
|----------|---------------|--------|--------|-------------|-------------|
| #1 | `app-events.json` | 12 | 5 | High | 192.168.1.105 |
| #2 | `auth.log` | 21 | 5 | High | 192.168.1.105 |
| #3 | `nginx-access.log` | 23 | 9 | Critical | 192.168.1.105 |
| #4 | **All 3 combined** | 56 | 17 | Critical (100) | 192.168.1.105 |

### Detected Attack Types

| Attack Type | Alerts | Severity | Example from Logs |
|------------|--------|----------|-------------------|
| SQL Injection | 4 | CRITICAL | `GET /api/search?q=UNION SELECT username,password FROM users` |
| Path Traversal | 7 | CRITICAL | `GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd` |
| XSS | 2 | HIGH | `POST /api/search?q=<script>alert('xss')</script>` |
| Command Injection | 1 | CRITICAL | `sudo /bin/cat /etc/shadow` |
| Brute Force | 3 | HIGH | 5+ failed SSH logins from 192.168.1.105 in 15 seconds |

### Attacker Profiles

| Attacker IP | Events | Attack Types | Threat Score | Correlation Pattern |
|------------|--------|-------------|-------------|-------------------|
| `192.168.1.105` | 34 | SQLi + Path Traversal + Brute Force | 100 | Credential Stuffing → Unauthorized Access → Data Exfiltration |
| `10.0.0.42` | 14 | XSS + Brute Force | 75 | Brute Force → Successful Login |
| `172.16.0.10` | 8 | None (legitimate traffic) | 0 | Normal browsing behavior |

---

## ✅ Verify It Yourself (Judges)

### 1. Check the Raw Log Files

Browse the real log files the backend reads:

```bash
# List all log files with GitHub links
curl https://devwrapfinal.onrender.com/api/sample-logs

# Read a specific log file
curl https://devwrapfinal.onrender.com/api/sample-logs/nginx-access.log

# Get raw text (plain text, no JSON wrapper)
curl https://devwrapfinal.onrender.com/api/sample-logs/nginx-access.log?format=raw
```

### 2. Verify Files Match GitHub

The API response includes GitHub URLs for each file. Click them to verify the file in this public repo matches what the backend reads:

- 📄 [nginx-access.log on GitHub](https://github.com/Itz-snj/DevwrapFinal/blob/main/sample-logs/nginx-access.log)
- 📄 [auth.log on GitHub](https://github.com/Itz-snj/DevwrapFinal/blob/main/sample-logs/auth.log)
- 📄 [app-events.json on GitHub](https://github.com/Itz-snj/DevwrapFinal/blob/main/sample-logs/app-events.json)

### 3. Fetch Live from GitHub

The backend can also fetch log files **directly from this GitHub repository** and process them:

```bash
# Fetch nginx-access.log live from GitHub and run detection
curl "https://devwrapfinal.onrender.com/api/sample-logs/github-fetch/nginx-access.log?analyze=true"
```

### 4. Check Pre-seeded Incidents

```bash
# List all incidents (auto-generated from real log files)
curl https://devwrapfinal.onrender.com/api/incidents

# Get server health + incident count
curl https://devwrapfinal.onrender.com/api/health
```

### 5. Upload Your Own Logs

Upload any nginx, auth.log, or JSON log file through:
- **Frontend**: Visit the [Upload page](https://devwrapfinalfrontend.onrender.com/upload) and drag & drop
- **API**: `POST /api/analyze` with multipart form data
- **Swagger**: Visit [/api-docs](https://devwrapfinal.onrender.com/api-docs) and use "Try it out"

---

## 🔌 Live API Endpoints

### Quick Links

| Endpoint | Description | Try It |
|----------|-------------|--------|
| `/api/health` | Server status + uptime + incident count | [Open](https://devwrapfinal.onrender.com/api/health) |
| `/api/sample-logs` | Browse real log files with GitHub links | [Open](https://devwrapfinal.onrender.com/api/sample-logs) |
| `/api/incidents` | List all detected security incidents | [Open](https://devwrapfinal.onrender.com/api/incidents) |
| `/api/rules` | View all 28 detection rules | [Open](https://devwrapfinal.onrender.com/api/rules) |
| `/api-docs` | Interactive Swagger documentation | [Open](https://devwrapfinal.onrender.com/api-docs) |

### All 21+ Endpoints

<details>
<summary>Phase 1 — Parsing (7 endpoints)</summary>

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/health` | Server status |
| `GET` | `/api/formats` | Supported log formats |
| `POST` | `/api/detect` | Auto-detect log format |
| `POST` | `/api/parse` | Parse raw content |
| `POST` | `/api/parse/file` | Upload & parse single file |
| `POST` | `/api/deobfuscate` | Test deobfuscation |
| `GET` | `/api/parse/sample` | Parse bundled sample |

</details>

<details>
<summary>Phase 2 — Detection & Correlation (7 endpoints)</summary>

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/rules` | List 28 detection rules |
| `POST` | `/api/detect-threats` | Run rules on content |
| `POST` | `/api/correlate` | Parse → Detect → Correlate |
| `POST` | `/api/analyze/full` | Full pipeline (JSON body) |
| `GET` | `/api/analyze/sample` | Analyze sample log |
| `GET` | `/api/ip/:address` | IP geolocation |
| `GET` | `/api/ip-cache/stats` | Cache stats |

</details>

<details>
<summary>Phase 3 — Incidents & Reports (7 endpoints)</summary>

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/analyze` | Upload files → full pipeline |
| `GET` | `/api/incidents` | List all incidents |
| `GET` | `/api/incidents/:id` | Incident detail |
| `GET` | `/api/incidents/:id/timeline` | Paginated timeline |
| `GET` | `/api/incidents/:id/graph` | Blast radius graph |
| `GET` | `/api/incidents/:id/report` | Download report (md/pdf) |
| `DELETE` | `/api/incidents/:id` | Delete incident |

</details>

<details>
<summary>Sample Logs — Read-Only File Browser (3 endpoints)</summary>

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/sample-logs` | List files with GitHub links |
| `GET` | `/api/sample-logs/:filename` | Read raw file contents |
| `GET` | `/api/sample-logs/github-fetch/:filename` | Fetch live from GitHub |

</details>

<details>
<summary>Real-Time</summary>

| Protocol | URL | Purpose |
|----------|-----|---------|
| WebSocket | `wss://devwrapfinal.onrender.com/ws/live` | Live event + alert stream |

</details>

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                              │
│   Neo Brutalist Dashboard — TanStack Router + Tailwind + shadcn/ui   │
│   Pages: Dashboard | Upload | Incidents | Live Monitor | Reports     │
└────────────┬───────────────────────────────┬─────────────────────────┘
             │ REST API (24 endpoints)       │ WebSocket
             ▼                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        BACKEND (Node.js + Express)                   │
│                                                                      │
│   sample-logs/ ──→ ParserFactory ──→ RuleEngine ──→ CorrelationEngine│
│     (real files)   (auto-detect)     (28 rules)    (IP grouping,     │
│                    (deobfuscate)     (5 categories)  attack chains,   │
│                                                      blast radius)   │
│                         │                                            │
│                         ▼                                            │
│              IncidentStore (file-backed JSON)                        │
│              LiveWatchdog (chokidar + WebSocket)                     │
│              IpEnricher (ip-api.com + cache)                         │
│              ReportGenerator (Markdown + PDF)                        │
└──────────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19 + TypeScript + TanStack Router + Tailwind CSS + shadcn/ui |
| Backend | Node.js + Express + WebSocket (ws) |
| File Watching | chokidar |
| Reports | md-to-pdf |
| API Docs | Swagger UI (OpenAPI 3.0) |
| Deployment | Render (free tier, both services) |
| Keep-Alive | GitHub Actions cron (*/10 min) + server self-ping |

---

## 🚀 Running Locally

```bash
# Clone
git clone https://github.com/Itz-snj/DevwrapFinal.git
cd DevwrapFinal

# Install dependencies (monorepo workspaces)
npm install

# Start backend (port 3001)
cd server && npm start

# In another terminal — start frontend (port 3000)
cd frontend && npm run dev

# Access points:
#   Frontend:  http://localhost:3000
#   Backend:   http://localhost:3001/api/health
#   Swagger:   http://localhost:3001/api-docs
#   Sample Logs: http://localhost:3001/api/sample-logs
#   WebSocket: ws://localhost:3001/ws/live
```

### Quick API Test

```bash
# Analyze the sample nginx log
curl -s 'http://localhost:3001/api/analyze/sample?file=nginx-access.log' | jq .summary

# Real-time monitoring — drop a log file
cp sample-logs/nginx-access.log server/watched-logs/test.log
# → Events and alerts stream to all WebSocket clients
```

---

## 🧪 Test Coverage

| Phase | Tests | Scope |
|-------|-------|-------|
| Phase 1 | 50 | Parsers, deobfuscation, schemas, factory auto-detect |
| Phase 2 | 47 | Rule engine, correlation, IP enrichment, full pipeline |
| Phase 3 | 47 | Incident store CRUD, report generation, API endpoints |
| **Total** | **144** | |

```bash
node server/tests/phase1.verify.js
node server/tests/phase2.verify.js
node server/tests/phase3.verify.js  # Needs server running
```

---

## ✅ Requirements Coverage

| # | Requirement | Status | Implementation |
|---|-------------|--------|----------------|
| 1.1 | Nginx access logs | ✅ | `NginxParser.js` |
| 1.2 | Linux auth.log | ✅ | `AuthLogParser.js` |
| 1.3 | JSON structured logs | ✅ | `JsonLogParser.js` |
| 1.4 | Normalize: timestamp, IP, endpoint, status | ✅ | `schemas.js` + `ParserFactory.js` |
| 2.1 | Timestamp synchronization | ✅ | `CorrelationEngine.js` |
| 2.2 | IP-based linking | ✅ | `groupByIp()` |
| 2.3 | Multi-event pattern detection | ✅ | 4 correlation patterns |
| 3.1 | SQL Injection detection | ✅ | `sqlInjection.js` — 9 rules |
| 3.2 | Brute Force detection | ✅ | `bruteForce.js` — 3 rules |
| 3.3 | Path Traversal detection | ✅ | `pathTraversal.js` — 5 rules |
| 3.4 | Extensible rule system | ✅ | Modular `rules/` folder |
| 4.1 | Graph visualization | ✅ | `react-force-graph-2d` (D3-based) |
| 4.2 | Attacker IP as central node | ✅ | `buildGraphData()` |
| 4.3 | Connected endpoints/resources | ✅ | Nodes: attacker, endpoint, resource |
| 5.1 | WebSocket real-time | ✅ | `ws://*/ws/live` |
| 5.2 | File watching (tail-style) | ✅ | `chokidar` in `LiveWatchdog.js` |
| 5.3 | High-severity alerts | ✅ | Detection + WS broadcast |
| 6.1 | Incident Timeline | ✅ | `MarkdownGenerator.js` |
| 6.2 | Attacker Profile (IP, geo, ISP) | ✅ | `IpEnricher.js` + `ip-api.com` |
| 6.3 | Evidence blocks (raw log entries) | ✅ | `_evidence()` |
| 6.4 | PDF reports | ✅ | `PdfGenerator.js` (md-to-pdf) |
| 6.5 | Markdown reports | ✅ | `MarkdownGenerator.js` |
| 7.1 | IP Geolocation | ✅ | `IpEnricher.js` |
| 8.1 | URL decoding | ✅ | `Deobfuscator.js` |
| 8.2 | Base64 decoding | ✅ | `Deobfuscator.js` |

**Overall Coverage: 100%** — All 24 requirements implemented with 144 tests.