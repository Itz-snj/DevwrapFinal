# Project Phoenix — Final Architecture

## System Overview

**Project Phoenix** is an automated log correlation and incident forensics platform. It parses heterogeneous security logs, detects threats using deterministic rules (no AI), correlates events across sources, builds attacker profiles, and generates forensic reports.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                              │
│   Neo Brutalist Dashboard — Lovable-generated                       │
│   Pages: Dashboard | Upload | Incidents | Live Monitor | Reports     │
│                                                                      │
│   Tech: React + TypeScript + Tailwind + shadcn/ui                    │
│   Theme: Neo Brutalism (thick borders, hard shadows, flat colors)    │
└────────────┬───────────────────────────────────┬─────────────────────┘
             │ REST API (21 endpoints)           │ WebSocket
             │ http://localhost:3001/api/*        │ ws://localhost:3001/ws/live
             ▼                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        BACKEND (Node.js + Express)                   │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                      API LAYER                               │    │
│  │  phase1.js — Parsing, Detection, Deobfuscation (7 routes)   │    │
│  │  phase2.js — Threats, Correlation, IP Intel   (7 routes)    │    │
│  │  phase3.js — Incidents, Reports, Full Pipeline (7 routes)   │    │
│  │  swagger.js — OpenAPI 3.0 live docs at /api-docs            │    │
│  └───────────┬──────────────────────────────────┬──────────────┘    │
│              │                                  │                    │
│  ┌───────────▼──────────────────────────────────▼──────────────┐    │
│  │                    PROCESSING PIPELINE                       │    │
│  │                                                              │    │
│  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐    │    │
│  │  │  INGESTION   │──▶│  DETECTION   │──▶│ CORRELATION  │    │    │
│  │  │              │   │              │   │              │    │    │
│  │  │ NginxParser  │   │ RuleEngine   │   │ CorrelEngine │    │    │
│  │  │ AuthParser   │   │ 28 rules     │   │ IP grouping  │    │    │
│  │  │ JsonParser   │   │ 5 categories │   │ Attack chains│    │    │
│  │  │ ParserFactory│   │ Regex+Aggr   │   │ Threat score │    │    │
│  │  │ Deobfuscator │   │              │   │ Blast radius │    │    │
│  │  └──────────────┘   └──────────────┘   └──────┬───────┘    │    │
│  │                                                │            │    │
│  │  ┌──────────────┐   ┌──────────────┐   ┌──────▼───────┐    │    │
│  │  │  REPORTING   │   │  ENRICHMENT  │   │   SCHEMAS    │    │    │
│  │  │              │   │              │   │              │    │    │
│  │  │ MarkdownGen  │   │ IpEnricher   │   │ NormalEvent  │    │    │
│  │  │ PdfGenerator │   │ ip-api.com   │   │ Alert        │    │    │
│  │  │              │   │ Rate-limited │   │ AttackChain  │    │    │
│  │  │              │   │ Cached       │   │ AttackProf   │    │    │
│  │  │              │   │              │   │ Incident     │    │    │
│  │  └──────────────┘   └──────────────┘   └──────────────┘    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────┐   ┌─────────────────┐                         │
│  │  INCIDENT STORE │   │  LIVE WATCHDOG  │                         │
│  │                 │   │                 │                         │
│  │  File-backed    │   │  chokidar watch │                         │
│  │  JSON in        │   │  → parse new    │                         │
│  │  data/incidents │   │  → detect       │                         │
│  │  CRUD ops       │   │  → WS broadcast │                         │
│  └─────────────────┘   └─────────────────┘                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## File Tree

```
devwrap/final/
├── package.json                          # Monorepo root with workspaces
├── LOVABLE_PROMPT.md                     # Frontend generation prompt (Neo Brutalism)
├── workflow.md                           # Project workflow + API contracts
│
├── sample-logs/                          # Realistic test data
│   ├── nginx-access.log                  # 23 entries with encoded attack payloads
│   ├── auth.log                          # 21 entries: brute force, SSH, sudo, PAM
│   └── app-events.json                   # 12 structured JSON events
│
├── server/                               # Backend
│   ├── package.json                      # Deps: express, ws, chokidar, multer, md-to-pdf, etc.
│   │
│   ├── src/
│   │   ├── server.js                     # Entry point — Express + WebSocket + routes
│   │   ├── swagger.js                    # OpenAPI 3.0 spec (Phase 1-3, 21 endpoints)
│   │   │
│   │   ├── api/
│   │   │   ├── phase1.js                 # 7 routes: formats, detect, parse, deobfuscate
│   │   │   ├── phase2.js                 # 7 routes: rules, detect-threats, correlate, analyze
│   │   │   └── phase3.js                 # 7 routes: analyze (upload), incidents CRUD, reports
│   │   │
│   │   ├── pipeline/
│   │   │   ├── schemas.js                # NormalizedEvent, Alert, AttackerProfile, AttackChain, Incident
│   │   │   │
│   │   │   ├── deobfuscation/
│   │   │   │   └── Deobfuscator.js       # URL decode, Base64, Unicode, HTML entities
│   │   │   │
│   │   │   ├── ingestion/
│   │   │   │   ├── NginxParser.js        # Nginx combined log format
│   │   │   │   ├── AuthLogParser.js      # Linux auth/syslog format
│   │   │   │   ├── JsonLogParser.js      # NDJSON + pretty-printed JSON
│   │   │   │   └── ParserFactory.js      # Auto-detect + factory pattern
│   │   │   │
│   │   │   ├── detection/
│   │   │   │   ├── RuleEngine.js         # Regex + aggregation rule executor
│   │   │   │   └── rules/
│   │   │   │       ├── index.js          # Aggregates all 28 rules
│   │   │   │       ├── sqlInjection.js   # 9 rules: UNION, tautology, DROP, SLEEP
│   │   │   │       ├── bruteForce.js     # 3 rules: threshold, max attempts, rapid
│   │   │   │       ├── pathTraversal.js  # 5 rules: ../, /etc/passwd, /proc, .env
│   │   │   │       ├── xss.js           # 6 rules: script, events, javascript:
│   │   │   │       └── commandInjection.js # 5 rules: ;cmd, |pipe, `backtick`, $()
│   │   │   │
│   │   │   ├── correlation/
│   │   │   │   └── CorrelationEngine.js  # IP grouping, sliding window, attack chains
│   │   │   │
│   │   │   ├── enrichment/
│   │   │   │   └── IpEnricher.js         # ip-api.com + cache + rate limiting
│   │   │   │
│   │   │   └── reporting/
│   │   │       ├── MarkdownGenerator.js  # 7-section forensic report
│   │   │       └── PdfGenerator.js       # md-to-pdf with branded CSS
│   │   │
│   │   ├── store/
│   │   │   └── IncidentStore.js          # File-backed JSON persistence
│   │   │
│   │   └── realtime/
│   │       └── LiveWatchdog.js           # WebSocket server + chokidar file watcher
│   │
│   ├── data/incidents/                   # Persisted incident JSON files
│   ├── watched-logs/                     # Drop logs here for real-time monitoring
│   │
│   └── tests/
│       ├── phase1.verify.js              # 50 tests
│       ├── phase2.verify.js              # 47 tests
│       └── phase3.verify.js              # 47 tests
│
└── frontend/                             # React dashboard (Lovable-generated)
    └── ...                               # TanStack Router + Tailwind + shadcn/ui
```

---

## Data Flow

```
Log Files (nginx, auth.log, JSON)
        │
        ▼
┌─ INGESTION ─────────────────────────┐
│  ParserFactory.parseAuto()          │
│  ├─ Detects format (confidence %)   │
│  ├─ Selects: Nginx/Auth/Json parser │
│  └─ Deobfuscator.run() on each line│
│     └─ URL → Base64 → Unicode      │
│                                     │
│  Output: NormalizedEvent[]          │
└──────────┬──────────────────────────┘
           │
           ▼
┌─ DETECTION ─────────────────────────┐
│  RuleEngine.detectAll(events)       │
│  ├─ 26 regex rules per event        │
│  │   SQL, XSS, Path, Cmd Injection  │
│  └─ 2 aggregation rules             │
│     (sliding window brute force)    │
│                                     │
│  Output: Alert[]                    │
└──────────┬──────────────────────────┘
           │
           ▼
┌─ CORRELATION ───────────────────────┐
│  CorrelationEngine.correlate()      │
│  ├─ Group events by IP             │
│  ├─ Sliding window → AttackChain[] │
│  ├─ Multi-event patterns:          │
│  │   Credential Stuffing           │
│  │   Unauthorized Access           │
│  │   Successful Traversal          │
│  │   Data Exfiltration             │
│  ├─ Threat scoring (0-100)         │
│  └─ Blast radius graph (nodes/edges)│
│                                     │
│  Output: AttackerProfile[],         │
│          AttackChain[], GraphData   │
└──────────┬──────────────────────────┘
           │
           ▼
┌─ ENRICHMENT ────────────────────────┐
│  IpEnricher.enrichAttackers()       │
│  ├─ Skip private IPs (RFC 1918)    │
│  ├─ ip-api.com lookup              │
│  ├─ Rate limit: 45 req/min         │
│  └─ In-memory cache                │
│                                     │
│  Output: geo, ISP, org per IP      │
└──────────┬──────────────────────────┘
           │
           ▼
┌─ INCIDENT ──────────────────────────┐
│  Incident.buildSummary()            │
│  IncidentStore.save(incident)       │
│  → Persisted as JSON on disk       │
│                                     │
│  Report: MarkdownGenerator.generate │
│  PDF:    PdfGenerator.generate      │
└─────────────────────────────────────┘
```

---

## API Endpoints (21 total)

### Phase 1 — Parsing (7 endpoints)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/health` | Server status |
| `GET` | `/api/formats` | Supported log formats |
| `POST` | `/api/detect` | Auto-detect format |
| `POST` | `/api/parse` | Parse raw content |
| `POST` | `/api/parse/file` | Upload & parse single file |
| `POST` | `/api/deobfuscate` | Test deobfuscation |
| `GET` | `/api/parse/sample` | Parse bundled sample |

### Phase 2 — Detection & Correlation (7 endpoints)
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/rules` | List 28 detection rules |
| `POST` | `/api/detect-threats` | Run rules on content |
| `POST` | `/api/correlate` | Parse → Detect → Correlate |
| `POST` | `/api/analyze/full` | Full pipeline (JSON body) |
| `GET` | `/api/analyze/sample` | Analyze sample log |
| `GET` | `/api/ip/:address` | IP geolocation |
| `GET` | `/api/ip-cache/stats` | Cache stats |

### Phase 3 — Incidents & Reports (7 endpoints)
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/analyze` | Upload files → full pipeline |
| `GET` | `/api/incidents` | List all incidents |
| `GET` | `/api/incidents/:id` | Incident detail |
| `GET` | `/api/incidents/:id/timeline` | Paginated timeline |
| `GET` | `/api/incidents/:id/graph` | Blast radius graph |
| `GET` | `/api/incidents/:id/report` | Download report (md/pdf) |
| `DELETE` | `/api/incidents/:id` | Delete incident |

### Real-time
| Protocol | URL | Purpose |
|----------|-----|---------|
| WebSocket | `ws://localhost:3001/ws/live` | Live event + alert stream |

---

## Detection Rules (28 total)

| Category | Count | Examples |
|----------|-------|---------|
| SQL Injection | 9 | UNION SELECT, OR 1=1, DROP TABLE, SLEEP, INFORMATION_SCHEMA |
| XSS | 6 | `<script>`, onerror, javascript:, img/svg XSS, data: URI |
| Path Traversal | 5 | ../../../, /etc/passwd, /proc, .env, .git/config |
| Command Injection | 5 | ;cmd, |pipe, \`backtick\`, $(), reverse shell |
| Brute Force | 3 | 5+ failures/5min, max attempts, rapid auth requests |

---

## Test Coverage

| Phase | Tests | Scope |
|-------|-------|-------|
| Phase 1 | 50 | Parsers, deobfuscation, schemas, factory auto-detect |
| Phase 2 | 47 | Rule engine, correlation, IP enrichment, full pipeline |
| Phase 3 | 47 | Incident store CRUD, report generation, API endpoints |
| **Total** | **144** | |

```bash
# Run all tests
node server/tests/phase1.verify.js
node server/tests/phase2.verify.js
node server/tests/phase3.verify.js  # Needs server running for API tests
```

---

## Running

```bash
# Start the backend
node server/src/server.js

# Access points:
#   API:       http://localhost:3001/api/health
#   Swagger:   http://localhost:3001/api-docs
#   WebSocket: ws://localhost:3001/ws/live

# Quick test: analyze a sample log
curl -s 'http://localhost:3001/api/analyze/sample?file=nginx-access.log' | jq .summary

# Real-time monitoring: drop a log file into server/watched-logs/
cp sample-logs/nginx-access.log server/watched-logs/test.log
```
