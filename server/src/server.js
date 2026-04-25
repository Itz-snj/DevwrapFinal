import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import path from 'path';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './swagger.js';
import phase1Routes from './api/phase1.js';
import phase2Routes from './api/phase2.js';
import phase3Routes from './api/phase3.js';
import { IncidentStore } from './store/IncidentStore.js';
import { LiveWatchdog } from './realtime/LiveWatchdog.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Middleware ──────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
}));
app.use(express.json({ limit: '50mb' }));

// ─── Incident Store (injected into routes via app.set) ──────────────
const incidentStore = new IncidentStore();
app.set('incidentStore', incidentStore);

// ─── Swagger UI ─────────────────────────────────────────────────────
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: `
    .swagger-ui .topbar { background-color: #0A0A0F; }
    .swagger-ui .info .title { color: #00F0FF; }
  `,
  customSiteTitle: 'Project Phoenix — API Docs',
  swaggerOptions: {
    persistAuthorization: true,
    tryItOutEnabled: true,
    displayRequestDuration: true
  }
}));

// ─── Health Check ───────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Project Phoenix',
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    incidents: incidentStore.count()
  });
});

// ─── Phase 1 Routes: Parsing, Detection, Deobfuscation ─────────────
app.use('/api', phase1Routes);

// ─── Phase 2 Routes: Detection, Correlation, IP Intelligence ────────
app.use('/api', phase2Routes);

// ─── Phase 3 Routes: Incidents, Reports, Full Pipeline ──────────────
app.use('/api', phase3Routes);

// ─── Demo Inject Route (triggers live events for showcase) ──────────

const DEMO_LOGS = {
  'brute-force': [
    '192.168.1.200 - - [25/Apr/2026:10:00:01 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '192.168.1.200 - - [25/Apr/2026:10:00:02 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '192.168.1.200 - - [25/Apr/2026:10:00:03 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '192.168.1.200 - - [25/Apr/2026:10:00:04 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '192.168.1.200 - - [25/Apr/2026:10:00:05 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '192.168.1.200 - - [25/Apr/2026:10:00:06 +0000] "POST /admin/login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
  ],
  'sqli': [
    `10.0.0.99 - - [25/Apr/2026:10:01:01 +0000] "GET /api/search?q=' OR 1=1 -- HTTP/1.1" 200 4096 "-" "sqlmap/1.7"`,
    `10.0.0.99 - - [25/Apr/2026:10:01:02 +0000] "GET /api/search?q=UNION SELECT username,password FROM users HTTP/1.1" 200 8192 "-" "sqlmap/1.7"`,
    `10.0.0.99 - - [25/Apr/2026:10:01:03 +0000] "GET /api/products?id=1;DROP TABLE users-- HTTP/1.1" 500 0 "-" "sqlmap/1.7"`,
  ],
  'mixed': [
    '203.0.113.42 - - [25/Apr/2026:10:02:01 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "DirBuster/1.0"',
    '203.0.113.42 - - [25/Apr/2026:10:02:02 +0000] "GET /api/users HTTP/1.1" 200 2048 "-" "DirBuster/1.0"',
    `203.0.113.42 - - [25/Apr/2026:10:02:03 +0000] "GET /search?q=<script>alert('xss')</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"`,
    '203.0.113.42 - - [25/Apr/2026:10:02:04 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '203.0.113.42 - - [25/Apr/2026:10:02:05 +0000] "POST /admin/login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
    '203.0.113.42 - - [25/Apr/2026:10:02:06 +0000] "POST /admin/login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
  ]
};

app.post('/api/demo/inject', (req, res) => {
  const type = req.body?.type || 'mixed';
  const lines = DEMO_LOGS[type] || DEMO_LOGS['mixed'];
  const watchDir = path.join(__dirname, '../watched-logs');
  const filename = `demo_${Date.now()}.log`;
  writeFileSync(path.join(watchDir, filename), lines.join('\n'), 'utf-8');
  res.json({ message: `Injected ${lines.length} ${type} events`, filename });
});

app.post('/api/demo/fetch-remote', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL parameter' });
  
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
    
    const text = await response.text();
    const watchDir = path.join(__dirname, '../watched-logs');
    const filename = `remote_${Date.now()}.log`;
    
    // Write the fetched log to the watched directory. 
    // LiveWatchdog will automatically detect it, parse it, and broadcast events!
    writeFileSync(path.join(watchDir, filename), text, 'utf-8');
    
    const linesCount = text.split('\n').filter(line => line.trim().length > 0).length;
    res.json({ 
      message: `Successfully fetched and injected ${linesCount} lines from remote URL`, 
      filename 
    });
  } catch (error) {
    console.error('[Remote Fetch Error]', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ─── Start Server & WebSocket ───────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`\n🔥 Project Phoenix server running on http://localhost:${PORT}`);
  console.log(`   Health:    http://localhost:${PORT}/api/health`);
  console.log(`   Swagger:   http://localhost:${PORT}/api-docs`);
  console.log(`   WebSocket: ws://localhost:${PORT}/ws/live\n`);
});

// ─── Live Watchdog (WebSocket + File Watcher) ───────────────────────
const watchDir = path.join(__dirname, '../watched-logs');
if (!existsSync(watchDir)) mkdirSync(watchDir, { recursive: true });

const watchdog = new LiveWatchdog({ server, watchDir });

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('\nShutting down...');
  await watchdog.shutdown();
  server.close();
  process.exit(0);
});

export { app, server, watchdog };
