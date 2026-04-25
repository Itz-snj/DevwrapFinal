import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import path from 'path';
import { existsSync, mkdirSync } from 'fs';
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
app.use(cors());
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
