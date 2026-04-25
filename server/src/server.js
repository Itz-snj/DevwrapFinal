import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import path from 'path';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './swagger.js';
import phase1Routes from './api/phase1.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

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
    timestamp: new Date().toISOString()
  });
});

// ─── Phase 1 Routes: Parsing, Detection, Deobfuscation ─────────────
app.use('/api', phase1Routes);

// Placeholder for future phases
// app.use('/api', phase2Routes);  // Detection & Correlation
// app.use('/api', phase3Routes);  // Full Analysis Pipeline
// app.use('/api', phase4Routes);  // Report Generation

// ─── Start Server ───────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`\n🔥 Project Phoenix server running on http://localhost:${PORT}`);
  console.log(`   Health:  http://localhost:${PORT}/api/health`);
  console.log(`   Swagger: http://localhost:${PORT}/api-docs\n`);
});

export { app, server };
