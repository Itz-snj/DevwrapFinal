/**
 * Project Phoenix — Phase 3 API Routes
 * 
 * Incident management, report generation, timeline, and graph endpoints.
 * These are the endpoints the frontend dashboard consumes.
 */

import { Router } from 'express';
import multer from 'multer';
import { ParserFactory } from '../pipeline/ingestion/ParserFactory.js';
import { RuleEngine } from '../pipeline/detection/RuleEngine.js';
import { CorrelationEngine } from '../pipeline/correlation/CorrelationEngine.js';
import { IpEnricher } from '../pipeline/enrichment/IpEnricher.js';
import { MarkdownGenerator } from '../pipeline/reporting/MarkdownGenerator.js';
import { PdfGenerator } from '../pipeline/reporting/PdfGenerator.js';
import { Incident } from '../pipeline/schemas.js';

const router = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });
const factory = new ParserFactory();
const ruleEngine = new RuleEngine();
const correlationEngine = new CorrelationEngine();
const ipEnricher = new IpEnricher();
const markdownGen = new MarkdownGenerator();
const pdfGen = new PdfGenerator();

// IncidentStore is injected via middleware (set in server.js)
function getStore(req) {
  return req.app.get('incidentStore');
}

// ─── POST /api/analyze ─────────────────────────────────────────────
// Multipart file upload → full pipeline → store & return incident
router.post('/analyze', upload.array('files', 10), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded. Use form field name "files".' });
  }

  try {
    const store = getStore(req);
    let allEvents = [];
    let allAlerts = [];
    const parsedFiles = [];

    // Parse all uploaded files
    for (const file of req.files) {
      const content = file.buffer.toString('utf-8');
      const filename = file.originalname;

      try {
        const { events, format, confidence } = factory.parseAuto(content, filename);
        allEvents.push(...events);
        parsedFiles.push({ filename, format, confidence, events: events.length });
      } catch (err) {
        parsedFiles.push({ filename, error: err.message, events: 0 });
      }
    }

    if (allEvents.length === 0) {
      return res.status(400).json({
        error: 'No events could be parsed from the uploaded files',
        files: parsedFiles
      });
    }

    // Detect
    const { alerts } = ruleEngine.detectAll(allEvents);
    allAlerts = alerts;

    // Correlate
    const { attackers, attackChains, graphData, correlationAlerts } =
      correlationEngine.correlate(allEvents, allAlerts);

    // Enrich
    if (attackers.length > 0) {
      await ipEnricher.enrichAttackers(attackers);
    }

    // Build incident
    const incident = new Incident({
      events: allEvents,
      alerts: allAlerts,
      attackers,
      attackChains,
      graphData
    });
    incident.buildSummary();

    // Store
    store.save(incident);

    res.json({
      incidentId: incident.id,
      files: parsedFiles,
      summary: incident.summary,
      attackers: attackers.map(a => ({
        ...(a.toJSON?.() || a),
        isp: a.isp,
        org: a.org
      })),
      attackChains: attackChains.map(c => c.toJSON()),
      correlationAlerts,
      graphData,
      alertsBySeverity: incident.summary.alertsBySeverity,
      attackTypes: incident.summary.attackTypes
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/incidents ────────────────────────────────────────────
router.get('/incidents', (req, res) => {
  const store = getStore(req);
  const incidents = store.list();
  res.json({ incidents, total: incidents.length });
});

// ─── GET /api/incidents/:id ────────────────────────────────────────
router.get('/incidents/:id', (req, res) => {
  const store = getStore(req);
  const incident = store.get(req.params.id);

  if (!incident) {
    return res.status(404).json({ error: `Incident not found: ${req.params.id}` });
  }

  res.json({
    id: incident.id,
    createdAt: incident.createdAt,
    status: incident.status,
    summary: incident.summary,
    attackers: incident.attackers,
    alertsBySeverity: incident.summary?.alertsBySeverity,
    attackTypes: incident.summary?.attackTypes
  });
});

// ─── GET /api/incidents/:id/timeline ───────────────────────────────
router.get('/incidents/:id/timeline', (req, res) => {
  const store = getStore(req);
  const incident = store.get(req.params.id);

  if (!incident) {
    return res.status(404).json({ error: `Incident not found: ${req.params.id}` });
  }

  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 100;
  const events = incident.events || [];

  // Sort by timestamp
  events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  // Paginate
  const start = (page - 1) * pageSize;
  const pageEvents = events.slice(start, start + pageSize);

  // Attach alerts to each event
  const alertMap = new Map();
  for (const alert of (incident.alerts || [])) {
    const key = alert.event?.ip + '_' + alert.event?.timestamp;
    if (!alertMap.has(key)) alertMap.set(key, []);
    alertMap.get(key).push({
      ruleId: alert.ruleId,
      severity: alert.severity,
      category: alert.category,
      description: alert.description
    });
  }

  const enrichedEvents = pageEvents.map((e, i) => {
    const key = e.ip + '_' + e.timestamp;
    return {
      ...e,
      alerts: alertMap.get(key) || []
    };
  });

  res.json({
    events: enrichedEvents,
    totalEvents: events.length,
    page,
    pageSize,
    totalPages: Math.ceil(events.length / pageSize)
  });
});

// ─── GET /api/incidents/:id/graph ──────────────────────────────────
router.get('/incidents/:id/graph', (req, res) => {
  const store = getStore(req);
  const incident = store.get(req.params.id);

  if (!incident) {
    return res.status(404).json({ error: `Incident not found: ${req.params.id}` });
  }

  res.json(incident.graphData || { nodes: [], edges: [] });
});

// ─── GET /api/incidents/:id/report ─────────────────────────────────
router.get('/incidents/:id/report', async (req, res) => {
  const store = getStore(req);
  const incident = store.get(req.params.id);

  if (!incident) {
    return res.status(404).json({ error: `Incident not found: ${req.params.id}` });
  }

  const format = req.query.format || 'md';
  const markdown = markdownGen.generate(incident);

  if (format === 'pdf') {
    try {
      const pdfBuffer = await pdfGen.generate(markdown);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="phoenix_report_${incident.id}.pdf"`);
      return res.send(pdfBuffer);
    } catch (err) {
      // Fallback to markdown if PDF fails
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="phoenix_report_${incident.id}.md"`);
      res.setHeader('X-PDF-Error', err.message);
      return res.send(markdown);
    }
  }

  // Markdown download
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="phoenix_report_${incident.id}.md"`);
  res.send(markdown);
});

// ─── DELETE /api/incidents/:id ─────────────────────────────────────
router.delete('/incidents/:id', (req, res) => {
  const store = getStore(req);
  const deleted = store.delete(req.params.id);

  if (!deleted) {
    return res.status(404).json({ error: `Incident not found: ${req.params.id}` });
  }

  res.json({ message: 'Incident deleted', id: req.params.id });
});

export default router;
