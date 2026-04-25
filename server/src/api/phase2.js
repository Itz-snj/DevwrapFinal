/**
 * Project Phoenix — Phase 2 API Routes
 * 
 * Exposes the detection engine, correlation engine, and IP enrichment
 * via REST endpoints. Also provides a full analysis pipeline endpoint.
 */

import { Router } from 'express';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { ParserFactory } from '../pipeline/ingestion/ParserFactory.js';
import { RuleEngine } from '../pipeline/detection/RuleEngine.js';
import { CorrelationEngine } from '../pipeline/correlation/CorrelationEngine.js';
import { IpEnricher } from '../pipeline/enrichment/IpEnricher.js';
import { Incident } from '../pipeline/schemas.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const router = Router();
const factory = new ParserFactory();
const ruleEngine = new RuleEngine();
const correlationEngine = new CorrelationEngine();
const ipEnricher = new IpEnricher();

const SAMPLE_DIR = join(__dirname, '../../../sample-logs');
const VALID_SAMPLES = ['nginx-access.log', 'auth.log', 'app-events.json'];

// Uses shared IncidentStore (injected via app.set in server.js)
function getStore(req) {
  return req.app.get('incidentStore');
}

// ─── GET /api/rules ────────────────────────────────────────────────
router.get('/rules', (req, res) => {
  const stats = ruleEngine.getStats();
  res.json(stats);
});

// ─── POST /api/detect-threats ──────────────────────────────────────
router.post('/detect-threats', (req, res) => {
  const { content, format, sourceFile = '' } = req.body;

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'Missing required field: content (string)' });
  }

  try {
    // Parse
    let events;
    if (format) {
      events = factory.parseWithFormat(format, content, sourceFile);
    } else {
      events = factory.parseAuto(content, sourceFile).events;
    }

    // Detect
    const { alerts } = ruleEngine.detectAll(events);

    // Group alerts by category
    const byCategory = {};
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const alert of alerts) {
      byCategory[alert.category] = (byCategory[alert.category] || 0) + 1;
      bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
    }

    res.json({
      totalEvents: events.length,
      totalAlerts: alerts.length,
      alertsBySeverity: bySeverity,
      alertsByCategory: byCategory,
      alerts: alerts.map(a => a.toJSON())
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── POST /api/correlate ───────────────────────────────────────────
router.post('/correlate', (req, res) => {
  const { content, format, sourceFile = '', windowSeconds } = req.body;

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'Missing required field: content (string)' });
  }

  try {
    // Parse
    let events;
    if (format) {
      events = factory.parseWithFormat(format, content, sourceFile);
    } else {
      events = factory.parseAuto(content, sourceFile).events;
    }

    // Detect
    const { alerts } = ruleEngine.detectAll(events);

    // Correlate
    const engine = windowSeconds
      ? new CorrelationEngine({ windowSeconds })
      : correlationEngine;

    const result = engine.correlate(events, alerts);

    res.json({
      totalEvents: events.length,
      totalAlerts: alerts.length,
      attackers: result.attackers.map(a => a.toJSON()),
      attackChains: result.attackChains.map(c => c.toJSON()),
      correlationAlerts: result.correlationAlerts,
      graphData: result.graphData
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── POST /api/analyze/full ────────────────────────────────────────
// Full pipeline: Parse → Detect → Correlate → Enrich → Store
router.post('/analyze/full', async (req, res) => {
  const { content, format, sourceFile = '', enrichIps = true } = req.body;

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'Missing required field: content (string)' });
  }

  try {
    // 1. Parse
    let events, detectedFormat;
    if (format) {
      events = factory.parseWithFormat(format, content, sourceFile);
      detectedFormat = format;
    } else {
      const result = factory.parseAuto(content, sourceFile);
      events = result.events;
      detectedFormat = result.format;
    }

    // 2. Detect
    const { alerts } = ruleEngine.detectAll(events);

    // 3. Correlate
    const { attackers, attackChains, graphData, correlationAlerts } = correlationEngine.correlate(events, alerts);

    // 4. Enrich (optional)
    if (enrichIps && attackers.length > 0) {
      await ipEnricher.enrichAttackers(attackers);
    }

    // 5. Build incident
    const incident = new Incident({
      events,
      alerts,
      attackers,
      attackChains,
      graphData
    });
    incident.buildSummary();

    // 6. Store (persistent)
    const store = getStore(req);
    if (store) store.save(incident);

    res.json({
      incidentId: incident.id,
      format: detectedFormat,
      summary: incident.summary,
      attackers: attackers.map(a => ({
        ...a.toJSON(),
        isp: a.isp,
        org: a.org,
        as: a.as
      })),
      attackChains: attackChains.map(c => c.toJSON()),
      correlationAlerts,
      graphData,
      alertsBySeverity: incident.summary.alertsBySeverity
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── GET /api/analyze/sample ───────────────────────────────────────
// Run full pipeline on a bundled sample log
router.get('/analyze/sample', async (req, res) => {
  const { file, enrichIps = 'false' } = req.query;

  if (!file || !VALID_SAMPLES.includes(file)) {
    return res.status(400).json({
      error: `Invalid sample file. Choose one of: ${VALID_SAMPLES.join(', ')}`,
      available: VALID_SAMPLES
    });
  }

  try {
    const content = readFileSync(join(SAMPLE_DIR, file), 'utf-8');
    const { events, format } = factory.parseAuto(content, file);
    const { alerts } = ruleEngine.detectAll(events);
    const { attackers, attackChains, graphData, correlationAlerts } = correlationEngine.correlate(events, alerts);

    if (enrichIps === 'true') {
      await ipEnricher.enrichAttackers(attackers);
    }

    const incident = new Incident({ events, alerts, attackers, attackChains, graphData });
    incident.buildSummary();
    const store = getStore(req);
    if (store) store.save(incident);

    res.json({
      incidentId: incident.id,
      filename: file,
      format,
      summary: incident.summary,
      attackers: attackers.map(a => ({
        ...a.toJSON(),
        isp: a.isp,
        org: a.org
      })),
      attackChains: attackChains.map(c => c.toJSON()),
      correlationAlerts,
      graphData,
      alertsBySeverity: incident.summary.alertsBySeverity
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── GET /api/ip/:address ──────────────────────────────────────────
router.get('/ip/:address', async (req, res) => {
  const { address } = req.params;

  try {
    const data = await ipEnricher.enrich(address);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/ip-cache/stats ───────────────────────────────────────
router.get('/ip-cache/stats', (req, res) => {
  res.json(ipEnricher.getCacheStats());
});

export default router;
