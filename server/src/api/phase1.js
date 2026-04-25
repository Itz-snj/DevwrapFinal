/**
 * Project Phoenix — Phase 1 API Routes
 * 
 * Exposes the parsing, format detection, and deobfuscation
 * pipeline via REST endpoints.
 */

import { Router } from 'express';
import multer from 'multer';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { ParserFactory } from '../pipeline/ingestion/ParserFactory.js';
import { Deobfuscator } from '../pipeline/deobfuscation/Deobfuscator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const router = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB max
const factory = new ParserFactory();
const deobfuscator = new Deobfuscator();

const SAMPLE_DIR = join(__dirname, '../../../sample-logs');
const VALID_SAMPLES = ['nginx-access.log', 'auth.log', 'app-events.json'];

// ─── GET /api/formats ──────────────────────────────────────────────
router.get('/formats', (req, res) => {
  res.json({ formats: factory.getSupportedFormats() });
});

// ─── POST /api/detect ──────────────────────────────────────────────
router.post('/detect', (req, res) => {
  const { content } = req.body;

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'Missing required field: content (string)' });
  }

  try {
    const { format, confidence } = factory.detect(content);
    res.json({ format, confidence });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── POST /api/parse ───────────────────────────────────────────────
router.post('/parse', (req, res) => {
  const { content, format, sourceFile = '' } = req.body;

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'Missing required field: content (string)' });
  }

  try {
    let events, detectedFormat, confidence;

    if (format) {
      // Manual format specified
      events = factory.parseWithFormat(format, content, sourceFile);
      detectedFormat = format;
      confidence = 100;
    } else {
      // Auto-detect
      const result = factory.parseAuto(content, sourceFile);
      events = result.events;
      detectedFormat = result.format;
      confidence = result.confidence;
    }

    res.json({
      format: detectedFormat,
      confidence,
      totalEvents: events.length,
      events: events.map(e => e.toJSON())
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── POST /api/parse/file ──────────────────────────────────────────
router.post('/parse/file', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded. Use form field name "file".' });
  }

  const content = req.file.buffer.toString('utf-8');
  const filename = req.file.originalname;
  const manualFormat = req.body?.format;

  try {
    let events, detectedFormat, confidence;

    if (manualFormat) {
      events = factory.parseWithFormat(manualFormat, content, filename);
      detectedFormat = manualFormat;
      confidence = 100;
    } else {
      const result = factory.parseAuto(content, filename);
      events = result.events;
      detectedFormat = result.format;
      confidence = result.confidence;
    }

    res.json({
      filename,
      format: detectedFormat,
      confidence,
      totalEvents: events.length,
      events: events.map(e => e.toJSON())
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── POST /api/deobfuscate ─────────────────────────────────────────
router.post('/deobfuscate', (req, res) => {
  const { input } = req.body;

  if (!input || typeof input !== 'string') {
    return res.status(400).json({ error: 'Missing required field: input (string)' });
  }

  const output = deobfuscator.deobfuscate(input);
  res.json({
    input,
    output,
    changed: input !== output
  });
});

// ─── GET /api/parse/sample ─────────────────────────────────────────
router.get('/parse/sample', (req, res) => {
  const { file } = req.query;

  if (!file || !VALID_SAMPLES.includes(file)) {
    return res.status(400).json({
      error: `Invalid sample file. Choose one of: ${VALID_SAMPLES.join(', ')}`,
      available: VALID_SAMPLES
    });
  }

  try {
    const content = readFileSync(join(SAMPLE_DIR, file), 'utf-8');
    const { events, format, confidence } = factory.parseAuto(content, file);

    res.json({
      filename: file,
      format,
      confidence,
      totalEvents: events.length,
      events: events.map(e => e.toJSON())
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

export default router;
