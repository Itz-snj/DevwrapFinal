/**
 * Project Phoenix — JSON Application Log Parser
 * 
 * Parses structured JSON logs in two formats:
 *   1. Newline-delimited JSON (NDJSON) — one JSON object per line
 *   2. Multi-line pretty-printed JSON — objects separated by blank lines or concatenated
 * 
 * These are typical of application services using structured logging frameworks
 * (Winston, Bunyan, Pino, etc.).
 * 
 * Expected fields (all optional, flexible mapping):
 *   timestamp, level, service, message, ip, method, endpoint, statusCode, ...
 */

import { NormalizedEvent } from '../schemas.js';
import { Deobfuscator } from '../deobfuscation/Deobfuscator.js';

/**
 * Map of common timestamp field names found in various JSON log formats.
 */
const TIMESTAMP_FIELDS = ['timestamp', 'time', 'date', 'datetime', '@timestamp', 'ts', 'created_at', 'logged_at'];
const IP_FIELDS = ['ip', 'remote_addr', 'client_ip', 'src_ip', 'source_ip', 'remote_ip', 'clientIp'];
const LEVEL_FIELDS = ['level', 'severity', 'loglevel', 'log_level', 'priority'];
const ENDPOINT_FIELDS = ['endpoint', 'path', 'url', 'uri', 'request_uri', 'route'];
const METHOD_FIELDS = ['method', 'http_method', 'request_method', 'verb'];
const STATUS_FIELDS = ['statusCode', 'status_code', 'status', 'http_status', 'response_code'];
const USER_FIELDS = ['user', 'username', 'userId', 'user_id', 'account'];
const MESSAGE_FIELDS = ['message', 'msg', 'text', 'description', 'log'];

/**
 * Find the first matching field from a list of candidate names.
 */
function findField(obj, candidates) {
  for (const key of candidates) {
    if (obj[key] !== undefined && obj[key] !== null && obj[key] !== '') {
      return obj[key];
    }
  }
  return undefined;
}

/**
 * Normalize log level strings to our standard set.
 */
function normalizeLogLevel(level) {
  if (!level) return 'info';
  
  const l = String(level).toLowerCase();
  if (['error', 'err', 'fatal', 'critical', 'crit', 'alert', 'emerg'].includes(l)) return 'error';
  if (['warn', 'warning'].includes(l)) return 'warn';
  if (['debug', 'trace', 'verbose'].includes(l)) return 'debug';
  return 'info';
}

/**
 * Extract individual JSON objects from content that may be:
 *   - NDJSON (one object per line)
 *   - Pretty-printed (multi-line objects separated by newlines)
 *   - A JSON array of objects
 * 
 * Returns an array of { jsonString, startLine } tuples.
 */
function extractJsonObjects(content) {
  const results = [];

  // Strategy 1: Try as a JSON array first
  const trimmed = content.trim();
  if (trimmed.startsWith('[')) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) {
        return arr.map((obj, i) => ({ obj, startLine: i + 1 }));
      }
    } catch {
      // Not a valid JSON array, fall through
    }
  }

  // Strategy 2: Try NDJSON (one object per line)
  const lines = content.split('\n');
  let ndjsonCount = 0;
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    try {
      const p = JSON.parse(t);
      if (typeof p === 'object' && p !== null) ndjsonCount++;
    } catch { /* skip */ }
  }

  // If >50% of non-empty lines are valid single-line JSON, treat as NDJSON
  const nonEmptyLines = lines.filter(l => l.trim()).length;
  if (nonEmptyLines > 0 && (ndjsonCount / nonEmptyLines) > 0.5) {
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (!t) continue;
      try {
        const obj = JSON.parse(t);
        if (typeof obj === 'object' && obj !== null) {
          results.push({ obj, startLine: i + 1 });
        }
      } catch { /* skip */ }
    }
    return results;
  }

  // Strategy 3: Multi-line JSON — brace-counting parser
  let depth = 0;
  let currentChunk = '';
  let chunkStartLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const t = line.trim();

    if (depth === 0 && t.startsWith('{')) {
      currentChunk = '';
      chunkStartLine = i + 1;
    }

    if (depth > 0 || t.startsWith('{')) {
      currentChunk += line + '\n';

      for (const ch of t) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }

      if (depth === 0 && currentChunk.trim()) {
        try {
          const obj = JSON.parse(currentChunk.trim());
          if (typeof obj === 'object' && obj !== null) {
            results.push({ obj, startLine: chunkStartLine });
          }
        } catch { /* malformed, skip */ }
        currentChunk = '';
      }
    }
  }

  return results;
}

export class JsonLogParser {
  constructor() {
    this.source = 'app';
    this.deobfuscator = new Deobfuscator();
  }

  /**
   * Check if content looks like JSON logs (NDJSON or multi-line).
   * @param {string[]} sampleLines
   * @returns {number} Confidence score 0-100.
   */
  static detect(sampleLines) {
    // Quick check: does the first non-empty line start with { or [ ?
    const firstNonEmpty = sampleLines.find(l => l.trim());
    if (!firstNonEmpty) return 0;
    const t = firstNonEmpty.trim();
    if (t.startsWith('{') || t.startsWith('[')) {
      // Looks like JSON — try to extract objects from the full joined content
      const joined = sampleLines.join('\n');
      const objects = extractJsonObjects(joined);
      return objects.length > 0 ? 80 : 10;
    }
    // Fallback: try each line individually (NDJSON)
    let matches = 0;
    for (const line of sampleLines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (typeof parsed === 'object' && parsed !== null) matches++;
      } catch { /* Not JSON */ }
    }
    return sampleLines.length > 0 ? Math.round((matches / sampleLines.length) * 100) : 0;
  }

  /**
   * Parse a single JSON log line.
   * @param {string} line
   * @param {number} lineNumber
   * @param {string} sourceFile
   * @returns {NormalizedEvent|null}
   */
  parseLine(line, lineNumber, sourceFile = '') {
    const trimmed = line.trim();
    if (!trimmed) return null;

    let obj;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      return null; // Not valid JSON
    }

    if (typeof obj !== 'object' || obj === null) return null;

    // Extract fields using flexible field mapping
    const timestamp = findField(obj, TIMESTAMP_FIELDS);
    const ip = findField(obj, IP_FIELDS) || '';
    const logLevel = normalizeLogLevel(findField(obj, LEVEL_FIELDS));
    const rawEndpoint = findField(obj, ENDPOINT_FIELDS) || '';
    const method = findField(obj, METHOD_FIELDS) || '';
    const statusCode = findField(obj, STATUS_FIELDS);
    const user = findField(obj, USER_FIELDS) || '';
    const message = findField(obj, MESSAGE_FIELDS) || '';

    // Deobfuscate endpoint
    const endpoint = this.deobfuscator.deobfuscateField(rawEndpoint);

    // Build metadata from all remaining fields
    const knownFields = new Set([
      ...TIMESTAMP_FIELDS, ...IP_FIELDS, ...LEVEL_FIELDS,
      ...ENDPOINT_FIELDS, ...METHOD_FIELDS, ...STATUS_FIELDS,
      ...USER_FIELDS, ...MESSAGE_FIELDS
    ]);
    const metadata = {};
    for (const [key, value] of Object.entries(obj)) {
      if (!knownFields.has(key)) {
        metadata[key] = value;
      }
    }
    metadata.message = message;
    if (rawEndpoint !== endpoint) {
      metadata.rawEndpoint = rawEndpoint;
    }

    return new NormalizedEvent({
      timestamp: timestamp ? new Date(timestamp) : new Date(),
      source: this.source,
      sourceFile,
      ip,
      method: method.toUpperCase(),
      endpoint,
      statusCode: statusCode ? parseInt(statusCode, 10) : null,
      logLevel,
      user,
      rawLine: trimmed,
      lineNumber,
      metadata
    });
  }

  /**
   * Parse a pre-extracted JSON object into a NormalizedEvent.
   * @param {Object} obj - Parsed JSON object.
   * @param {number} lineNumber
   * @param {string} sourceFile
   * @returns {NormalizedEvent|null}
   */
  parseObject(obj, lineNumber, sourceFile = '') {
    if (typeof obj !== 'object' || obj === null) return null;

    const timestamp = findField(obj, TIMESTAMP_FIELDS);
    const ip = findField(obj, IP_FIELDS) || '';
    const logLevel = normalizeLogLevel(findField(obj, LEVEL_FIELDS));
    const rawEndpoint = findField(obj, ENDPOINT_FIELDS) || '';
    const method = findField(obj, METHOD_FIELDS) || '';
    const statusCode = findField(obj, STATUS_FIELDS);
    const user = findField(obj, USER_FIELDS) || '';
    const message = findField(obj, MESSAGE_FIELDS) || '';

    const endpoint = this.deobfuscator.deobfuscateField(rawEndpoint);

    const knownFields = new Set([
      ...TIMESTAMP_FIELDS, ...IP_FIELDS, ...LEVEL_FIELDS,
      ...ENDPOINT_FIELDS, ...METHOD_FIELDS, ...STATUS_FIELDS,
      ...USER_FIELDS, ...MESSAGE_FIELDS
    ]);
    const metadata = {};
    for (const [key, value] of Object.entries(obj)) {
      if (!knownFields.has(key)) {
        metadata[key] = value;
      }
    }
    metadata.message = message;
    if (rawEndpoint !== endpoint) {
      metadata.rawEndpoint = rawEndpoint;
    }

    return new NormalizedEvent({
      timestamp: timestamp ? new Date(timestamp) : new Date(),
      source: this.source,
      sourceFile,
      ip,
      method: method ? method.toUpperCase() : '',
      endpoint,
      statusCode: statusCode ? parseInt(statusCode, 10) : null,
      logLevel,
      user,
      rawLine: JSON.stringify(obj),
      lineNumber,
      metadata
    });
  }

  /**
   * Parse entire file content (handles both NDJSON and multi-line JSON).
   * @param {string} content
   * @param {string} sourceFile
   * @returns {NormalizedEvent[]}
   */
  parse(content, sourceFile = '') {
    const jsonObjects = extractJsonObjects(content);
    const events = [];

    for (const { obj, startLine } of jsonObjects) {
      const event = this.parseObject(obj, startLine, sourceFile);
      if (event) events.push(event);
    }

    return events;
  }
}
