/**
 * Project Phoenix — Nginx Access Log Parser
 * 
 * Parses the standard Nginx combined log format:
 * $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
 * 
 * Example:
 * 192.168.1.105 - - [25/Apr/2026:08:02:15 +0000] "GET /admin HTTP/1.1" 403 256 "-" "Mozilla/5.0..."
 */

import { NormalizedEvent } from '../schemas.js';
import { Deobfuscator } from '../deobfuscation/Deobfuscator.js';

// Nginx combined log format regex
const NGINX_LOG_REGEX = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/;

/**
 * Parse Nginx date format: 25/Apr/2026:08:02:15 +0000 → Date
 */
function parseNginxDate(dateStr) {
  const months = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
  };

  // Format: 25/Apr/2026:08:02:15 +0000
  const match = dateStr.match(/(\d+)\/(\w+)\/(\d+):(\d+):(\d+):(\d+)\s+([+-]\d{4})/);
  if (!match) return new Date(dateStr); // Fallback

  const [, day, monthStr, year, hour, minute, second, tz] = match;
  const month = months[monthStr];
  
  // Build ISO string with timezone
  const tzSign = tz[0];
  const tzHours = tz.slice(1, 3);
  const tzMins = tz.slice(3, 5);
  const isoStr = `${year}-${String(month + 1).padStart(2, '0')}-${day.padStart(2, '0')}T${hour}:${minute}:${second}${tzSign}${tzHours}:${tzMins}`;
  
  return new Date(isoStr);
}

export class NginxParser {
  constructor() {
    this.source = 'nginx';
    this.deobfuscator = new Deobfuscator();
  }

  /**
   * Check if content looks like Nginx access logs.
   * @param {string[]} sampleLines - First few lines of the file.
   * @returns {number} Confidence score 0-100.
   */
  static detect(sampleLines) {
    let matches = 0;
    for (const line of sampleLines) {
      if (NGINX_LOG_REGEX.test(line)) matches++;
    }
    return Math.round((matches / sampleLines.length) * 100);
  }

  /**
   * Parse a single Nginx log line.
   * @param {string} line - Raw log line.
   * @param {number} lineNumber - Line number in source file.
   * @param {string} sourceFile - Source filename.
   * @returns {NormalizedEvent|null}
   */
  parseLine(line, lineNumber, sourceFile = '') {
    const trimmed = line.trim();
    if (!trimmed) return null;

    const match = trimmed.match(NGINX_LOG_REGEX);
    if (!match) return null;

    const [, ip, user, dateStr, method, rawEndpoint, status, bodyBytes, referer, userAgent] = match;

    // Deobfuscate the endpoint (may contain URL-encoded attacks)
    const endpoint = this.deobfuscator.deobfuscateField(rawEndpoint);

    return new NormalizedEvent({
      timestamp: parseNginxDate(dateStr),
      source: this.source,
      sourceFile,
      ip,
      method,
      endpoint,
      statusCode: parseInt(status, 10),
      logLevel: parseInt(status, 10) >= 400 ? 'warn' : 'info',
      userAgent,
      user: user === '-' ? '' : user,
      rawLine: trimmed,
      lineNumber,
      metadata: {
        bodyBytes: parseInt(bodyBytes, 10),
        referer: referer === '-' ? '' : referer,
        rawEndpoint // Keep the original encoded endpoint
      }
    });
  }

  /**
   * Parse entire file content.
   * @param {string} content - Full file content.
   * @param {string} sourceFile - Source filename.
   * @returns {NormalizedEvent[]}
   */
  parse(content, sourceFile = '') {
    const lines = content.split('\n');
    const events = [];

    for (let i = 0; i < lines.length; i++) {
      const event = this.parseLine(lines[i], i + 1, sourceFile);
      if (event) events.push(event);
    }

    return events;
  }
}
