/**
 * Project Phoenix — Auth Log Parser
 * 
 * Parses Linux authentication logs (syslog format) from /var/log/auth.log.
 * Handles sshd, sudo, pam_unix, and other auth-related messages.
 * 
 * Format: Month Day HH:MM:SS hostname service[pid]: message
 * Example: Apr 25 08:02:10 server sshd[1234]: Failed password for admin from 192.168.1.105 port 22 ssh2
 */

import { NormalizedEvent } from '../schemas.js';

// Syslog base format regex
const SYSLOG_REGEX = /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)$/;

// Specific message patterns for field extraction
const PATTERNS = {
  failedPassword: /Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)/,
  acceptedPassword: /Accepted password for (\S+) from (\S+) port (\d+)/,
  acceptedPublickey: /Accepted publickey for (\S+) from (\S+) port (\d+)/,
  maxAttempts: /maximum authentication attempts exceeded for (\S+) from (\S+) port (\d+)/,
  disconnecting: /Disconnecting (?:authenticating )?user (\S+) (\S+) port (\d+)/,
  sessionOpened: /pam_unix\(\S+\):\s+session opened for user (\S+)/,
  sessionClosed: /pam_unix\(\S+\):\s+session closed for user (\S+)/,
  authFailure: /pam_unix\(\S+\):\s+authentication failure;.*ruser=(\S*).*rhost=(\S*)\s+user=(\S+)/,
  sudoCommand: /(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)$/
};

/**
 * Parse syslog date into a Date object.
 * Note: syslog doesn't include year, so we assume current year.
 */
function parseSyslogDate(month, day, hour, minute, second) {
  const months = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
  };

  const now = new Date();
  const date = new Date(now.getFullYear(), months[month], parseInt(day), parseInt(hour), parseInt(minute), parseInt(second));
  
  // If the parsed date is in the future, it's probably from last year
  if (date > now) {
    date.setFullYear(date.getFullYear() - 1);
  }
  
  return date;
}

/**
 * Extract structured fields from the syslog message based on pattern matching.
 */
function extractFields(message, service) {
  const fields = {
    ip: '',
    user: '',
    method: '',
    endpoint: '',
    statusCode: null,
    logLevel: 'info',
    metadata: {}
  };

  // Failed password
  let match = message.match(PATTERNS.failedPassword);
  if (match) {
    fields.user = match[1];
    fields.ip = match[2];
    fields.method = 'AUTH';
    fields.endpoint = '/login';
    fields.statusCode = 401;
    fields.logLevel = 'warn';
    fields.metadata.authResult = 'failed';
    fields.metadata.port = parseInt(match[3]);
    return fields;
  }

  // Accepted password
  match = message.match(PATTERNS.acceptedPassword);
  if (match) {
    fields.user = match[1];
    fields.ip = match[2];
    fields.method = 'AUTH';
    fields.endpoint = '/login';
    fields.statusCode = 200;
    fields.logLevel = 'info';
    fields.metadata.authResult = 'success';
    fields.metadata.authMethod = 'password';
    fields.metadata.port = parseInt(match[3]);
    return fields;
  }

  // Accepted publickey
  match = message.match(PATTERNS.acceptedPublickey);
  if (match) {
    fields.user = match[1];
    fields.ip = match[2];
    fields.method = 'AUTH';
    fields.endpoint = '/login';
    fields.statusCode = 200;
    fields.logLevel = 'info';
    fields.metadata.authResult = 'success';
    fields.metadata.authMethod = 'publickey';
    fields.metadata.port = parseInt(match[3]);
    return fields;
  }

  // Maximum attempts exceeded
  match = message.match(PATTERNS.maxAttempts);
  if (match) {
    fields.user = match[1];
    fields.ip = match[2];
    fields.method = 'AUTH';
    fields.endpoint = '/login';
    fields.statusCode = 429;
    fields.logLevel = 'error';
    fields.metadata.authResult = 'max_attempts';
    fields.metadata.port = parseInt(match[3]);
    return fields;
  }

  // Disconnecting user
  match = message.match(PATTERNS.disconnecting);
  if (match) {
    fields.user = match[1];
    fields.ip = match[2];
    fields.method = 'AUTH';
    fields.endpoint = '/login';
    fields.statusCode = 403;
    fields.logLevel = 'warn';
    fields.metadata.authResult = 'disconnected';
    return fields;
  }

  // Sudo command
  match = message.match(PATTERNS.sudoCommand);
  if (match) {
    fields.user = match[1];
    fields.method = 'SUDO';
    fields.endpoint = match[4]; // The command executed
    fields.logLevel = 'warn';
    fields.metadata.pwd = match[2];
    fields.metadata.targetUser = match[3];
    fields.metadata.command = match[4];
    return fields;
  }

  // Session opened
  match = message.match(PATTERNS.sessionOpened);
  if (match) {
    fields.user = match[1];
    fields.method = 'SESSION';
    fields.endpoint = '/session/open';
    fields.statusCode = 200;
    fields.metadata.sessionAction = 'opened';
    return fields;
  }

  // Session closed
  match = message.match(PATTERNS.sessionClosed);
  if (match) {
    fields.user = match[1];
    fields.method = 'SESSION';
    fields.endpoint = '/session/close';
    fields.statusCode = 200;
    fields.metadata.sessionAction = 'closed';
    return fields;
  }

  // Auth failure (PAM)
  match = message.match(PATTERNS.authFailure);
  if (match) {
    fields.user = match[3];
    fields.ip = match[2] || '';
    fields.method = 'AUTH';
    fields.endpoint = '/login';
    fields.statusCode = 401;
    fields.logLevel = 'warn';
    fields.metadata.authResult = 'pam_failure';
    return fields;
  }

  // Fallback: unrecognized message
  fields.metadata.rawMessage = message;
  fields.logLevel = 'info';
  return fields;
}

export class AuthLogParser {
  constructor() {
    this.source = 'auth';
  }

  /**
   * Check if content looks like auth.log (syslog format).
   * @param {string[]} sampleLines
   * @returns {number} Confidence score 0-100.
   */
  static detect(sampleLines) {
    let matches = 0;
    for (const line of sampleLines) {
      if (SYSLOG_REGEX.test(line)) matches++;
    }
    return Math.round((matches / sampleLines.length) * 100);
  }

  /**
   * Parse a single auth.log line.
   * @param {string} line
   * @param {number} lineNumber
   * @param {string} sourceFile
   * @returns {NormalizedEvent|null}
   */
  parseLine(line, lineNumber, sourceFile = '') {
    const trimmed = line.trim();
    if (!trimmed) return null;

    const match = trimmed.match(SYSLOG_REGEX);
    if (!match) return null;

    const [, month, day, hour, minute, second, hostname, service, pid, message] = match;

    const timestamp = parseSyslogDate(month, day, hour, minute, second);
    const fields = extractFields(message, service);

    return new NormalizedEvent({
      timestamp,
      source: this.source,
      sourceFile,
      ip: fields.ip,
      method: fields.method,
      endpoint: fields.endpoint,
      statusCode: fields.statusCode,
      logLevel: fields.logLevel,
      user: fields.user,
      rawLine: trimmed,
      lineNumber,
      metadata: {
        ...fields.metadata,
        hostname,
        service,
        pid: pid ? parseInt(pid) : null,
        message
      }
    });
  }

  /**
   * Parse entire file content.
   * @param {string} content
   * @param {string} sourceFile
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
