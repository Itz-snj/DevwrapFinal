/**
 * Project Phoenix — Core Schemas
 * 
 * Defines all data structures used throughout the processing pipeline.
 * Every log line from any source gets normalized into a NormalizedEvent.
 * The pipeline then produces Alerts, AttackerProfiles, and Incidents.
 */

/**
 * NormalizedEvent — The universal log entry format.
 * Every parser outputs events conforming to this shape.
 */
export class NormalizedEvent {
  constructor({
    timestamp,
    source,
    sourceFile = '',
    ip = '',
    method = '',
    endpoint = '',
    statusCode = null,
    logLevel = 'info',
    userAgent = '',
    user = '',
    rawLine = '',
    lineNumber = 0,
    metadata = {}
  }) {
    /** @type {Date} Parsed timestamp */
    this.timestamp = timestamp instanceof Date ? timestamp : new Date(timestamp);
    /** @type {string} Log source type: 'nginx' | 'auth' | 'app' */
    this.source = source;
    /** @type {string} Original filename */
    this.sourceFile = sourceFile;
    /** @type {string} Source IP address */
    this.ip = ip;
    /** @type {string} HTTP method or action */
    this.method = method;
    /** @type {string} Request endpoint / path / command */
    this.endpoint = endpoint;
    /** @type {number|null} HTTP status code (if applicable) */
    this.statusCode = statusCode;
    /** @type {string} Log level: 'info' | 'warn' | 'error' | 'debug' */
    this.logLevel = logLevel;
    /** @type {string} User-Agent string */
    this.userAgent = userAgent;
    /** @type {string} Username (if available) */
    this.user = user;
    /** @type {string} Original raw log line */
    this.rawLine = rawLine;
    /** @type {number} Line number in source file */
    this.lineNumber = lineNumber;
    /** @type {Object} Additional fields from the source log */
    this.metadata = metadata;
  }

  /**
   * Returns a unique key for deduplication.
   */
  getKey() {
    return `${this.timestamp.toISOString()}_${this.ip}_${this.endpoint}_${this.source}`;
  }

  /**
   * Serialize to plain object (for JSON responses).
   */
  toJSON() {
    return {
      timestamp: this.timestamp.toISOString(),
      source: this.source,
      sourceFile: this.sourceFile,
      ip: this.ip,
      method: this.method,
      endpoint: this.endpoint,
      statusCode: this.statusCode,
      logLevel: this.logLevel,
      userAgent: this.userAgent,
      user: this.user,
      rawLine: this.rawLine,
      lineNumber: this.lineNumber,
      metadata: this.metadata
    };
  }
}

/**
 * Alert — A detected suspicious pattern matched by the Regex Vault.
 */
export class Alert {
  constructor({
    id = '',
    ruleId,
    category,
    severity,
    description,
    matchedPattern = '',
    event = null
  }) {
    /** @type {string} Unique alert ID */
    this.id = id || `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    /** @type {string} Rule ID that triggered this alert */
    this.ruleId = ruleId;
    /** @type {string} Attack category: 'SQL Injection' | 'Brute Force' | 'Path Traversal' | ... */
    this.category = category;
    /** @type {string} Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' */
    this.severity = severity;
    /** @type {string} Human-readable description */
    this.description = description;
    /** @type {string} The matched pattern/substring */
    this.matchedPattern = matchedPattern;
    /** @type {NormalizedEvent|null} The event that triggered this alert */
    this.event = event;
  }

  toJSON() {
    return {
      id: this.id,
      ruleId: this.ruleId,
      category: this.category,
      severity: this.severity,
      description: this.description,
      matchedPattern: this.matchedPattern,
      event: this.event?.toJSON?.() || this.event
    };
  }
}

/**
 * AttackerProfile — Aggregated information about a single attacker IP.
 */
export class AttackerProfile {
  constructor({
    ip,
    threatScore = 0,
    totalRequests = 0,
    alerts = [],
    geo = null,
    userAgents = [],
    firstSeen = null,
    lastSeen = null,
    targetedEndpoints = [],
    attackTypes = []
  }) {
    /** @type {string} Attacker IP address */
    this.ip = ip;
    /** @type {number} Computed threat score (0-100) */
    this.threatScore = threatScore;
    /** @type {number} Total requests from this IP */
    this.totalRequests = totalRequests;
    /** @type {Alert[]} Alerts triggered by this IP */
    this.alerts = alerts;
    /** @type {Object|null} Geolocation data from IP intelligence */
    this.geo = geo;
    /** @type {string[]} Distinct user-agent strings */
    this.userAgents = userAgents;
    /** @type {Date|null} First event timestamp */
    this.firstSeen = firstSeen;
    /** @type {Date|null} Last event timestamp */
    this.lastSeen = lastSeen;
    /** @type {string[]} Endpoints targeted */
    this.targetedEndpoints = targetedEndpoints;
    /** @type {string[]} Types of attacks from this IP */
    this.attackTypes = attackTypes;
  }

  toJSON() {
    return {
      ip: this.ip,
      threatScore: this.threatScore,
      totalRequests: this.totalRequests,
      alerts: this.alerts.length,
      geo: this.geo,
      userAgents: this.userAgents,
      firstSeen: this.firstSeen?.toISOString?.() || this.firstSeen,
      lastSeen: this.lastSeen?.toISOString?.() || this.lastSeen,
      targetedEndpoints: this.targetedEndpoints,
      attackTypes: this.attackTypes
    };
  }
}

/**
 * AttackChain — A correlated sequence of events representing an attack progression.
 */
export class AttackChain {
  constructor({
    id = '',
    ip,
    events = [],
    alerts = [],
    threatScore = 0,
    startTime = null,
    endTime = null,
    description = ''
  }) {
    this.id = id || `chain_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    this.ip = ip;
    this.events = events;
    this.alerts = alerts;
    this.threatScore = threatScore;
    this.startTime = startTime;
    this.endTime = endTime;
    this.description = description;
  }

  toJSON() {
    return {
      id: this.id,
      ip: this.ip,
      events: this.events.map(e => e.toJSON?.() || e),
      alerts: this.alerts.map(a => a.toJSON?.() || a),
      threatScore: this.threatScore,
      startTime: this.startTime?.toISOString?.() || this.startTime,
      endTime: this.endTime?.toISOString?.() || this.endTime,
      description: this.description
    };
  }
}

/**
 * Incident — Top-level analysis result containing everything.
 */
export class Incident {
  constructor({
    id = '',
    createdAt = new Date(),
    status = 'analyzed',
    summary = {},
    events = [],
    alerts = [],
    attackers = [],
    attackChains = [],
    graphData = { nodes: [], edges: [] }
  }) {
    this.id = id || `inc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    this.createdAt = createdAt;
    this.status = status;
    this.summary = summary;
    this.events = events;
    this.alerts = alerts;
    this.attackers = attackers;
    this.attackChains = attackChains;
    this.graphData = graphData;
  }

  /**
   * Build summary statistics from internal data.
   */
  buildSummary() {
    const alertsBySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const alert of this.alerts) {
      if (alertsBySeverity[alert.severity] !== undefined) {
        alertsBySeverity[alert.severity]++;
      }
    }

    const attackTypeMap = new Map();
    for (const alert of this.alerts) {
      if (!attackTypeMap.has(alert.category)) {
        attackTypeMap.set(alert.category, { type: alert.category, count: 0, severity: alert.severity });
      }
      attackTypeMap.get(alert.category).count++;
    }

    const timestamps = this.events.map(e => e.timestamp).filter(Boolean);
    const topAttacker = this.attackers.sort((a, b) => b.threatScore - a.threatScore)[0];

    this.summary = {
      totalEvents: this.events.length,
      totalAlerts: this.alerts.length,
      threatScore: topAttacker?.threatScore || 0,
      timeRange: {
        start: timestamps.length ? new Date(Math.min(...timestamps)).toISOString() : null,
        end: timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : null
      },
      topAttackerIp: topAttacker?.ip || null,
      attackTypes: [...attackTypeMap.values()],
      alertsBySeverity
    };

    return this.summary;
  }

  toJSON() {
    return {
      id: this.id,
      createdAt: this.createdAt.toISOString(),
      status: this.status,
      summary: this.summary,
      attackers: this.attackers.map(a => a.toJSON?.() || a),
      alertsBySeverity: this.summary.alertsBySeverity,
      attackTypes: this.summary.attackTypes
    };
  }
}

/**
 * Severity weights for threat score calculation.
 */
export const SEVERITY_WEIGHTS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3
};

/**
 * Severity levels in order.
 */
export const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
