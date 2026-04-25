/**
 * Project Phoenix — Correlation Engine
 * 
 * Merges events from all log sources, groups by IP, applies sliding
 * window analysis, builds attack chains, and computes threat scores.
 * 
 * Pipeline: Events → Sort by time → Group by IP → Window analysis → 
 *           Attack chains → Threat scores → Graph data
 */

import { AttackerProfile, AttackChain, SEVERITY_WEIGHTS } from '../schemas.js';

/**
 * Default correlation configuration.
 */
const DEFAULT_CONFIG = {
  windowSeconds: 300,          // 5-minute sliding window
  minAlertsForChain: 2,        // Minimum alerts to form an attack chain
  maxThreatScore: 100,         // Score cap
  sourceDiversityBonus: 10     // Bonus per additional log source involved
};

/**
 * Correlation rules — detect specific multi-event attack patterns.
 */
const CORRELATION_PATTERNS = [
  {
    id: 'CORR_CREDENTIAL_STUFFING',
    name: 'Credential Stuffing',
    description: 'Failed logins followed by successful login from same IP',
    detect: (events) => {
      const failedLogins = events.filter(e => e.statusCode === 401);
      const successLogins = events.filter(e => e.statusCode === 200 && e.endpoint?.includes('login'));
      if (failedLogins.length >= 3 && successLogins.length > 0) {
        const lastFailed = failedLogins[failedLogins.length - 1];
        const firstSuccess = successLogins[0];
        if (firstSuccess.timestamp > lastFailed.timestamp) {
          return { matched: true, severity: 'CRITICAL', description: `${failedLogins.length} failed logins then successful login` };
        }
      }
      return { matched: false };
    }
  },
  {
    id: 'CORR_UNAUTHORIZED_ACCESS',
    name: 'Unauthorized Access Attempt',
    description: 'Failed login followed by access to restricted resources',
    detect: (events) => {
      const failedLogins = events.filter(e => e.statusCode === 401);
      const forbidden = events.filter(e => e.statusCode === 403);
      if (failedLogins.length >= 1 && forbidden.length >= 1) {
        return { matched: true, severity: 'HIGH', description: `${failedLogins.length} failed logins + ${forbidden.length} forbidden accesses` };
      }
      return { matched: false };
    }
  },
  {
    id: 'CORR_SUCCESSFUL_TRAVERSAL',
    name: 'Successful Path Traversal',
    description: 'Path traversal attempt with 200 status — possible file access',
    detect: (events) => {
      const traversals = events.filter(e => 
        e.statusCode === 200 && 
        (e.endpoint?.includes('../') || e.endpoint?.includes('/etc/'))
      );
      if (traversals.length > 0) {
        return { matched: true, severity: 'CRITICAL', description: `${traversals.length} successful path traversal(s)` };
      }
      return { matched: false };
    }
  },
  {
    id: 'CORR_DATA_EXFILTRATION',
    name: 'Potential Data Exfiltration',
    description: 'Successful access to data endpoints after attack attempts',
    detect: (events, alerts) => {
      const hasAttackAlerts = alerts.length > 0;
      const dataAccess = events.filter(e => 
        e.statusCode === 200 && 
        (e.endpoint?.includes('/api/users') || e.endpoint?.includes('/api/data') || e.endpoint?.includes('/export'))
      );
      if (hasAttackAlerts && dataAccess.length > 0) {
        return { matched: true, severity: 'CRITICAL', description: `Data endpoint accessed after ${alerts.length} attack alerts` };
      }
      return { matched: false };
    }
  }
];

export class CorrelationEngine {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.correlationPatterns = CORRELATION_PATTERNS;
  }

  /**
   * Run the full correlation pipeline.
   * @param {NormalizedEvent[]} events - All events from all sources.
   * @param {Alert[]} alerts - All alerts from detection phase.
   * @returns {{ attackers: AttackerProfile[], attackChains: AttackChain[], graphData: Object, correlationAlerts: Object[] }}
   */
  correlate(events, alerts) {
    // 1. Sort all events by timestamp
    const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);

    // 2. Group by IP
    const ipGroups = this.groupByIp(sorted);

    // 3. Map alerts to IPs
    const alertsByIp = new Map();
    for (const alert of alerts) {
      const ip = alert.event?.ip || 'unknown';
      if (!alertsByIp.has(ip)) alertsByIp.set(ip, []);
      alertsByIp.get(ip).push(alert);
    }

    // 4. Build attacker profiles and attack chains
    const attackers = [];
    const attackChains = [];
    const correlationAlerts = [];

    for (const [ip, ipEvents] of ipGroups) {
      const ipAlerts = alertsByIp.get(ip) || [];
      
      // Skip IPs with no alerts (benign traffic)
      if (ipAlerts.length === 0) continue;

      // Run correlation patterns
      const corrResults = this.runCorrelationPatterns(ipEvents, ipAlerts);
      correlationAlerts.push(...corrResults);

      // Build attack chains using sliding window
      const chains = this.buildAttackChains(ip, ipEvents, ipAlerts);
      attackChains.push(...chains);

      // Build attacker profile
      const profile = this.buildAttackerProfile(ip, ipEvents, ipAlerts, chains, corrResults);
      attackers.push(profile);
    }

    // 5. Sort attackers by threat score (highest first)
    attackers.sort((a, b) => b.threatScore - a.threatScore);

    // 6. Build graph data for blast radius visualization
    const graphData = this.buildGraphData(attackers, events, alerts);

    return { attackers, attackChains, graphData, correlationAlerts };
  }

  /**
   * Group events by IP address.
   * @param {NormalizedEvent[]} events
   * @returns {Map<string, NormalizedEvent[]>}
   */
  groupByIp(events) {
    const groups = new Map();
    for (const event of events) {
      const ip = event.ip || 'unknown';
      if (!groups.has(ip)) groups.set(ip, []);
      groups.get(ip).push(event);
    }
    return groups;
  }

  /**
   * Run multi-event correlation patterns against an IP's events.
   */
  runCorrelationPatterns(events, alerts) {
    const results = [];
    for (const pattern of this.correlationPatterns) {
      const result = pattern.detect(events, alerts);
      if (result.matched) {
        results.push({
          patternId: pattern.id,
          name: pattern.name,
          severity: result.severity,
          description: result.description
        });
      }
    }
    return results;
  }

  /**
   * Build attack chains using sliding window analysis.
   * An attack chain is a sequence of suspicious events from the same IP
   * within the configured time window.
   */
  buildAttackChains(ip, events, alerts) {
    const chains = [];
    const alertEventKeys = new Set(alerts.map(a => a.event?.getKey?.()));

    // Find events that triggered alerts
    const suspiciousEvents = events.filter(e => {
      if (alertEventKeys.has(e.getKey())) return true;
      if (e.statusCode === 401 || e.statusCode === 403) return true;
      return false;
    });

    if (suspiciousEvents.length < this.config.minAlertsForChain) return chains;

    // Group into chains using sliding window
    let chainEvents = [suspiciousEvents[0]];
    let chainAlerts = alerts.filter(a => a.event?.getKey?.() === suspiciousEvents[0].getKey());

    for (let i = 1; i < suspiciousEvents.length; i++) {
      const timeDiff = suspiciousEvents[i].timestamp - chainEvents[chainEvents.length - 1].timestamp;

      if (timeDiff <= this.config.windowSeconds * 1000) {
        // Within window — extend chain
        chainEvents.push(suspiciousEvents[i]);
        const evtAlerts = alerts.filter(a => a.event?.getKey?.() === suspiciousEvents[i].getKey());
        chainAlerts.push(...evtAlerts);
      } else {
        // Window expired — finalize current chain and start new one
        if (chainEvents.length >= this.config.minAlertsForChain) {
          chains.push(this._createChain(ip, chainEvents, chainAlerts));
        }
        chainEvents = [suspiciousEvents[i]];
        chainAlerts = alerts.filter(a => a.event?.getKey?.() === suspiciousEvents[i].getKey());
      }
    }

    // Finalize last chain
    if (chainEvents.length >= this.config.minAlertsForChain) {
      chains.push(this._createChain(ip, chainEvents, chainAlerts));
    }

    return chains;
  }

  /**
   * Create an AttackChain instance from events and alerts.
   */
  _createChain(ip, events, alerts) {
    const categories = [...new Set(alerts.map(a => a.category))];
    const description = categories.length > 0
      ? `Attack chain: ${categories.join(' → ')}`
      : `Suspicious activity chain (${events.length} events)`;

    return new AttackChain({
      ip,
      events,
      alerts,
      threatScore: this.computeThreatScore(events, alerts),
      startTime: events[0].timestamp,
      endTime: events[events.length - 1].timestamp,
      description
    });
  }

  /**
   * Build an AttackerProfile for a single IP.
   */
  buildAttackerProfile(ip, events, alerts, chains, correlations) {
    const timestamps = events.map(e => e.timestamp).filter(Boolean);
    const endpoints = [...new Set(events.map(e => e.endpoint).filter(Boolean))];
    const userAgents = [...new Set(events.map(e => e.userAgent).filter(Boolean))];
    const attackTypes = [...new Set(alerts.map(a => a.category))];

    return new AttackerProfile({
      ip,
      threatScore: this.computeThreatScore(events, alerts, correlations),
      totalRequests: events.length,
      alerts,
      userAgents,
      firstSeen: timestamps.length ? new Date(Math.min(...timestamps)) : null,
      lastSeen: timestamps.length ? new Date(Math.max(...timestamps)) : null,
      targetedEndpoints: endpoints,
      attackTypes
    });
  }

  /**
   * Compute threat score (0-100) based on alerts, severity, and source diversity.
   */
  computeThreatScore(events, alerts, correlations = []) {
    let score = 0;

    // Base score from alerts × severity weight
    for (const alert of alerts) {
      score += SEVERITY_WEIGHTS[alert.severity] || 3;
    }

    // Source diversity bonus (events from multiple log sources)
    const sources = new Set(events.map(e => e.source));
    score += (sources.size - 1) * this.config.sourceDiversityBonus;

    // Correlation pattern bonus
    for (const corr of correlations) {
      score += SEVERITY_WEIGHTS[corr.severity] || 5;
    }

    // Successful attack bonus (200 status on suspicious endpoints)
    const successfulAttacks = events.filter(e =>
      e.statusCode === 200 &&
      (e.endpoint?.includes('../') || e.endpoint?.includes('/etc/') || e.endpoint?.includes('UNION'))
    );
    score += successfulAttacks.length * 15;

    return Math.min(score, this.config.maxThreatScore);
  }

  /**
   * Build graph data for blast radius visualization.
   * Nodes: attacker IPs, endpoints, resources
   * Edges: attacker → endpoint, endpoint → resource
   */
  buildGraphData(attackers, events, alerts) {
    const nodes = [];
    const edges = [];
    const nodeIds = new Set();
    const edgeKeys = new Set();

    for (const attacker of attackers) {
      // Add attacker node
      const attackerNodeId = `ip_${attacker.ip}`;
      if (!nodeIds.has(attackerNodeId)) {
        nodes.push({
          id: attackerNodeId,
          type: 'attacker',
          label: attacker.ip,
          threatScore: attacker.threatScore,
          geo: attacker.geo
        });
        nodeIds.add(attackerNodeId);
      }

      // Get this attacker's events
      const attackerEvents = events.filter(e => e.ip === attacker.ip);

      // Group by endpoint
      const endpointGroups = new Map();
      for (const event of attackerEvents) {
        if (!event.endpoint) continue;
        const ep = event.endpoint;
        if (!endpointGroups.has(ep)) endpointGroups.set(ep, []);
        endpointGroups.get(ep).push(event);
      }

      for (const [endpoint, epEvents] of endpointGroups) {
        const endpointNodeId = `ep_${endpoint}`;
        const epAlerts = alerts.filter(a => a.event?.ip === attacker.ip && a.event?.endpoint === endpoint);
        const maxSeverity = this._getMaxSeverity(epAlerts);

        // Add endpoint node
        if (!nodeIds.has(endpointNodeId)) {
          nodes.push({
            id: endpointNodeId,
            type: 'endpoint',
            label: endpoint,
            requestCount: epEvents.length,
            severity: maxSeverity
          });
          nodeIds.add(endpointNodeId);
        }

        // Add edge: attacker → endpoint
        const edgeKey = `${attackerNodeId}->${endpointNodeId}`;
        if (!edgeKeys.has(edgeKey)) {
          edges.push({
            source: attackerNodeId,
            target: endpointNodeId,
            weight: epEvents.length,
            severity: maxSeverity
          });
          edgeKeys.add(edgeKey);
        }

        // Check if endpoint implies resource access (200 on sensitive paths)
        const successfulAccess = epEvents.filter(e => e.statusCode === 200);
        if (successfulAccess.length > 0 && epAlerts.length > 0) {
          const resourceLabel = endpoint.split('/').pop() || endpoint;
          const resourceNodeId = `res_${resourceLabel}`;

          if (!nodeIds.has(resourceNodeId)) {
            nodes.push({
              id: resourceNodeId,
              type: 'resource',
              label: resourceLabel,
              severity: 'CRITICAL'
            });
            nodeIds.add(resourceNodeId);
          }

          const resEdgeKey = `${endpointNodeId}->${resourceNodeId}`;
          if (!edgeKeys.has(resEdgeKey)) {
            edges.push({
              source: endpointNodeId,
              target: resourceNodeId,
              weight: successfulAccess.length,
              severity: 'CRITICAL'
            });
            edgeKeys.add(resEdgeKey);
          }
        }
      }
    }

    return { nodes, edges };
  }

  /**
   * Get the highest severity from a list of alerts.
   */
  _getMaxSeverity(alerts) {
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    for (const level of order) {
      if (alerts.some(a => a.severity === level)) return level;
    }
    return alerts.length > 0 ? 'MEDIUM' : 'LOW';
  }
}
