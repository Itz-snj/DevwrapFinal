/**
 * Project Phoenix — Rule Engine
 * 
 * Loads all detection rules and runs them against NormalizedEvents.
 * Handles two rule types:
 *   1. Regex rules — match patterns against event fields
 *   2. Aggregation rules — detect patterns across multiple events (e.g., brute force)
 * 
 * Returns an array of Alert objects for events that match.
 */

import { Alert } from '../schemas.js';
import { allRules } from './rules/index.js';

export class RuleEngine {
  constructor(customRules = null) {
    /** @type {Array} All loaded rules */
    this.rules = customRules || allRules;
    this.regexRules = this.rules.filter(r => r.pattern && !r.type);
    this.aggregationRules = this.rules.filter(r => r.type === 'aggregation');
  }

  /**
   * Run all regex-based rules against a single event.
   * @param {NormalizedEvent} event
   * @returns {Alert[]}
   */
  detectSingle(event) {
    const alerts = [];

    for (const rule of this.regexRules) {
      const fieldsToCheck = rule.fields || ['endpoint', 'rawLine'];

      for (const field of fieldsToCheck) {
        const value = field === 'rawLine' ? event.rawLine :
                      field === 'endpoint' ? event.endpoint :
                      event.metadata?.[field] || event[field];

        if (!value || typeof value !== 'string') continue;

        // Reset regex lastIndex for global patterns
        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(value);

        if (match) {
          alerts.push(new Alert({
            ruleId: rule.id,
            category: rule.category,
            severity: rule.severity,
            description: rule.description,
            matchedPattern: match[0],
            event
          }));
          break; // One alert per rule per event
        }
      }
    }

    return alerts;
  }

  /**
   * Run all rules (regex + aggregation) against a batch of events.
   * @param {NormalizedEvent[]} events - All events to analyze.
   * @returns {{ alerts: Alert[], alertsByEvent: Map<string, Alert[]> }}
   */
  detectAll(events) {
    const alerts = [];
    const alertsByEvent = new Map();

    // 1. Run regex rules on each event
    for (const event of events) {
      const eventAlerts = this.detectSingle(event);
      if (eventAlerts.length > 0) {
        alerts.push(...eventAlerts);
        const key = event.getKey();
        alertsByEvent.set(key, (alertsByEvent.get(key) || []).concat(eventAlerts));
      }
    }

    // 2. Run aggregation rules
    const aggAlerts = this.detectAggregations(events);
    alerts.push(...aggAlerts);

    return { alerts, alertsByEvent };
  }

  /**
   * Run aggregation-based rules (e.g., brute force detection).
   * Groups events by IP and checks thresholds within time windows.
   * @param {NormalizedEvent[]} events
   * @returns {Alert[]}
   */
  detectAggregations(events) {
    const alerts = [];

    for (const rule of this.aggregationRules) {
      // Filter events that match this rule's criteria
      const matchingEvents = events.filter(e => rule.match(e));
      
      if (matchingEvents.length === 0) continue;

      // Group by the specified field (typically 'ip')
      const groups = new Map();
      for (const event of matchingEvents) {
        const key = event[rule.groupBy] || 'unknown';
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(event);
      }

      // Check each group against threshold within time window
      for (const [groupKey, groupEvents] of groups) {
        // Sort by timestamp
        const sorted = groupEvents.sort((a, b) => a.timestamp - b.timestamp);

        // Sliding window check
        let windowStart = 0;
        for (let i = 0; i < sorted.length; i++) {
          // Move window start forward if events are outside the window
          while (
            windowStart < i &&
            (sorted[i].timestamp - sorted[windowStart].timestamp) > rule.windowSeconds * 1000
          ) {
            windowStart++;
          }

          const windowCount = i - windowStart + 1;
          if (windowCount >= rule.threshold) {
            // Trigger alert on the event that crossed the threshold
            alerts.push(new Alert({
              ruleId: rule.id,
              category: rule.category,
              severity: rule.severity,
              description: `${rule.description} (${windowCount} events from ${groupKey} in ${rule.windowSeconds}s)`,
              matchedPattern: `${windowCount} events in ${rule.windowSeconds}s window`,
              event: sorted[i]
            }));
            break; // One alert per group per rule
          }
        }
      }
    }

    return alerts;
  }

  /**
   * Get statistics about loaded rules.
   */
  getStats() {
    const categories = {};
    for (const rule of this.rules) {
      categories[rule.category] = (categories[rule.category] || 0) + 1;
    }
    return {
      totalRules: this.rules.length,
      regexRules: this.regexRules.length,
      aggregationRules: this.aggregationRules.length,
      categories
    };
  }
}
