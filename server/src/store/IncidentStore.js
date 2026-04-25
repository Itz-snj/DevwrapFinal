/**
 * Project Phoenix — Incident Store
 * 
 * File-backed JSON persistence for analyzed incidents.
 * Each incident is saved as a separate JSON file in server/data/incidents/.
 * Survives server restarts.
 */

import { readFileSync, writeFileSync, readdirSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Incident } from '../pipeline/schemas.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DATA_DIR = join(__dirname, '../../data/incidents');

export class IncidentStore {
  constructor(dataDir = DATA_DIR) {
    this.dataDir = dataDir;
    this._ensureDir();
  }

  /**
   * Create data directory if it doesn't exist.
   */
  _ensureDir() {
    if (!existsSync(this.dataDir)) {
      mkdirSync(this.dataDir, { recursive: true });
    }
  }

  /**
   * Save an incident to disk.
   * @param {Incident} incident
   * @returns {string} Incident ID
   */
  save(incident) {
    const filePath = join(this.dataDir, `${incident.id}.json`);
    const data = {
      id: incident.id,
      createdAt: incident.createdAt?.toISOString?.() || incident.createdAt,
      status: incident.status,
      summary: incident.summary,
      events: incident.events.map(e => e.toJSON?.() || e),
      alerts: incident.alerts.map(a => a.toJSON?.() || a),
      attackers: incident.attackers.map(a => ({
        ...(a.toJSON?.() || a),
        isp: a.isp,
        org: a.org,
        as: a.as,
        isPrivateIp: a.isPrivateIp
      })),
      attackChains: incident.attackChains.map(c => c.toJSON?.() || c),
      graphData: incident.graphData
    };
    writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
    return incident.id;
  }

  /**
   * Get a single incident by ID.
   * @param {string} id
   * @returns {Object|null}
   */
  get(id) {
    const filePath = join(this.dataDir, `${id}.json`);
    if (!existsSync(filePath)) return null;
    try {
      return JSON.parse(readFileSync(filePath, 'utf-8'));
    } catch {
      return null;
    }
  }

  /**
   * List all incidents (summary only, no full events).
   * @returns {Object[]}
   */
  list() {
    this._ensureDir();
    const files = readdirSync(this.dataDir).filter(f => f.endsWith('.json'));
    const incidents = [];

    for (const file of files) {
      try {
        const data = JSON.parse(readFileSync(join(this.dataDir, file), 'utf-8'));
        incidents.push({
          id: data.id,
          createdAt: data.createdAt,
          status: data.status,
          threatScore: data.summary?.threatScore || 0,
          totalAlerts: data.summary?.totalAlerts || 0,
          totalEvents: data.summary?.totalEvents || 0,
          topAttackerIp: data.summary?.topAttackerIp || null,
          alertsBySeverity: data.summary?.alertsBySeverity || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
          attackTypes: data.summary?.attackTypes || []
        });
      } catch {
        // Skip corrupted files
      }
    }

    // Sort by creation time (newest first)
    incidents.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    return incidents;
  }

  /**
   * Delete an incident.
   * @param {string} id
   * @returns {boolean} True if deleted
   */
  delete(id) {
    const filePath = join(this.dataDir, `${id}.json`);
    if (!existsSync(filePath)) return false;
    unlinkSync(filePath);
    return true;
  }

  /**
   * Get count of stored incidents.
   */
  count() {
    this._ensureDir();
    return readdirSync(this.dataDir).filter(f => f.endsWith('.json')).length;
  }
}
