/**
 * Project Phoenix — Live Watchdog (WebSocket + File Watcher)
 * 
 * Real-time log monitoring:
 *   1. Watches a directory for new/modified log files (via chokidar)
 *   2. Parses new lines through the pipeline
 *   3. Runs detection rules
 *   4. Pushes events + alerts to connected WebSocket clients
 * 
 * WebSocket message format:
 *   { type: 'event'|'alert'|'heartbeat'|'stats', data: {...}, timestamp: ISO }
 */

import { WebSocketServer } from 'ws';
import chokidar from 'chokidar';
import { readFileSync, statSync } from 'fs';
import { ParserFactory } from '../pipeline/ingestion/ParserFactory.js';
import { RuleEngine } from '../pipeline/detection/RuleEngine.js';

export class LiveWatchdog {
  /**
   * @param {Object} options
   * @param {import('http').Server} options.server - HTTP server to upgrade for WebSocket
   * @param {string} options.watchDir - Directory to watch for log files
   */
  constructor({ server, watchDir }) {
    this.watchDir = watchDir;
    this.factory = new ParserFactory();
    this.ruleEngine = new RuleEngine();
    this.clients = new Set();

    // Track file sizes to only process new content
    this.fileSizes = new Map();

    // Stats
    this.stats = { eventsProcessed: 0, alertsGenerated: 0, filesWatched: 0 };

    // WebSocket server
    this.wss = new WebSocketServer({ server, path: '/ws/live' });
    this._setupWebSocket();

    // File watcher
    this.watcher = null;
    this._startWatching();

    // Heartbeat
    this._heartbeatInterval = setInterval(() => this._sendHeartbeat(), 30000);
  }

  /**
   * Setup WebSocket connection handling.
   */
  _setupWebSocket() {
    this.wss.on('connection', (ws, req) => {
      const clientId = `${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      this.clients.add(ws);
      console.log(`   [WS] Client connected: ${clientId} (${this.clients.size} total)`);

      // Send welcome + stats
      this._send(ws, {
        type: 'connected',
        data: {
          message: 'Connected to Project Phoenix Live Watchdog',
          watchDir: this.watchDir,
          stats: this.stats
        }
      });

      ws.on('close', () => {
        this.clients.delete(ws);
        console.log(`   [WS] Client disconnected: ${clientId} (${this.clients.size} total)`);
      });

      ws.on('error', (err) => {
        console.error(`   [WS] Client error: ${err.message}`);
        this.clients.delete(ws);
      });
    });
  }

  /**
   * Start watching the log directory with chokidar.
   */
  _startWatching() {
    this.watcher = chokidar.watch(this.watchDir, {
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 500, pollInterval: 100 },
      ignored: /(^|[\/\\])\../, // Ignore dotfiles
    });

    this.watcher.on('add', (filePath) => {
      console.log(`   [Watch] New file: ${filePath}`);
      this.stats.filesWatched++;
      this._processFile(filePath, true);
    });

    this.watcher.on('change', (filePath) => {
      this._processFile(filePath, false);
    });

    this.watcher.on('error', (err) => {
      console.error(`   [Watch] Error: ${err.message}`);
    });

    console.log(`   [Watch] Monitoring: ${this.watchDir}`);
  }

  /**
   * Process a log file — parse new content, detect threats, broadcast.
   * @param {string} filePath
   * @param {boolean} isNew - If true, process entire file; otherwise only new bytes
   */
  _processFile(filePath, isNew) {
    try {
      const content = readFileSync(filePath, 'utf-8');
      const currentSize = Buffer.byteLength(content, 'utf-8');
      const prevSize = this.fileSizes.get(filePath) || 0;

      // Skip if no new content
      if (!isNew && currentSize <= prevSize) return;

      // Get only the new portion
      let newContent;
      if (isNew || prevSize === 0) {
        newContent = content;
      } else {
        // Read new bytes as string (approximate — works for line-based logs)
        const allLines = content.split('\n');
        const prevLines = readFileSync(filePath, 'utf-8').substring(0, prevSize).split('\n').length;
        newContent = allLines.slice(prevLines - 1).join('\n');
      }

      this.fileSizes.set(filePath, currentSize);

      if (!newContent.trim()) return;

      // Parse
      let events;
      try {
        const result = this.factory.parseAuto(newContent, filePath);
        events = result.events;
      } catch {
        // Format not detected — skip
        return;
      }

      if (events.length === 0) return;

      // Detect threats
      const { alerts } = this.ruleEngine.detectAll(events);

      // Update stats
      this.stats.eventsProcessed += events.length;
      this.stats.alertsGenerated += alerts.length;

      // Broadcast events
      for (const event of events) {
        this._broadcast({
          type: 'event',
          data: event.toJSON()
        });
      }

      // Broadcast alerts
      for (const alert of alerts) {
        this._broadcast({
          type: 'alert',
          data: alert.toJSON()
        });
      }

      // Broadcast stats update
      this._broadcast({
        type: 'stats',
        data: this.stats
      });

      console.log(`   [Watch] Processed ${events.length} events, ${alerts.length} alerts from ${filePath}`);
    } catch (err) {
      console.error(`   [Watch] Error processing ${filePath}: ${err.message}`);
    }
  }

  /**
   * Send a message to a single WebSocket client.
   */
  _send(ws, message) {
    if (ws.readyState === 1) { // WebSocket.OPEN
      ws.send(JSON.stringify({
        ...message,
        timestamp: new Date().toISOString()
      }));
    }
  }

  /**
   * Broadcast a message to all connected clients.
   */
  _broadcast(message) {
    const payload = JSON.stringify({
      ...message,
      timestamp: new Date().toISOString()
    });

    for (const client of this.clients) {
      if (client.readyState === 1) {
        client.send(payload);
      }
    }
  }

  /**
   * Send heartbeat to all clients.
   */
  _sendHeartbeat() {
    this._broadcast({
      type: 'heartbeat',
      data: { clients: this.clients.size, stats: this.stats }
    });
  }

  /**
   * Shutdown the watchdog.
   */
  async shutdown() {
    clearInterval(this._heartbeatInterval);
    if (this.watcher) await this.watcher.close();
    this.wss.close();
    console.log('   [Watch] Watchdog shut down');
  }

  /**
   * Get current stats.
   */
  getStats() {
    return {
      ...this.stats,
      connectedClients: this.clients.size,
      watchDir: this.watchDir
    };
  }
}
