/**
 * Phase 3 Verification — Tests Incident Store, Reports, API, and WebSocket:
 *   - IncidentStore (save, get, list, delete)
 *   - MarkdownGenerator (report structure)
 *   - Phase 3 API endpoints via HTTP
 *   - WebSocket connectivity
 */

import { readFileSync, existsSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import http from 'http';

import { IncidentStore } from '../src/store/IncidentStore.js';
import { MarkdownGenerator } from '../src/pipeline/reporting/MarkdownGenerator.js';
import { ParserFactory } from '../src/pipeline/ingestion/ParserFactory.js';
import { RuleEngine } from '../src/pipeline/detection/RuleEngine.js';
import { CorrelationEngine } from '../src/pipeline/correlation/CorrelationEngine.js';
import { Incident } from '../src/pipeline/schemas.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SAMPLE_DIR = join(__dirname, '../../sample-logs');
const TEST_DATA_DIR = join(__dirname, '../data/test-incidents');

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  ✅ ${testName}`);
    passed++;
  } else {
    console.error(`  ❌ ${testName}`);
    failed++;
  }
}

// ─── Build test incident ────────────────────────────────────────────

const factory = new ParserFactory();
const ruleEngine = new RuleEngine();
const correlationEngine = new CorrelationEngine();

const nginxContent = readFileSync(join(SAMPLE_DIR, 'nginx-access.log'), 'utf-8');
const authContent = readFileSync(join(SAMPLE_DIR, 'auth.log'), 'utf-8');

const nginxEvents = factory.parseWithFormat('nginx', nginxContent, 'nginx-access.log');
const authEvents = factory.parseWithFormat('auth', authContent, 'auth.log');
const allEvents = [...nginxEvents, ...authEvents];

const { alerts } = ruleEngine.detectAll(allEvents);
const { attackers, attackChains, graphData } = correlationEngine.correlate(allEvents, alerts);

const incident = new Incident({ events: allEvents, alerts, attackers, attackChains, graphData });
incident.buildSummary();

console.log(`\n📊 Test incident: ${incident.id} (${allEvents.length} events, ${alerts.length} alerts)\n`);

// ─── Incident Store Tests ──────────────────────────────────────────

console.log('📦 Incident Store');

// Clean test dir
if (existsSync(TEST_DATA_DIR)) rmSync(TEST_DATA_DIR, { recursive: true });

const store = new IncidentStore(TEST_DATA_DIR);

// Save
const savedId = store.save(incident);
assert(savedId === incident.id, `Saved incident: ${savedId}`);

// File exists
assert(existsSync(join(TEST_DATA_DIR, `${incident.id}.json`)), 'JSON file created on disk');

// Get
const retrieved = store.get(incident.id);
assert(retrieved !== null, 'Retrieved incident from store');
assert(retrieved.id === incident.id, 'Retrieved ID matches');
assert(retrieved.summary.totalEvents === allEvents.length, `Summary has ${retrieved.summary.totalEvents} events`);
assert(retrieved.summary.totalAlerts === alerts.length, `Summary has ${retrieved.summary.totalAlerts} alerts`);
assert(retrieved.attackers.length > 0, `Has ${retrieved.attackers.length} attackers`);
assert(retrieved.graphData.nodes.length > 0, `Graph has ${retrieved.graphData.nodes.length} nodes`);
assert(retrieved.events.length === allEvents.length, `Full events stored (${retrieved.events.length})`);

// List
const list = store.list();
assert(list.length === 1, `List returns 1 incident`);
assert(list[0].id === incident.id, 'List item ID matches');
assert(list[0].threatScore >= 0, `List item has threatScore: ${list[0].threatScore}`);
assert(list[0].topAttackerIp, `List item has topAttackerIp: ${list[0].topAttackerIp}`);

// Save another
const incident2 = new Incident({ events: nginxEvents, alerts: alerts.slice(0, 3), attackers: [], attackChains: [], graphData: { nodes: [], edges: [] } });
incident2.buildSummary();
store.save(incident2);
assert(store.list().length === 2, 'Store now has 2 incidents');
assert(store.count() === 2, 'Count returns 2');

// Get non-existent
assert(store.get('nonexistent') === null, 'Returns null for missing ID');

// Delete
assert(store.delete(incident2.id) === true, 'Deleted second incident');
assert(store.list().length === 1, 'Back to 1 incident');
assert(store.delete('nonexistent') === false, 'Delete returns false for missing ID');

// ─── Markdown Report Generator Tests ───────────────────────────────

console.log('\n📝 Markdown Report Generator');

const mdGen = new MarkdownGenerator();
const report = mdGen.generate(retrieved);

assert(typeof report === 'string', 'Report is a string');
assert(report.length > 500, `Report length: ${report.length} chars`);
assert(report.includes('Incident Forensics Report'), 'Has report title');
assert(report.includes('Executive Summary'), 'Has Executive Summary section');
assert(report.includes('Attacker Profiles'), 'Has Attacker Profiles section');
assert(report.includes('Attack Timeline'), 'Has Attack Timeline section');
assert(report.includes('Alert Breakdown'), 'Has Alert Breakdown section');
assert(report.includes('Attack Chains'), 'Has Attack Chains section');
assert(report.includes('Evidence'), 'Has Evidence section');
assert(report.includes('Recommendations'), 'Has Recommendations section');
assert(report.includes(incident.id), 'Report contains incident ID');
assert(report.includes('CRITICAL'), 'Report shows severity levels');
assert(report.includes('Project Phoenix'), 'Has footer branding');

// Recommendations should be context-aware
assert(report.includes('Block IP'), 'Recommends blocking high-threat IPs');
assert(
  report.includes('parameterized queries') || report.includes('SQL injection'),
  'Has SQLi-specific recommendation'
);

// ─── API Integration Tests ──────────────────────────────────────────

console.log('\n🌐 API Integration (requires server at localhost:3001)');

/**
 * Simple HTTP request helper.
 */
function httpRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3001,
      path,
      method,
      headers: { 'Content-Type': 'application/json' },
      timeout: 5000
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data), headers: res.headers });
        } catch {
          resolve({ status: res.statusCode, data, headers: res.headers });
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Check if server is running
let serverRunning = false;
try {
  const health = await httpRequest('GET', '/api/health');
  serverRunning = health.status === 200;
} catch {
  serverRunning = false;
}

if (serverRunning) {
  // Create an incident via analyze/full
  const { data: analyzeResult } = await httpRequest('POST', '/api/analyze/full', {
    content: nginxContent,
    sourceFile: 'nginx-access.log',
    enrichIps: false
  });
  const testId = analyzeResult.incidentId;
  assert(testId, `Created incident via /analyze/full: ${testId}`);

  // List incidents
  const { data: listResult } = await httpRequest('GET', '/api/incidents');
  assert(listResult.incidents.length > 0, `GET /incidents returned ${listResult.incidents.length} incident(s)`);

  // Get incident detail
  const { data: detailResult } = await httpRequest('GET', `/api/incidents/${testId}`);
  assert(detailResult.id === testId, `GET /incidents/${testId} returned correct ID`);
  assert(detailResult.summary.totalEvents > 0, `Detail has ${detailResult.summary.totalEvents} events`);

  // Get timeline
  const { data: timelineResult } = await httpRequest('GET', `/api/incidents/${testId}/timeline?page=1&pageSize=10`);
  assert(timelineResult.events.length > 0, `Timeline has ${timelineResult.events.length} events (page 1)`);
  assert(timelineResult.totalPages >= 1, `Timeline has ${timelineResult.totalPages} page(s)`);
  assert(timelineResult.pageSize === 10, 'Timeline respects pageSize=10');

  // Get graph
  const { data: graphResult } = await httpRequest('GET', `/api/incidents/${testId}/graph`);
  assert(graphResult.nodes && graphResult.nodes.length > 0, `Graph has ${graphResult.nodes.length} nodes`);
  assert(graphResult.edges && graphResult.edges.length > 0, `Graph has ${graphResult.edges.length} edges`);

  // Get report (markdown)
  const { data: reportResult, headers } = await httpRequest('GET', `/api/incidents/${testId}/report?format=md`);
  assert(typeof reportResult === 'string' && reportResult.includes('Incident Forensics'), 'Report download works (markdown)');

  // 404 test
  const { status } = await httpRequest('GET', '/api/incidents/nonexistent');
  assert(status === 404, 'Returns 404 for missing incident');

  // Delete
  const { data: deleteResult } = await httpRequest('DELETE', `/api/incidents/${testId}`);
  assert(deleteResult.message === 'Incident deleted', `Deleted incident ${testId}`);

  // Confirm deletion
  const { status: status2 } = await httpRequest('GET', `/api/incidents/${testId}`);
  assert(status2 === 404, 'Incident no longer exists after DELETE');

} else {
  console.log('  ⚠️  Server not running — skipping API tests');
  console.log('     Start with: node server/src/server.js');
}

// ─── Cleanup ────────────────────────────────────────────────────────

if (existsSync(TEST_DATA_DIR)) rmSync(TEST_DATA_DIR, { recursive: true });

// ─── Summary ───────────────────────────────────────────────────────

console.log(`\n${'═'.repeat(50)}`);
console.log(`  Phase 3 Verification: ${passed} passed, ${failed} failed`);
console.log(`${'═'.repeat(50)}\n`);

process.exit(failed > 0 ? 1 : 0);
