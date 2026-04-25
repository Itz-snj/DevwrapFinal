/**
 * Phase 1 Verification — Tests all pipeline foundation modules:
 *   - Deobfuscation layer
 *   - Nginx parser
 *   - Auth.log parser
 *   - JSON log parser (multi-line format)
 *   - Parser factory (auto-detection)
 *   - Schemas (NormalizedEvent, Alert, Incident)
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { Deobfuscator, urlDecode, base64Decode } from '../src/pipeline/deobfuscation/Deobfuscator.js';
import { NginxParser } from '../src/pipeline/ingestion/NginxParser.js';
import { AuthLogParser } from '../src/pipeline/ingestion/AuthLogParser.js';
import { JsonLogParser } from '../src/pipeline/ingestion/JsonLogParser.js';
import { ParserFactory } from '../src/pipeline/ingestion/ParserFactory.js';
import { NormalizedEvent, Alert, Incident, SEVERITY_WEIGHTS } from '../src/pipeline/schemas.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SAMPLE_DIR = join(__dirname, '../../sample-logs');

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

// ─── Deobfuscation Tests ───────────────────────────────────────────

console.log('\n🔓 Deobfuscation Layer');

const deob = new Deobfuscator();

assert(urlDecode('%2e%2e%2f') === '../', 'URL decode: %2e%2e%2f → ../');
assert(urlDecode('%27%20OR%201%3D1') === "' OR 1=1", "URL decode: SQL injection payload");
assert(urlDecode('%252e%252e%252f') === '../', 'Double URL encoding: %252e → %2e → .');
assert(urlDecode('normal-string') === 'normal-string', 'URL decode: clean string unchanged');

const b64Input = Buffer.from('../../etc/passwd').toString('base64');
assert(base64Decode(b64Input).includes('../../etc/passwd'), 'Base64 decode: path traversal');

assert(deob.deobfuscate('%2e%2e/%2e%2e/etc/passwd') === '../../etc/passwd', 'Full pipeline: URL-encoded path traversal');
assert(deob.deobfuscate('normal log line') === 'normal log line', 'Full pipeline: clean string unchanged');

// ─── Nginx Parser Tests ────────────────────────────────────────────

console.log('\n📄 Nginx Parser');

const nginxContent = readFileSync(join(SAMPLE_DIR, 'nginx-access.log'), 'utf-8');
const nginxParser = new NginxParser();
const nginxEvents = nginxParser.parse(nginxContent, 'nginx-access.log');

assert(nginxEvents.length > 0, `Parsed ${nginxEvents.length} events from nginx log`);
assert(nginxEvents[0].source === 'nginx', 'Source is "nginx"');
assert(nginxEvents[0].ip === '192.168.1.105', 'First event IP: 192.168.1.105');
assert(nginxEvents[0].method === 'POST', 'First event method: POST');
assert(nginxEvents[0].endpoint === '/admin/login', 'First event endpoint: /admin/login');
assert(nginxEvents[0].statusCode === 401, 'First event status: 401');
assert(nginxEvents[0].timestamp instanceof Date, 'Timestamp is a Date object');
assert(!isNaN(nginxEvents[0].timestamp.getTime()), 'Timestamp is valid');

// Check deobfuscation happened (line with %2e%2e → ../..)
const traversalEvent = nginxEvents.find(e => e.endpoint.includes('../../'));
assert(traversalEvent !== undefined, 'URL-encoded path traversal was deobfuscated');

// Check SQL injection line was deobfuscated
const sqliEvent = nginxEvents.find(e => e.endpoint.includes("OR 1=1"));
assert(sqliEvent !== undefined, 'URL-encoded SQL injection was deobfuscated');

// Auto-detect
const nginxLines = nginxContent.split('\n').filter(l => l.trim()).slice(0, 10);
assert(NginxParser.detect(nginxLines) > 80, `Nginx auto-detect confidence > 80%: ${NginxParser.detect(nginxLines)}%`);

// ─── Auth Log Parser Tests ─────────────────────────────────────────

console.log('\n🔐 Auth Log Parser');

const authContent = readFileSync(join(SAMPLE_DIR, 'auth.log'), 'utf-8');
const authParser = new AuthLogParser();
const authEvents = authParser.parse(authContent, 'auth.log');

assert(authEvents.length > 0, `Parsed ${authEvents.length} events from auth.log`);
assert(authEvents[0].source === 'auth', 'Source is "auth"');
assert(authEvents[0].ip === '192.168.1.105', 'First event IP: 192.168.1.105');
assert(authEvents[0].statusCode === 401, 'Failed password → status 401');
assert(authEvents[0].user === 'admin', 'First event user: admin');

// Find successful login
const successLogin = authEvents.find(e => e.statusCode === 200 && e.metadata?.authResult === 'success');
assert(successLogin !== undefined, 'Found successful login event');

// Find sudo command
const sudoEvent = authEvents.find(e => e.method === 'SUDO');
assert(sudoEvent !== undefined, 'Found sudo command event');
assert(sudoEvent?.metadata?.command?.includes('/etc/shadow'), 'Sudo command targets /etc/shadow');

// Auto-detect
const authLines = authContent.split('\n').filter(l => l.trim()).slice(0, 10);
assert(AuthLogParser.detect(authLines) > 80, `Auth log auto-detect confidence > 80%: ${AuthLogParser.detect(authLines)}%`);

// ─── JSON Log Parser Tests ─────────────────────────────────────────

console.log('\n📋 JSON Log Parser (multi-line format)');

const jsonContent = readFileSync(join(SAMPLE_DIR, 'app-events.json'), 'utf-8');
const jsonParser = new JsonLogParser();
const jsonEvents = jsonParser.parse(jsonContent, 'app-events.json');

assert(jsonEvents.length > 0, `Parsed ${jsonEvents.length} events from JSON log`);
assert(jsonEvents.length === 12, `Expected 12 events, got ${jsonEvents.length}`);
assert(jsonEvents[0].source === 'app', 'Source is "app"');
assert(jsonEvents[0].ip === '192.168.1.105', 'First event IP: 192.168.1.105');
assert(jsonEvents[0].endpoint === '/api/auth/login', 'First event endpoint: /api/auth/login');

// Find SQL injection event
const jsonSqli = jsonEvents.find(e => e.metadata?.query?.includes('OR 1=1'));
assert(jsonSqli !== undefined, 'Found SQL injection in JSON logs');

// Find XSS event
const jsonXss = jsonEvents.find(e => e.metadata?.payload?.includes('<script>'));
assert(jsonXss !== undefined, 'Found XSS payload in JSON logs');

// Auto-detect (needs more lines for multi-line JSON)
const jsonLines = jsonContent.split('\n').filter(l => l.trim()).slice(0, 50);
assert(JsonLogParser.detect(jsonLines) > 50, `JSON log auto-detect confidence > 50%: ${JsonLogParser.detect(jsonLines)}%`);

// ─── Parser Factory Tests ──────────────────────────────────────────

console.log('\n🏭 Parser Factory');

const factory = new ParserFactory();

const nginxResult = factory.parseAuto(nginxContent, 'nginx-access.log');
assert(nginxResult.format === 'nginx', `Auto-detected nginx format: ${nginxResult.format}`);
assert(nginxResult.events.length > 0, `Factory parsed ${nginxResult.events.length} nginx events`);

const authResult = factory.parseAuto(authContent, 'auth.log');
assert(authResult.format === 'auth', `Auto-detected auth format: ${authResult.format}`);
assert(authResult.events.length > 0, `Factory parsed ${authResult.events.length} auth events`);

const jsonResult = factory.parseAuto(jsonContent, 'app-events.json');
assert(jsonResult.format === 'json', `Auto-detected JSON format: ${jsonResult.format}`);
assert(jsonResult.events.length > 0, `Factory parsed ${jsonResult.events.length} JSON events`);

assert(factory.getSupportedFormats().length === 3, 'Factory supports 3 formats');

// ─── Schema Tests ──────────────────────────────────────────────────

console.log('\n📐 Schemas');

const event = new NormalizedEvent({
  timestamp: '2026-04-25T08:00:00Z',
  source: 'test',
  ip: '1.2.3.4',
  endpoint: '/test'
});
assert(event.timestamp instanceof Date, 'NormalizedEvent: string timestamp → Date');
assert(event.toJSON().timestamp === '2026-04-25T08:00:00.000Z', 'NormalizedEvent: toJSON works');

const alert = new Alert({
  ruleId: 'TEST_001',
  category: 'Test',
  severity: 'HIGH',
  description: 'Test alert'
});
assert(alert.id.startsWith('alert_'), 'Alert: auto-generates ID');
assert(alert.toJSON().severity === 'HIGH', 'Alert: toJSON works');

const incident = new Incident({
  events: nginxEvents,
  alerts: [alert],
  attackers: []
});
assert(incident.id.startsWith('inc_'), 'Incident: auto-generates ID');
incident.buildSummary();
assert(incident.summary.totalEvents === nginxEvents.length, `Incident summary: ${nginxEvents.length} events`);
assert(incident.summary.totalAlerts === 1, 'Incident summary: 1 alert');

assert(SEVERITY_WEIGHTS.CRITICAL === 25, 'Severity weights: CRITICAL = 25');

// ─── Summary ───────────────────────────────────────────────────────

console.log(`\n${'═'.repeat(50)}`);
console.log(`  Phase 1 Verification: ${passed} passed, ${failed} failed`);
console.log(`${'═'.repeat(50)}\n`);

process.exit(failed > 0 ? 1 : 0);
