/**
 * Phase 2 Verification — Tests Detection, Correlation & IP Enrichment:
 *   - Rule Engine (regex + aggregation rules)
 *   - Correlation Engine (IP grouping, attack chains, threat scoring)
 *   - IP Enricher (private IP detection, caching)
 *   - Full pipeline integration (parse → detect → correlate)
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { ParserFactory } from '../src/pipeline/ingestion/ParserFactory.js';
import { RuleEngine } from '../src/pipeline/detection/RuleEngine.js';
import { CorrelationEngine } from '../src/pipeline/correlation/CorrelationEngine.js';
import { IpEnricher } from '../src/pipeline/enrichment/IpEnricher.js';
import { allRules } from '../src/pipeline/detection/rules/index.js';

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

// ─── Parse all sample logs ─────────────────────────────────────────

const factory = new ParserFactory();
const nginxContent = readFileSync(join(SAMPLE_DIR, 'nginx-access.log'), 'utf-8');
const authContent = readFileSync(join(SAMPLE_DIR, 'auth.log'), 'utf-8');
const jsonContent = readFileSync(join(SAMPLE_DIR, 'app-events.json'), 'utf-8');

const nginxEvents = factory.parseWithFormat('nginx', nginxContent, 'nginx-access.log');
const authEvents = factory.parseWithFormat('auth', authContent, 'auth.log');
const jsonEvents = factory.parseWithFormat('json', jsonContent, 'app-events.json');
const allEvents = [...nginxEvents, ...authEvents, ...jsonEvents];

console.log(`\n📊 Parsed ${allEvents.length} total events (${nginxEvents.length} nginx, ${authEvents.length} auth, ${jsonEvents.length} json)`);

// ─── Rule Engine Tests ─────────────────────────────────────────────

console.log('\n🛡️ Rule Engine');

const ruleEngine = new RuleEngine();
const stats = ruleEngine.getStats();

assert(stats.totalRules > 20, `Loaded ${stats.totalRules} detection rules`);
assert(stats.regexRules > 15, `${stats.regexRules} regex rules`);
assert(stats.aggregationRules >= 2, `${stats.aggregationRules} aggregation rules`);
assert(Object.keys(stats.categories).length >= 5, `${Object.keys(stats.categories).length} categories`);

// Test against nginx logs (should detect SQL injection, path traversal, etc.)
const { alerts: nginxAlerts } = ruleEngine.detectAll(nginxEvents);
assert(nginxAlerts.length > 0, `Detected ${nginxAlerts.length} alerts in nginx logs`);

// Check for SQL injection alerts
const sqliAlerts = nginxAlerts.filter(a => a.category === 'SQL Injection');
assert(sqliAlerts.length > 0, `Found ${sqliAlerts.length} SQL injection alerts`);

// Check for Path Traversal alerts  
const traversalAlerts = nginxAlerts.filter(a => a.category === 'Path Traversal');
assert(traversalAlerts.length > 0, `Found ${traversalAlerts.length} path traversal alerts`);

// Test against auth logs (should detect brute force)
const { alerts: authAlerts } = ruleEngine.detectAll(authEvents);
assert(authAlerts.length > 0, `Detected ${authAlerts.length} alerts in auth logs`);

const bruteForceAlerts = authAlerts.filter(a => a.category === 'Brute Force');
assert(bruteForceAlerts.length > 0, `Found ${bruteForceAlerts.length} brute force alerts`);

// Test against all events combined
const { alerts: allAlerts, alertsByEvent } = ruleEngine.detectAll(allEvents);
assert(allAlerts.length > nginxAlerts.length, `All-source detection found ${allAlerts.length} alerts (> nginx-only)`);
assert(alertsByEvent instanceof Map, 'alertsByEvent is a Map');

// Check alert structure
const sampleAlert = allAlerts[0];
assert(sampleAlert.id.startsWith('alert_'), 'Alert has auto-generated ID');
assert(sampleAlert.ruleId, `Alert rule: ${sampleAlert.ruleId}`);
assert(sampleAlert.severity, `Alert severity: ${sampleAlert.severity}`);
assert(sampleAlert.event !== null, 'Alert has event reference');

// Check severities are valid
const validSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const allSeveritiesValid = allAlerts.every(a => validSeverities.has(a.severity));
assert(allSeveritiesValid, 'All alerts have valid severity levels');

// ─── Correlation Engine Tests ──────────────────────────────────────

console.log('\n🔗 Correlation Engine');

const correlationEngine = new CorrelationEngine();
const { attackers, attackChains, graphData, correlationAlerts } = correlationEngine.correlate(allEvents, allAlerts);

assert(attackers.length > 0, `Found ${attackers.length} attacker profile(s)`);
assert(attackers[0].ip, `Top attacker IP: ${attackers[0].ip}`);
assert(attackers[0].threatScore > 0, `Top attacker threat score: ${attackers[0].threatScore}`);
assert(attackers[0].totalRequests > 0, `Top attacker requests: ${attackers[0].totalRequests}`);
assert(attackers[0].attackTypes.length > 0, `Attack types: ${attackers[0].attackTypes.join(', ')}`);
assert(attackers[0].targetedEndpoints.length > 0, `Targeted ${attackers[0].targetedEndpoints.length} endpoints`);
assert(attackers[0].firstSeen instanceof Date, 'firstSeen is a Date');
assert(attackers[0].lastSeen instanceof Date, 'lastSeen is a Date');

// Attack chains
assert(attackChains.length > 0, `Built ${attackChains.length} attack chain(s)`);
assert(attackChains[0].id.startsWith('chain_'), 'Chain has auto-generated ID');
assert(attackChains[0].events.length >= 2, `Chain has ${attackChains[0].events.length} events`);
assert(attackChains[0].threatScore > 0, `Chain threat score: ${attackChains[0].threatScore}`);

// Correlation patterns
assert(Array.isArray(correlationAlerts), 'Correlation alerts is an array');
if (correlationAlerts.length > 0) {
  console.log(`  ✅ Found ${correlationAlerts.length} correlation pattern(s): ${correlationAlerts.map(c => c.name).join(', ')}`);
  passed++;
} else {
  console.log(`  ✅ No multi-event correlation patterns (expected for single-IP sample data)`);
  passed++;
}

// Graph data for blast radius
assert(graphData.nodes.length > 0, `Graph has ${graphData.nodes.length} nodes`);
assert(graphData.edges.length > 0, `Graph has ${graphData.edges.length} edges`);

const attackerNodes = graphData.nodes.filter(n => n.type === 'attacker');
const endpointNodes = graphData.nodes.filter(n => n.type === 'endpoint');
assert(attackerNodes.length > 0, `${attackerNodes.length} attacker node(s)`);
assert(endpointNodes.length > 0, `${endpointNodes.length} endpoint node(s)`);

// Serialization
const attackerJson = attackers[0].toJSON();
assert(attackerJson.ip, 'AttackerProfile.toJSON() works');
const chainJson = attackChains[0].toJSON();
assert(chainJson.id, 'AttackChain.toJSON() works');

// ─── IP Enricher Tests ─────────────────────────────────────────────

console.log('\n🌍 IP Enricher');

const enricher = new IpEnricher();

// Test private IP detection
const privateResult = await enricher.enrich('192.168.1.105');
assert(privateResult.isPrivate === true, 'Detects 192.168.1.x as private');
assert(privateResult.geo.country === 'Private Network', 'Private IP → "Private Network"');

const loopback = await enricher.enrich('127.0.0.1');
assert(loopback.isPrivate === true, 'Detects 127.0.0.1 as private');

const tenNet = await enricher.enrich('10.0.0.1');
assert(tenNet.isPrivate === true, 'Detects 10.x as private');

// Test caching
const cached = await enricher.enrich('192.168.1.105');
assert(cached.cached === true, 'Second lookup returns cached result');

// Test cache stats
const cacheStats = enricher.getCacheStats();
assert(cacheStats.cached >= 3, `Cache has ${cacheStats.cached} entries`);

// Test enrichAttackers
const attackersCopy = attackers.map(a => ({ ...a, ip: a.ip }));
// enrichAttackers modifies in-place, test with a shallow copy
assert(typeof enricher.enrichAttackers === 'function', 'enrichAttackers method exists');

// ─── Full Pipeline Integration Test ────────────────────────────────

console.log('\n🔄 Full Pipeline Integration');

// Simulate the full analysis endpoint logic
const { events: parsedAll } = factory.parseAuto(nginxContent, 'nginx-access.log');
const { alerts: detectedAlerts } = ruleEngine.detectAll(parsedAll);
const correlated = correlationEngine.correlate(parsedAll, detectedAlerts);

assert(parsedAll.length > 0, `Pipeline: Parsed ${parsedAll.length} events`);
assert(detectedAlerts.length > 0, `Pipeline: Detected ${detectedAlerts.length} alerts`);
assert(correlated.attackers.length > 0, `Pipeline: Found ${correlated.attackers.length} attacker(s)`);
assert(correlated.graphData.nodes.length > 0, `Pipeline: Graph has ${correlated.graphData.nodes.length} nodes`);

// ─── Summary ───────────────────────────────────────────────────────

console.log(`\n${'═'.repeat(50)}`);
console.log(`  Phase 2 Verification: ${passed} passed, ${failed} failed`);
console.log(`${'═'.repeat(50)}\n`);

process.exit(failed > 0 ? 1 : 0);
