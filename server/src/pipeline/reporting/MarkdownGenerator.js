/**
 * Project Phoenix — Markdown Report Generator
 * 
 * Generates a structured forensic incident report in Markdown.
 * Sections:
 *   1. Executive Summary
 *   2. Attacker Profiles
 *   3. Attack Timeline
 *   4. Alert Breakdown
 *   5. Attack Chains
 *   6. Evidence Table (raw log lines)
 *   7. Recommendations
 */

/**
 * Generate severity badge.
 */
function badge(severity) {
  const map = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };
  return `${map[severity] || '⚪'} **${severity}**`;
}

/**
 * Format timestamp for reports.
 */
function formatTs(ts) {
  if (!ts) return 'N/A';
  const d = new Date(ts);
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

export class MarkdownGenerator {
  /**
   * Generate a full forensic report.
   * @param {Object} incident - Stored incident object (from IncidentStore.get())
   * @returns {string} Markdown string
   */
  generate(incident) {
    const sections = [
      this._header(incident),
      this._executiveSummary(incident),
      this._attackerProfiles(incident),
      this._timeline(incident),
      this._alertBreakdown(incident),
      this._attackChains(incident),
      this._evidence(incident),
      this._recommendations(incident),
      this._footer(incident)
    ];

    return sections.join('\n\n---\n\n');
  }

  _header(incident) {
    return `# 🔥 Project Phoenix — Incident Forensics Report

**Incident ID:** \`${incident.id}\`  
**Generated:** ${formatTs(new Date())}  
**Analysis Time:** ${formatTs(incident.createdAt)}  
**Status:** ${incident.status || 'analyzed'}`;
  }

  _executiveSummary(incident) {
    const s = incident.summary || {};
    const alertsBySev = s.alertsBySeverity || {};

    let lines = `## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| **Total Events Analyzed** | ${s.totalEvents || 0} |
| **Total Alerts Triggered** | ${s.totalAlerts || 0} |
| **Overall Threat Score** | **${s.threatScore || 0}/100** |
| **Time Range** | ${formatTs(s.timeRange?.start)} → ${formatTs(s.timeRange?.end)} |
| **Primary Threat Actor** | \`${s.topAttackerIp || 'N/A'}\` |

### Alert Severity Distribution

| ${badge('CRITICAL')} | ${badge('HIGH')} | ${badge('MEDIUM')} | ${badge('LOW')} |
|---|---|---|---|
| ${alertsBySev.CRITICAL || 0} | ${alertsBySev.HIGH || 0} | ${alertsBySev.MEDIUM || 0} | ${alertsBySev.LOW || 0} |`;

    if (s.attackTypes && s.attackTypes.length > 0) {
      lines += `\n\n### Attack Categories Detected\n\n| Category | Count | Severity |\n|----------|-------|----------|\n`;
      for (const t of s.attackTypes) {
        lines += `| ${t.type} | ${t.count} | ${badge(t.severity)} |\n`;
      }
    }

    return lines;
  }

  _attackerProfiles(incident) {
    const attackers = incident.attackers || [];
    if (attackers.length === 0) return '## 👤 Attacker Profiles\n\nNo attacker profiles identified.';

    let lines = `## 👤 Attacker Profiles\n\n`;

    for (const a of attackers) {
      const geo = a.geo || {};
      lines += `### IP: \`${a.ip}\`\n\n`;
      lines += `| Field | Value |\n|-------|-------|\n`;
      lines += `| **Threat Score** | **${a.threatScore}/100** |\n`;
      lines += `| **Total Requests** | ${a.totalRequests} |\n`;
      lines += `| **Alert Count** | ${a.alerts || 0} |\n`;
      lines += `| **Country** | ${geo.country || 'Unknown'} |\n`;
      lines += `| **City** | ${geo.city || 'Unknown'} |\n`;
      if (a.isp) lines += `| **ISP** | ${a.isp} |\n`;
      if (a.org) lines += `| **Organization** | ${a.org} |\n`;
      lines += `| **First Seen** | ${formatTs(a.firstSeen)} |\n`;
      lines += `| **Last Seen** | ${formatTs(a.lastSeen)} |\n`;
      lines += `| **Attack Types** | ${(a.attackTypes || []).join(', ') || 'N/A'} |\n`;

      if (a.targetedEndpoints && a.targetedEndpoints.length > 0) {
        lines += `\n**Targeted Endpoints:**\n`;
        for (const ep of a.targetedEndpoints.slice(0, 15)) {
          lines += `- \`${ep}\`\n`;
        }
      }
      lines += '\n';
    }

    return lines;
  }

  _timeline(incident) {
    const events = (incident.events || []).slice(0, 50); // Limit for readability
    if (events.length === 0) return '## ⏱️ Attack Timeline\n\nNo events recorded.';

    let lines = `## ⏱️ Attack Timeline\n\n`;
    lines += `*Showing first ${events.length} of ${incident.events?.length || 0} events*\n\n`;
    lines += `| # | Time | Source | IP | Method | Endpoint | Status |\n`;
    lines += `|---|------|--------|----|--------|----------|--------|\n`;

    for (let i = 0; i < events.length; i++) {
      const e = events[i];
      const ts = formatTs(e.timestamp).split(' ')[1] || formatTs(e.timestamp);
      const status = e.statusCode
        ? (e.statusCode >= 400 ? `❌ ${e.statusCode}` : `✅ ${e.statusCode}`)
        : '—';
      lines += `| ${i + 1} | ${ts} | ${e.source} | \`${e.ip}\` | ${e.method || '—'} | \`${(e.endpoint || '—').slice(0, 40)}\` | ${status} |\n`;
    }

    return lines;
  }

  _alertBreakdown(incident) {
    const alerts = incident.alerts || [];
    if (alerts.length === 0) return '## 🚨 Alert Breakdown\n\nNo alerts triggered.';

    let lines = `## 🚨 Alert Breakdown\n\n`;
    lines += `| # | Severity | Rule | Category | Matched Pattern | IP |\n`;
    lines += `|---|----------|------|----------|-----------------|----|\n`;

    for (let i = 0; i < alerts.length; i++) {
      const a = alerts[i];
      const ip = a.event?.ip || '—';
      const pattern = (a.matchedPattern || '—').slice(0, 30);
      lines += `| ${i + 1} | ${badge(a.severity)} | \`${a.ruleId}\` | ${a.category} | \`${pattern}\` | \`${ip}\` |\n`;
    }

    return lines;
  }

  _attackChains(incident) {
    const chains = incident.attackChains || [];
    if (chains.length === 0) return '## ⛓️ Attack Chains\n\nNo attack chains identified.';

    let lines = `## ⛓️ Attack Chains\n\n`;

    for (let i = 0; i < chains.length; i++) {
      const c = chains[i];
      lines += `### Chain ${i + 1}: \`${c.ip}\`\n\n`;
      lines += `- **Threat Score:** ${c.threatScore}/100\n`;
      lines += `- **Time Span:** ${formatTs(c.startTime)} → ${formatTs(c.endTime)}\n`;
      lines += `- **Description:** ${c.description}\n`;
      lines += `- **Events in Chain:** ${c.events?.length || 0}\n`;
      lines += `- **Alerts in Chain:** ${c.alerts?.length || 0}\n\n`;
    }

    return lines;
  }

  _evidence(incident) {
    const alerts = (incident.alerts || []).slice(0, 20);
    if (alerts.length === 0) return '## 📋 Evidence\n\nNo evidence captured.';

    let lines = `## 📋 Evidence (Raw Log Lines)\n\n`;
    lines += `*Showing evidence for first ${alerts.length} alerts*\n\n`;

    for (let i = 0; i < alerts.length; i++) {
      const a = alerts[i];
      if (!a.event?.rawLine) continue;
      lines += `**Alert ${i + 1}** — \`${a.ruleId}\` (${a.severity})\n`;
      lines += `\`\`\`\n${a.event.rawLine}\n\`\`\`\n\n`;
    }

    return lines;
  }

  _recommendations(incident) {
    const attackers = incident.attackers || [];
    const alerts = incident.alerts || [];
    const s = incident.summary || {};
    const recs = [];

    // IP blocking
    for (const a of attackers) {
      if (a.threatScore >= 50) {
        recs.push(`🚫 **Block IP \`${a.ip}\`** — Threat score ${a.threatScore}/100 with ${a.alerts || 0} alerts`);
      }
    }

    // Category-specific recommendations
    const categories = new Set(alerts.map(a => a.category));
    if (categories.has('SQL Injection')) {
      recs.push('🛡️ **Implement parameterized queries** — SQL injection attempts detected. Review all database query construction.');
    }
    if (categories.has('Brute Force')) {
      recs.push('🔒 **Enable rate limiting and account lockout** — Brute force attempts detected. Implement CAPTCHA after 3 failed attempts.');
    }
    if (categories.has('Path Traversal')) {
      recs.push('📁 **Sanitize file path inputs** — Path traversal attempts detected. Validate and canonicalize all file paths.');
    }
    if (categories.has('XSS')) {
      recs.push('🔤 **Implement Content Security Policy (CSP)** — XSS attempts detected. Sanitize all user input and enable CSP headers.');
    }
    if (categories.has('Command Injection')) {
      recs.push('⚠️ **Avoid shell command execution from user input** — Command injection attempts detected. Use parameterized system calls.');
    }

    // General
    if ((s.threatScore || 0) >= 70) {
      recs.push('🔴 **Escalate to security team** — High threat score indicates an active and sophisticated attack.');
    }
    recs.push('📊 **Review WAF rules** — Ensure Web Application Firewall rules cover all detected attack patterns.');
    recs.push('📝 **Preserve log files** — Retain all referenced log files as forensic evidence for potential legal proceedings.');

    let lines = `## 💡 Recommendations\n\n`;
    for (const rec of recs) {
      lines += `${rec}\n\n`;
    }
    return lines;
  }

  _footer(incident) {
    return `---\n\n*Report generated by Project Phoenix — Automated Log Correlation & Incident Forensics Dashboard*  \n*This report was produced using deterministic, rule-based analysis. No AI inference was used.*`;
  }
}
