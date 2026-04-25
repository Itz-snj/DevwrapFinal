/**
 * Project Phoenix — Brute Force Detection Rules
 * 
 * Detects brute force patterns via aggregation logic (not just regex).
 * The RuleEngine handles the aggregation; this file defines thresholds
 * and the patterns that identify failed authentication attempts.
 * 
 * Detection: N+ failed login attempts from a single IP within T seconds.
 */

export default [
  {
    id: 'BRUTE_FORCE_LOGIN',
    category: 'Brute Force',
    severity: 'HIGH',
    description: 'Multiple failed login attempts from the same IP — possible brute force attack',
    // This rule uses aggregation, not per-event regex
    type: 'aggregation',
    match: (event) => {
      // Match failed auth events (status 401, 403, or auth failure metadata)
      if (event.statusCode === 401 || event.statusCode === 403) return true;
      if (event.metadata?.authResult === 'failed') return true;
      if (event.metadata?.authResult === 'pam_failure') return true;
      return false;
    },
    threshold: 5,          // Minimum failed attempts to trigger
    windowSeconds: 300,    // Time window (5 minutes)
    groupBy: 'ip'          // Group by IP address
  },
  {
    id: 'BRUTE_FORCE_MAX_ATTEMPTS',
    category: 'Brute Force',
    severity: 'CRITICAL',
    description: 'Maximum authentication attempts exceeded — confirmed brute force',
    pattern: /maximum authentication attempts exceeded/gi,
    fields: ['rawLine']
  },
  {
    id: 'BRUTE_FORCE_RAPID_REQUESTS',
    category: 'Brute Force',
    severity: 'MEDIUM',
    description: 'Rapid sequential requests to the same endpoint from a single IP',
    type: 'aggregation',
    match: (event) => {
      // Match any request to login-related endpoints
      const loginEndpoints = ['/login', '/admin/login', '/auth', '/signin', '/api/auth'];
      return loginEndpoints.some(ep => event.endpoint?.toLowerCase().includes(ep));
    },
    threshold: 10,
    windowSeconds: 60,   // 10+ requests in 1 minute
    groupBy: 'ip'
  }
];
