export const MOCK_HEALTH = {
  status: "ok",
  service: "phoenix-forensics",
  version: "1.0.0",
  uptime: 18234,
  timestamp: new Date().toISOString(),
  incidents: 2,
};

export const MOCK_RULES = {
  totalRules: 28,
  regexRules: 22,
  aggregationRules: 6,
  categories: {
    "SQL Injection": 9,
    "Brute Force": 5,
    "Path Traversal": 6,
    "XSS": 4,
    "Command Injection": 4,
  },
};

export const MOCK_INCIDENTS = [
  {
    id: "inc_f7a291",
    createdAt: "2026-04-25T09:45:00Z",
    status: "analyzed",
    threatScore: 87,
    totalAlerts: 47,
    totalEvents: 4523,
    topAttackerIp: "192.168.1.105",
    attackTypes: [
      { type: "SQL Injection", count: 15, severity: "CRITICAL" as const },
      { type: "Brute Force", count: 23, severity: "HIGH" as const },
      { type: "Path Traversal", count: 9, severity: "CRITICAL" as const },
      { type: "XSS", count: 4, severity: "MEDIUM" as const },
    ],
    alertsBySeverity: { CRITICAL: 12, HIGH: 18, MEDIUM: 10, LOW: 7 },
  },
  {
    id: "inc_b3c842",
    createdAt: "2026-04-24T14:30:00Z",
    status: "analyzed",
    threatScore: 45,
    totalAlerts: 12,
    totalEvents: 890,
    topAttackerIp: "10.0.0.42",
    attackTypes: [
      { type: "Brute Force", count: 8, severity: "HIGH" as const },
      { type: "Path Traversal", count: 4, severity: "MEDIUM" as const },
    ],
    alertsBySeverity: { CRITICAL: 2, HIGH: 5, MEDIUM: 3, LOW: 2 },
  },
  {
    id: "inc_c9d103",
    createdAt: "2026-04-23T11:12:00Z",
    status: "analyzed",
    threatScore: 22,
    totalAlerts: 4,
    totalEvents: 312,
    topAttackerIp: "172.16.4.8",
    attackTypes: [{ type: "XSS", count: 4, severity: "LOW" as const }],
    alertsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 3 },
  },
];

export const MOCK_ATTACKERS = [
  {
    ip: "192.168.1.105",
    threatScore: 92,
    totalRequests: 234,
    alerts: 38,
    geo: { country: "Russia", city: "Moscow", lat: 55.7558, lon: 37.6173 },
    isp: "Rostelecom",
    org: "ShadowNet LLC",
    attackTypes: ["SQL Injection", "Path Traversal", "Brute Force"],
    targetedEndpoints: ["/admin/login", "/api/users", "/api/search?q=UNION", "/etc/passwd"],
    userAgents: ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"],
    firstSeen: "2026-04-25T08:02:00Z",
    lastSeen: "2026-04-25T09:28:00Z",
  },
  {
    ip: "10.0.0.42",
    threatScore: 65,
    totalRequests: 89,
    alerts: 12,
    geo: { country: "China", city: "Shanghai", lat: 31.2304, lon: 121.4737 },
    isp: "China Telecom",
    org: "Unknown",
    attackTypes: ["Brute Force"],
    targetedEndpoints: ["/admin/login", "/login"],
    userAgents: ["curl/7.68.0"],
    firstSeen: "2026-04-25T08:15:00Z",
    lastSeen: "2026-04-25T09:10:00Z",
  },
];

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type TimelineEvent = {
  timestamp: string;
  source: "nginx" | "auth" | "app";
  ip: string;
  method: string;
  endpoint: string;
  statusCode: number;
  logLevel: string;
  rawLine: string;
  alerts: { ruleId: string; severity: Severity; category: string; description: string }[];
};

export const MOCK_TIMELINE_EVENTS: TimelineEvent[] = [
  { timestamp: "2026-04-25T08:02:15Z", source: "auth", ip: "192.168.1.105", method: "POST", endpoint: "/admin/login", statusCode: 401, logLevel: "warn", rawLine: "Failed password for admin from 192.168.1.105", alerts: [{ ruleId: "BRUTE_FORCE_LOGIN", severity: "HIGH", category: "Brute Force", description: "Failed login attempt" }] },
  { timestamp: "2026-04-25T08:02:18Z", source: "auth", ip: "192.168.1.105", method: "POST", endpoint: "/admin/login", statusCode: 401, logLevel: "warn", rawLine: "Failed password for admin from 192.168.1.105", alerts: [] },
  { timestamp: "2026-04-25T08:05:30Z", source: "nginx", ip: "192.168.1.105", method: "GET", endpoint: "/api/search?q=1' OR '1'='1", statusCode: 200, logLevel: "info", rawLine: "GET /api/search?q=1'%20OR%20'1'='1 200 4521", alerts: [{ ruleId: "SQLI_TAUTOLOGY", severity: "CRITICAL", category: "SQL Injection", description: "Tautology-based SQL injection" }] },
  { timestamp: "2026-04-25T08:10:45Z", source: "nginx", ip: "192.168.1.105", method: "GET", endpoint: "/../../etc/passwd", statusCode: 200, logLevel: "info", rawLine: "GET /../../etc/passwd 200 1253", alerts: [{ ruleId: "PATH_TRAVERSAL_ETC_PASSWD", severity: "CRITICAL", category: "Path Traversal", description: "Attempt to access /etc/passwd" }] },
  { timestamp: "2026-04-25T08:15:22Z", source: "app", ip: "10.0.0.42", method: "POST", endpoint: "/api/auth/login", statusCode: 401, logLevel: "warn", rawLine: '{"level":"warn","message":"Login failed"}', alerts: [{ ruleId: "BRUTE_FORCE_LOGIN", severity: "HIGH", category: "Brute Force", description: "Failed login attempt" }] },
  { timestamp: "2026-04-25T08:20:00Z", source: "nginx", ip: "192.168.1.105", method: "GET", endpoint: "/api/users", statusCode: 200, logLevel: "info", rawLine: "GET /api/users 200 8920", alerts: [] },
  { timestamp: "2026-04-25T08:25:10Z", source: "nginx", ip: "10.0.0.42", method: "GET", endpoint: "/admin/config", statusCode: 403, logLevel: "warn", rawLine: "GET /admin/config 403 256", alerts: [] },
  { timestamp: "2026-04-25T08:31:02Z", source: "nginx", ip: "192.168.1.105", method: "GET", endpoint: "/api/products?id=1;DROP TABLE users", statusCode: 500, logLevel: "error", rawLine: "GET /api/products?id=1;DROP%20TABLE%20users 500", alerts: [{ ruleId: "SQLI_DROP", severity: "CRITICAL", category: "SQL Injection", description: "DROP TABLE attempt" }] },
  { timestamp: "2026-04-25T08:40:11Z", source: "app", ip: "192.168.1.105", method: "GET", endpoint: "/profile?name=<script>alert(1)</script>", statusCode: 200, logLevel: "warn", rawLine: "XSS payload detected in query", alerts: [{ ruleId: "XSS_SCRIPT_TAG", severity: "MEDIUM", category: "XSS", description: "Reflected XSS payload" }] },
];

export const MOCK_GRAPH = {
  nodes: [
    { id: "ip_192.168.1.105", type: "attacker" as const, label: "192.168.1.105", threatScore: 92, geo: { country: "Russia", city: "Moscow" } },
    { id: "ip_10.0.0.42", type: "attacker" as const, label: "10.0.0.42", threatScore: 65, geo: { country: "China", city: "Shanghai" } },
    { id: "ep_admin_login", type: "endpoint" as const, label: "/admin/login", requestCount: 47 },
    { id: "ep_api_search", type: "endpoint" as const, label: "/api/search", requestCount: 23 },
    { id: "ep_etc_passwd", type: "endpoint" as const, label: "/etc/passwd", requestCount: 9 },
    { id: "ep_api_users", type: "endpoint" as const, label: "/api/users", requestCount: 18 },
    { id: "res_users_db", type: "resource" as const, label: "users.db", severity: "CRITICAL" as const },
    { id: "res_secrets", type: "resource" as const, label: "secrets.env", severity: "HIGH" as const },
  ],
  edges: [
    { source: "ip_192.168.1.105", target: "ep_admin_login", weight: 24, severity: "HIGH" as const },
    { source: "ip_192.168.1.105", target: "ep_api_search", weight: 15, severity: "CRITICAL" as const },
    { source: "ip_192.168.1.105", target: "ep_etc_passwd", weight: 9, severity: "CRITICAL" as const },
    { source: "ip_192.168.1.105", target: "ep_api_users", weight: 12, severity: "MEDIUM" as const },
    { source: "ip_10.0.0.42", target: "ep_admin_login", weight: 23, severity: "HIGH" as const },
    { source: "ep_api_search", target: "res_users_db", weight: 8, severity: "CRITICAL" as const },
    { source: "ep_etc_passwd", target: "res_secrets", weight: 9, severity: "CRITICAL" as const },
    { source: "ep_api_users", target: "res_users_db", weight: 6, severity: "MEDIUM" as const },
  ],
};

export const MOCK_INCIDENT_DETAIL = {
  id: "inc_f7a291",
  createdAt: "2026-04-25T09:45:00Z",
  status: "analyzed",
  summary: {
    totalEvents: 4523,
    totalAlerts: 47,
    threatScore: 87,
    timeRange: { start: "2026-04-25T08:00:00Z", end: "2026-04-25T09:30:00Z" },
    topAttackerIp: "192.168.1.105",
    attackTypes: MOCK_INCIDENTS[0].attackTypes,
    alertsBySeverity: MOCK_INCIDENTS[0].alertsBySeverity,
  },
  attackers: MOCK_ATTACKERS,
  alertsBySeverity: MOCK_INCIDENTS[0].alertsBySeverity,
  attackTypes: MOCK_INCIDENTS[0].attackTypes,
};

export const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "bg-brut-red text-black",
  HIGH: "bg-brut-orange text-black",
  MEDIUM: "bg-brut-yellow text-black",
  LOW: "bg-brut-mint text-black",
};
