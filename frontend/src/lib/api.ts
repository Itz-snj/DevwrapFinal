import { MOCK_INCIDENTS, MOCK_ATTACKERS, MOCK_TIMELINE_EVENTS, MOCK_GRAPH, MOCK_RULES, MOCK_HEALTH, MOCK_INCIDENT_DETAIL } from "@/data/mock";

export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:3001";
export const WS_BASE = API_BASE.replace(/^http/, "ws");

async function tryFetch<T>(path: string, init?: RequestInit, fallback?: T): Promise<T> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000); // 15s to handle Render free-tier cold starts
    const res = await fetch(`${API_BASE}${path}`, { ...init, signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) throw new Error(String(res.status));
    return (await res.json()) as T;
  } catch {
    if (fallback !== undefined) return fallback;
    throw new Error("api unreachable");
  }
}

export const api = {
  health: () => tryFetch("/api/health", undefined, MOCK_HEALTH),
  rules: () => tryFetch("/api/rules", undefined, MOCK_RULES),
  incidents: () =>
    tryFetch<{ incidents: typeof MOCK_INCIDENTS; total: number }>(
      "/api/incidents",
      undefined,
      { incidents: MOCK_INCIDENTS, total: MOCK_INCIDENTS.length },
    ),
  incident: (id: string) =>
    tryFetch("/api/incidents/" + id, undefined, { ...MOCK_INCIDENT_DETAIL, id }),
  timeline: (id: string, page = 1, pageSize = 50) =>
    tryFetch(`/api/incidents/${id}/timeline?page=${page}&pageSize=${pageSize}`, undefined, {
      events: MOCK_TIMELINE_EVENTS,
      totalEvents: MOCK_TIMELINE_EVENTS.length,
      page,
      pageSize,
      totalPages: 1,
    }),
  graph: (id: string) => tryFetch("/api/incidents/" + id + "/graph", undefined, MOCK_GRAPH),
  ipLookup: (ip: string) =>
    tryFetch("/api/ip/" + ip, undefined, {
      ip,
      geo: { country: "Unknown", city: "Unknown", lat: 0, lon: 0 },
      isp: "Unknown",
      org: "Unknown",
      as: "AS0",
      isPrivate: false,
      cached: true,
    }),
  deleteIncident: (id: string) =>
    tryFetch("/api/incidents/" + id, { method: "DELETE" }, { message: "deleted (mock)", id }),
  reportUrl: (id: string, format: "md" | "pdf") =>
    `${API_BASE}/api/incidents/${id}/report?format=${format}`,
  upload: async (files: File[]) => {
    const fd = new FormData();
    files.forEach((f) => fd.append("files", f));
    try {
      const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: fd });
      if (!res.ok) throw new Error();
      return await res.json();
    } catch {
      // mock response
      return {
        incidentId: MOCK_INCIDENTS[0].id,
        files: files.map((f) => ({ filename: f.name, format: "nginx", confidence: 0.95, events: 1234 })),
        summary: MOCK_INCIDENT_DETAIL.summary,
        attackers: MOCK_ATTACKERS,
      };
    }
  },
};
