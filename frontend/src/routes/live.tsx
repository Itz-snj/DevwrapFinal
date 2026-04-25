import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { PageShell } from "@/components/Sidebar";
import { BrutCard, BrutButton, SectionHeader, SevBadge } from "@/components/brut";
import { API_BASE, WS_BASE } from "@/lib/api";
import type { Severity, TimelineEvent } from "@/data/mock";

export const Route = createFileRoute("/live")({
  head: () => ({
    meta: [
      { title: "Live Monitor — Project Phoenix" },
      { name: "description", content: "Real-time event and alert stream." },
      { property: "og:title", content: "Live Monitor" },
      { property: "og:description", content: "Watch events as they happen." },
    ],
  }),
  component: Live,
});

const SAMPLE_IPS = ["192.168.1.105", "10.0.0.42", "172.16.4.8", "8.8.8.8", "203.0.113.45"];
const SAMPLE_ENDPOINTS = ["/admin/login", "/api/users", "/api/search?q=test", "/health", "/api/products/1", "/etc/passwd"];
const SAMPLE_SOURCES = ["nginx", "auth", "app"] as const;
const SAMPLE_SEV: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function genEvent(): TimelineEvent {
  const ip = SAMPLE_IPS[Math.floor(Math.random() * SAMPLE_IPS.length)];
  const endpoint = SAMPLE_ENDPOINTS[Math.floor(Math.random() * SAMPLE_ENDPOINTS.length)];
  const source = SAMPLE_SOURCES[Math.floor(Math.random() * SAMPLE_SOURCES.length)];
  const status = [200, 200, 200, 401, 403, 404, 500][Math.floor(Math.random() * 7)];
  const isAlert = Math.random() < 0.3;
  return {
    timestamp: new Date().toISOString(),
    source,
    ip,
    method: "GET",
    endpoint,
    statusCode: status,
    logLevel: status >= 500 ? "error" : status >= 400 ? "warn" : "info",
    rawLine: `${ip} ${endpoint} ${status}`,
    alerts: isAlert
      ? [{ ruleId: "AUTO_DETECT_" + Math.floor(Math.random() * 99), severity: SAMPLE_SEV[Math.floor(Math.random() * 4)], category: "Auto", description: "Suspicious pattern matched" }]
      : [],
  };
}

function statusColor(c: number) {
  if (c >= 500) return "bg-brut-red";
  if (c >= 400) return "bg-brut-yellow";
  if (c >= 300) return "bg-brut-sky";
  return "bg-brut-mint";
}
function sourceColor(s: string) {
  return s === "nginx" ? "bg-brut-sky" : s === "auth" ? "bg-brut-yellow" : "bg-brut-mint";
}

function Live() {
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [alerts, setAlerts] = useState<TimelineEvent["alerts"][number][]>([]);
  const [stats, setStats] = useState({ events: 0, alerts: 0, files: 3 });
  const wsRef = useRef<WebSocket | null>(null);
  const fallbackTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    let mounted = true;
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(`${WS_BASE}/ws/live`);
      wsRef.current = ws;
      ws.onopen = () => mounted && setConnected(true);
      ws.onclose = () => mounted && setConnected(false);
      ws.onerror = () => mounted && setConnected(false);
      ws.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          if (m.type === "event") pushEvent(m.data as TimelineEvent);
          if (m.type === "alert" && m.data) setAlerts((p) => [m.data, ...p].slice(0, 30));
          if (m.type === "stats" && m.data) setStats({ events: m.data.eventsProcessed, alerts: m.data.alertsGenerated, files: m.data.filesWatched });
        } catch {}
      };
    } catch {
      setConnected(false);
    }

    // Always run a fallback simulator so the page is alive in demo mode
    fallbackTimerRef.current = setInterval(() => {
      if (!mounted) return;
      // Only simulate if WS isn't actively pushing
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
        const e = genEvent();
        pushEvent(e);
        if (e.alerts.length) setAlerts((p) => [e.alerts[0], ...p].slice(0, 30));
      }
    }, 1500);

    function pushEvent(e: TimelineEvent) {
      if (paused) return;
      setEvents((prev) => [e, ...prev].slice(0, 100));
      setStats((s) => ({ ...s, events: s.events + 1, alerts: s.alerts + (e.alerts.length ? 1 : 0) }));
    }

    return () => {
      mounted = false;
      ws?.close();
      if (fallbackTimerRef.current) clearInterval(fallbackTimerRef.current);
    };
  }, [paused]);

  return (
    <PageShell>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display font-bold text-4xl uppercase tracking-tight">Live Monitor</h1>
          <p className="font-mono text-sm text-muted-foreground mt-1">// real-time event stream</p>
        </div>
        <span className={`brut-border-2 px-3 py-1.5 font-mono font-bold uppercase ${connected ? "bg-brut-mint" : "bg-brut-red text-white"}`}>
          ● {connected ? "Connected" : "Demo Mode"}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <BrutCard color="yellow"><div className="font-mono text-xs uppercase">Events Processed</div><div className="font-display font-bold text-3xl">{stats.events}</div></BrutCard>
        <BrutCard color="red"><div className="font-mono text-xs uppercase">Alerts Generated</div><div className="font-display font-bold text-3xl">{stats.alerts}</div></BrutCard>
        <BrutCard color="mint"><div className="font-mono text-xs uppercase">Files Watched</div><div className="font-display font-bold text-3xl">{stats.files}</div></BrutCard>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <BrutButton variant={paused ? "mint" : "yellow"} onClick={() => setPaused((p) => !p)}>{paused ? "Resume" : "Pause"}</BrutButton>
        <BrutButton variant="white" onClick={() => { setEvents([]); setAlerts([]); }}>Clear</BrutButton>
        <span className="border-l-2 border-black mx-1" />
        <BrutButton variant="black" onClick={() => fetch(`${API_BASE}/api/demo/inject`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ type: "brute-force" }) })}>🎯 Brute Force</BrutButton>
        <BrutButton variant="black" onClick={() => fetch(`${API_BASE}/api/demo/inject`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ type: "sqli" }) })}>🎯 SQL Injection</BrutButton>
        <BrutButton variant="black" onClick={() => fetch(`${API_BASE}/api/demo/inject`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ type: "mixed" }) })}>🎯 Mixed Attack</BrutButton>
        
        <span className="border-l-2 border-black mx-1" />
        <div className="flex items-center gap-2">
          <input 
            type="text" 
            id="remoteUrlInput"
            placeholder="Paste raw log URL (e.g. pastebin raw)" 
            className="brut-border-2 px-3 py-1.5 text-sm font-mono w-64 focus:outline-none focus:bg-brut-mint/20"
          />
          <BrutButton variant="black" onClick={() => {
            const urlInput = document.getElementById('remoteUrlInput') as HTMLInputElement;
            if (!urlInput?.value) return;
            
            fetch(`${API_BASE}/api/demo/fetch-remote`, { 
              method: "POST", 
              headers: { "Content-Type": "application/json" }, 
              body: JSON.stringify({ url: urlInput.value }) 
            })
            .then(res => res.json())
            .then(data => {
               if (data.error) alert('Error fetching remote log: ' + data.error);
               else {
                 alert(data.message);
                 urlInput.value = '';
               }
            })
            .catch(err => alert('Failed to contact backend: ' + err.message));
          }}>🌍 Fetch Remote Log</BrutButton>
        </div>
      </div>

      <div className="grid lg:grid-cols-[1fr_360px] gap-4">
        <BrutCard color="white" className="p-0">
          <div className="px-4 py-2 border-b-[3px] border-black bg-brut-yellow font-display font-bold uppercase tracking-wider">Event Stream</div>
          <div className="overflow-auto max-h-[600px]">
            <table className="w-full text-sm">
              <thead className="sticky top-0">
                <tr className="bg-brut-yellow border-b-[3px] border-black font-display uppercase">
                  <th className="text-left p-2">Time</th><th className="text-left p-2">Source</th><th className="text-left p-2">IP</th><th className="text-left p-2">Endpoint</th><th className="text-left p-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => {
                  const flash = e.alerts.length && (e.alerts[0].severity === "CRITICAL" || e.alerts[0].severity === "HIGH");
                  return (
                    <tr key={i} className={`border-b-2 border-black ${flash ? "bg-brut-red/40" : i % 2 ? "bg-secondary" : "bg-white"}`}>
                      <td className="p-2 font-mono text-xs whitespace-nowrap">{new Date(e.timestamp).toLocaleTimeString("en-GB", { hour12: false })}</td>
                      <td className="p-2"><span className={`brut-border-2 px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase ${sourceColor(e.source)}`}>{e.source}</span></td>
                      <td className="p-2 font-mono">{e.ip}</td>
                      <td className="p-2 font-mono text-xs max-w-[260px] truncate">{e.endpoint}</td>
                      <td className="p-2"><span className={`brut-border-2 px-1.5 py-0.5 text-[10px] font-mono font-bold ${statusColor(e.statusCode)}`}>{e.statusCode}</span></td>
                    </tr>
                  );
                })}
                {events.length === 0 && (
                  <tr><td colSpan={5} className="p-6 text-center font-mono text-muted-foreground">Waiting for events...</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </BrutCard>

        <BrutCard color="white" className="p-0">
          <div className="px-4 py-2 border-b-[3px] border-black bg-brut-red text-black font-display font-bold uppercase tracking-wider">Alerts</div>
          <div className="overflow-auto max-h-[600px] p-3 space-y-2">
            {alerts.length === 0 && <p className="font-mono text-sm text-muted-foreground">No alerts yet.</p>}
            {alerts.map((a, i) => (
              <div key={i} className={`brut-border-2 p-3 ${a.severity === "CRITICAL" ? "bg-brut-red" : a.severity === "HIGH" ? "bg-brut-orange" : a.severity === "MEDIUM" ? "bg-brut-yellow" : "bg-brut-mint"}`}>
                <div className="flex items-center justify-between mb-1">
                  <SevBadge severity={a.severity} className="bg-white" />
                  <span className="font-mono text-[10px]">{a.ruleId}</span>
                </div>
                <p className="font-mono text-xs">{a.description}</p>
                <p className="font-mono text-[11px] mt-1 opacity-80">cat: {a.category}</p>
              </div>
            ))}
          </div>
        </BrutCard>
      </div>
    </PageShell>
  );
}
