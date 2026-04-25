import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageShell } from "@/components/Sidebar";
import { BrutCard, SectionHeader, SevBadge, Bar, BrutButton, LoadingBox } from "@/components/brut";
import { api } from "@/lib/api";
import { MOCK_INCIDENTS, MOCK_ATTACKERS, MOCK_TIMELINE_EVENTS, type Severity } from "@/data/mock";
import { AlertTriangle, Activity, Zap, ShieldAlert } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — Project Phoenix" },
      { name: "description", content: "Overview of incidents, threats, and active attackers." },
      { property: "og:title", content: "Phoenix Dashboard" },
      { property: "og:description", content: "Live incident forensics overview." },
    ],
  }),
  component: Dashboard,
});

function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [incidents, setIncidents] = useState(MOCK_INCIDENTS);

  useEffect(() => {
    api.incidents().then((d) => {
      setIncidents(d.incidents);
      setLoading(false);
    });
  }, []);

  const totalEvents = incidents.reduce((s, i) => s + i.totalEvents, 0);
  const totalAlerts = incidents.reduce((s, i) => s + i.totalAlerts, 0);
  const avgScore = Math.round(incidents.reduce((s, i) => s + i.threatScore, 0) / Math.max(1, incidents.length));
  const sevTotals = incidents.reduce(
    (acc, i) => {
      const sev = i.alertsBySeverity ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      (Object.keys(sev) as Severity[]).forEach((k) => (acc[k] += sev[k] ?? 0));
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<Severity, number>,
  );
  const sevMax = Math.max(...Object.values(sevTotals), 1);

  return (
    <PageShell>
      <div className="mb-8">
        <h1 className="font-display font-bold text-4xl uppercase tracking-tight">Forensics Dashboard</h1>
        <p className="font-mono text-sm text-muted-foreground mt-1">
          // monitoring {incidents.length} incidents — {loading ? "syncing…" : "synced"}
        </p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <BrutCard color="yellow">
          <Zap className="mb-2" size={28} />
          <div className="font-mono text-xs uppercase tracking-widest">Total Events</div>
          <div className="font-display font-bold text-4xl mt-1">{totalEvents.toLocaleString()}</div>
        </BrutCard>
        <BrutCard color="red">
          <AlertTriangle className="mb-2" size={28} />
          <div className="font-mono text-xs uppercase tracking-widest">Active Threats</div>
          <div className="font-display font-bold text-4xl mt-1">{sevTotals.CRITICAL + sevTotals.HIGH}</div>
        </BrutCard>
        <BrutCard color="white">
          <ShieldAlert className="mb-2" size={28} />
          <div className="font-mono text-xs uppercase tracking-widest">Threat Score</div>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="font-display font-bold text-4xl">{avgScore}</span>
            <span className="font-mono text-sm">/100</span>
          </div>
          <div className="mt-3">
            <Bar value={avgScore} color={avgScore > 70 ? "red" : avgScore > 40 ? "orange" : "mint"} />
          </div>
        </BrutCard>
        <BrutCard color="mint">
          <Activity className="mb-2" size={28} />
          <div className="font-mono text-xs uppercase tracking-widest">Incidents</div>
          <div className="font-display font-bold text-4xl mt-1">{incidents.length}</div>
        </BrutCard>
      </div>

      <div className="grid lg:grid-cols-2 gap-6 mb-8">
        <BrutCard color="white">
          <SectionHeader>Alerts by Severity</SectionHeader>
          <div className="space-y-3">
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]).map((sev) => (
              <div key={sev} className="flex items-center gap-3">
                <div className="w-24"><SevBadge severity={sev} /></div>
                <div className="flex-1 brut-border-2 bg-white h-7">
                  <div
                    className={`h-full ${
                      sev === "CRITICAL" ? "bg-brut-red" : sev === "HIGH" ? "bg-brut-orange" : sev === "MEDIUM" ? "bg-brut-yellow" : "bg-brut-mint"
                    }`}
                    style={{ width: `${(sevTotals[sev] / sevMax) * 100}%` }}
                  />
                </div>
                <div className="w-10 text-right font-mono font-bold">{sevTotals[sev]}</div>
              </div>
            ))}
          </div>
        </BrutCard>

        <BrutCard color="white">
          <SectionHeader>Recent Alerts</SectionHeader>
          <div className="brut-border-2 max-h-72 overflow-auto">
            {MOCK_TIMELINE_EVENTS.filter((e) => e.alerts.length).map((e, idx) => (
              <div
                key={idx}
                className={`flex items-center gap-3 px-3 py-2 border-b-2 border-black last:border-b-0 ${idx % 2 ? "bg-secondary" : "bg-white"}`}
              >
                <SevBadge severity={e.alerts[0].severity} />
                <span className="font-mono text-xs font-bold">{e.alerts[0].ruleId}</span>
                <span className="font-mono text-xs flex-1 truncate">{e.ip}</span>
                <span className="font-mono text-[11px] text-muted-foreground">{new Date(e.timestamp).toLocaleTimeString("en-GB", { hour12: false })}</span>
              </div>
            ))}
          </div>
        </BrutCard>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <BrutCard color="white">
          <SectionHeader>Attack Types</SectionHeader>
          <div className="space-y-2">
            {(incidents[0]?.attackTypes ?? []).map((a) => (
              <div key={a.type} className="flex items-center gap-3 brut-border-2 bg-secondary px-3 py-2">
                <span className="font-mono font-bold flex-1">{a.type}</span>
                <SevBadge severity={a.severity} />
                <span className="font-display font-bold text-lg w-10 text-right">{a.count}</span>
              </div>
            ))}
          </div>
        </BrutCard>

        <BrutCard color="white">
          <SectionHeader>Top Attackers</SectionHeader>
          <div className="brut-border-2 overflow-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-brut-yellow border-b-[3px] border-black font-display uppercase">
                  <th className="text-left p-2">IP</th>
                  <th className="text-left p-2">Geo</th>
                  <th className="text-left p-2">Score</th>
                  <th className="text-right p-2">Alerts</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_ATTACKERS.map((a, i) => (
                  <tr key={a.ip} className={`${i % 2 ? "bg-secondary" : "bg-white"} border-b-2 border-black last:border-b-0`}>
                    <td className="p-2 font-mono font-bold">{a.ip}</td>
                    <td className="p-2 font-mono text-xs">{a.geo.country}</td>
                    <td className="p-2 w-24">
                      <Bar value={a.threatScore} color={a.threatScore > 70 ? "red" : "orange"} />
                    </td>
                    <td className="p-2 text-right font-mono font-bold">{a.alerts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4">
            <Link to="/incidents">
              <BrutButton variant="black">View All Incidents →</BrutButton>
            </Link>
          </div>
        </BrutCard>
      </div>

      {loading && (
        <div className="mt-6">
          <LoadingBox />
        </div>
      )}
    </PageShell>
  );
}
