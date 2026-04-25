import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageShell } from "@/components/Sidebar";
import { BrutCard, BrutButton, SectionHeader, SevBadge, Bar, LoadingBox } from "@/components/brut";
import { api } from "@/lib/api";
import { MOCK_INCIDENT_DETAIL, MOCK_TIMELINE_EVENTS, MOCK_GRAPH, type Severity, type TimelineEvent } from "@/data/mock";
import { toast } from "sonner";
import { Download, Trash2 } from "lucide-react";
import { BlastRadius } from "@/components/BlastRadius";

export const Route = createFileRoute("/incidents/$id")({
  head: ({ params }) => ({
    meta: [
      { title: `Incident ${params.id} — Project Phoenix` },
      { name: "description", content: `Forensic detail for incident ${params.id}.` },
      { property: "og:title", content: `Incident ${params.id}` },
      { property: "og:description", content: "Phoenix incident forensics report." },
    ],
  }),
  component: IncidentDetail,
});

const TABS = ["Overview", "Timeline", "Blast Radius", "Attacker Intel"] as const;
type Tab = (typeof TABS)[number];

function scoreBadge(s: number) {
  return s >= 70 ? "bg-brut-red" : s >= 40 ? "bg-brut-orange" : "bg-brut-mint";
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

function IncidentDetail() {
  const { id } = Route.useParams();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("Overview");
  const [data, setData] = useState<typeof MOCK_INCIDENT_DETAIL | null>(null);

  useEffect(() => {
    api.incident(id).then((d) => setData(d as typeof MOCK_INCIDENT_DETAIL));
  }, [id]);

  if (!data) return <PageShell><LoadingBox /></PageShell>;

  const onDelete = async () => {
    await api.deleteIncident(id);
    toast.success("Incident deleted");
    navigate({ to: "/incidents" });
  };

  return (
    <PageShell>
      <div className="mb-6 flex flex-wrap items-end gap-3 justify-between">
        <div>
          <p className="font-mono text-sm text-muted-foreground">{new Date(data.createdAt).toLocaleString("en-GB", { hour12: false })}</p>
          <h1 className="font-display font-bold text-3xl uppercase tracking-tight flex items-center gap-3">
            <span className="font-mono">{id}</span>
            <span className={`brut-border-2 px-2 py-0.5 text-base font-mono font-bold ${scoreBadge(data.summary.threatScore)}`}>
              {data.summary.threatScore}/100
            </span>
          </h1>
        </div>
        <div className="flex gap-2">
          <a href={api.reportUrl(id, "md")} target="_blank" rel="noreferrer">
            <BrutButton><Download size={16}/> Download Report</BrutButton>
          </a>
          <BrutButton variant="red" onClick={onDelete}><Trash2 size={16}/> Delete</BrutButton>
        </div>
      </div>

      <div className="flex gap-1 mb-6 overflow-auto">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`brut-border-2 brut-press px-4 py-2 font-display font-bold uppercase tracking-wider text-sm whitespace-nowrap ${
              tab === t ? "bg-brut-yellow border-b-[6px]" : "bg-white"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Overview" && <OverviewTab data={data} />}
      {tab === "Timeline" && <TimelineTab id={id} />}
      {tab === "Blast Radius" && <BlastRadius id={id} />}
      {tab === "Attacker Intel" && <AttackerIntel data={data} />}
    </PageShell>
  );
}

function OverviewTab({ data }: { data: typeof MOCK_INCIDENT_DETAIL }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <BrutCard color="yellow"><div className="font-mono text-xs uppercase">Events</div><div className="font-display font-bold text-3xl">{data.summary.totalEvents.toLocaleString()}</div></BrutCard>
        <BrutCard color="red"><div className="font-mono text-xs uppercase">Alerts</div><div className="font-display font-bold text-3xl">{data.summary.totalAlerts}</div></BrutCard>
        <BrutCard color="sky"><div className="font-mono text-xs uppercase">Score</div><div className="font-display font-bold text-3xl">{data.summary.threatScore}</div></BrutCard>
        <BrutCard color="mint"><div className="font-mono text-xs uppercase">Top Attacker</div><div className="font-mono font-bold text-lg break-all">{data.summary.topAttackerIp}</div></BrutCard>
      </div>

      <BrutCard color="white">
        <SectionHeader>Attacker Profiles</SectionHeader>
        <div className="grid lg:grid-cols-2 gap-4">
          {data.attackers.map((a) => (
            <div key={a.ip} className="brut-border-2 bg-secondary p-4">
              <div className="flex items-baseline justify-between mb-2">
                <span className="font-mono font-bold text-xl">{a.ip}</span>
                <span className={`brut-border-2 px-2 py-0.5 font-mono font-bold ${scoreBadge(a.threatScore)}`}>{a.threatScore}</span>
              </div>
              <p className="font-mono text-sm">{a.geo?.city ?? "Unknown"}, {a.geo?.country ?? "Unknown"}</p>
              <p className="font-mono text-xs text-muted-foreground">{a.isp} • {a.org}</p>
              <div className="my-3"><Bar value={a.threatScore} color="red" /></div>
              <div className="flex flex-wrap gap-1 mb-3">
                {(a.attackTypes ?? []).map((t) => (
                  <span key={t} className="brut-border-2 bg-brut-yellow px-2 py-0.5 text-xs font-mono font-bold">{t}</span>
                ))}
              </div>
              <div className="font-mono text-xs text-muted-foreground">
                {new Date(a.firstSeen).toLocaleTimeString("en-GB", { hour12: false })} → {new Date(a.lastSeen).toLocaleTimeString("en-GB", { hour12: false })}
              </div>
            </div>
          ))}
        </div>
      </BrutCard>

      <BrutCard color="white">
        <SectionHeader>Attack Types</SectionHeader>
        <div className="brut-border-2 overflow-auto">
          <table className="w-full text-sm">
            <thead><tr className="bg-brut-yellow border-b-[3px] border-black font-display uppercase">
              <th className="text-left p-2">Type</th><th className="text-left p-2">Severity</th><th className="text-right p-2">Count</th>
            </tr></thead>
            <tbody>
              {data.summary.attackTypes.map((t, i) => (
                <tr key={t.type} className={`${i % 2 ? "bg-secondary" : "bg-white"} border-b-2 border-black last:border-b-0`}>
                  <td className="p-2 font-mono font-bold">{t.type}</td>
                  <td className="p-2"><SevBadge severity={t.severity} /></td>
                  <td className="p-2 text-right font-mono font-bold">{t.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </BrutCard>
    </div>
  );
}

function TimelineTab({ id }: { id: string }) {
  const [events, setEvents] = useState<TimelineEvent[]>(MOCK_TIMELINE_EVENTS);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [filterSrc, setFilterSrc] = useState<string>("all");
  const [filterIp, setFilterIp] = useState("");

  useEffect(() => {
    api.timeline(id, page, 50).then((d) => {
      setEvents(d.events as TimelineEvent[]);
      setTotalPages(d.totalPages || 1);
    });
  }, [id, page]);

  const filtered = events.filter((e) => (filterSrc === "all" || e.source === filterSrc) && (!filterIp || e.ip.includes(filterIp)));

  return (
    <div className="space-y-4">
      <BrutCard color="white">
        <div className="flex flex-wrap gap-3 items-center">
          <select value={filterSrc} onChange={(e) => setFilterSrc(e.target.value)} className="brut-border-2 bg-white px-3 py-1.5 font-mono text-sm">
            <option value="all">All Sources</option>
            <option value="nginx">nginx</option>
            <option value="auth">auth</option>
            <option value="app">app</option>
          </select>
          <input
            placeholder="Filter IP..."
            value={filterIp}
            onChange={(e) => setFilterIp(e.target.value)}
            className="brut-border-2 bg-white px-3 py-1.5 font-mono text-sm focus:outline-none focus:border-brut-yellow"
          />
          <span className="font-mono text-sm text-muted-foreground ml-auto">{filtered.length} events</span>
        </div>
      </BrutCard>

      <BrutCard color="white" className="p-0">
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead><tr className="bg-brut-yellow border-b-[3px] border-black font-display uppercase">
              <th className="text-left p-2 w-10">#</th>
              <th className="text-left p-2">Time</th>
              <th className="text-left p-2">Source</th>
              <th className="text-left p-2">IP</th>
              <th className="text-left p-2">Method</th>
              <th className="text-left p-2">Endpoint</th>
              <th className="text-left p-2">Status</th>
              <th className="text-left p-2">Alerts</th>
            </tr></thead>
            <tbody>
              {filtered.map((e, i) => (
                <tr key={i} className={`${i % 2 ? "bg-secondary" : "bg-white"} border-b-2 border-black last:border-b-0`}>
                  <td className="p-2 font-mono">{i + 1}</td>
                  <td className="p-2 font-mono text-xs whitespace-nowrap">{new Date(e.timestamp).toLocaleTimeString("en-GB", { hour12: false })}</td>
                  <td className="p-2"><span className={`brut-border-2 px-2 py-0.5 text-xs font-mono font-bold uppercase ${sourceColor(e.source)}`}>{e.source}</span></td>
                  <td className="p-2 font-mono">{e.ip}</td>
                  <td className="p-2 font-mono text-xs">{e.method}</td>
                  <td className="p-2 font-mono text-xs max-w-[300px] truncate" title={e.endpoint}>{e.endpoint}</td>
                  <td className="p-2"><span className={`brut-border-2 px-2 py-0.5 text-xs font-mono font-bold ${statusColor(e.statusCode)}`}>{e.statusCode}</span></td>
                  <td className="p-2 space-x-1">
                    {e.alerts.map((a) => <SevBadge key={a.ruleId} severity={a.severity} />)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </BrutCard>

      <div className="flex items-center justify-center gap-3">
        <BrutButton variant="white" disabled={page <= 1} onClick={() => setPage(page - 1)}>← Prev</BrutButton>
        <span className="font-mono font-bold">Page {page} of {totalPages}</span>
        <BrutButton variant="white" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next →</BrutButton>
      </div>
    </div>
  );
}

function AttackerIntel({ data }: { data: typeof MOCK_INCIDENT_DETAIL }) {
  return (
    <div className="space-y-5">
      {data.attackers.map((a) => (
        <BrutCard color="white" key={a.ip}>
          <div className="flex flex-wrap items-baseline gap-3 mb-4">
            <span className="font-mono font-bold text-2xl bg-brut-yellow px-2 brut-border-2">{a.ip}</span>
            <span className="font-mono">{a.geo?.city ?? "Unknown"}, {a.geo?.country ?? "Unknown"}</span>
            <span className={`ml-auto brut-border-2 px-2 py-0.5 font-mono font-bold ${scoreBadge(a.threatScore)}`}>{a.threatScore}/100</span>
          </div>
          <p className="font-mono text-sm text-muted-foreground mb-4">ISP: {a.isp} • Org: {a.org}</p>

          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="brut-border-2 bg-secondary p-3"><div className="font-mono text-xs uppercase">Requests</div><div className="font-display font-bold text-2xl">{a.totalRequests}</div></div>
            <div className="brut-border-2 bg-secondary p-3"><div className="font-mono text-xs uppercase">Alerts</div><div className="font-display font-bold text-2xl">{a.alerts}</div></div>
            <div className="brut-border-2 bg-secondary p-3"><div className="font-mono text-xs uppercase">Endpoints</div><div className="font-display font-bold text-2xl">{(a.targetedEndpoints ?? []).length}</div></div>
          </div>

          <Bar value={a.threatScore} color="red" />

          <div className="flex flex-wrap gap-1 mt-4">
            {(a.attackTypes ?? []).map((t) => (
              <span key={t} className="brut-border-2 bg-brut-yellow px-2 py-0.5 text-xs font-mono font-bold">{t}</span>
            ))}
          </div>

          <div className="mt-4 brut-border-2 bg-brut-black text-brut-yellow font-mono text-xs p-3">
            {(a.userAgents ?? []).map((ua, i) => <div key={i}>$ {ua}</div>)}
          </div>

          <div className="mt-4">
            <BrutButton variant="black" onClick={async () => {
              const r = await api.ipLookup(a.ip);
              toast.success(`${r.ip} → ${r.geo?.country ?? "Unknown"} (${r.isp})`);
            }}>Lookup IP</BrutButton>
          </div>
        </BrutCard>
      ))}
    </div>
  );
}

export { Route as incidentDetailRoute };
