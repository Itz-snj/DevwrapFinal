import { createFileRoute, Link, Outlet, useMatch } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageShell } from "@/components/Sidebar";
import { BrutCard, BrutButton, SectionHeader, EmptyState } from "@/components/brut";
import { api } from "@/lib/api";
import { MOCK_INCIDENTS } from "@/data/mock";
import { toast } from "sonner";

export const Route = createFileRoute("/incidents")({
  head: () => ({
    meta: [
      { title: "Incidents — Project Phoenix" },
      { name: "description", content: "All analyzed security incidents." },
      { property: "og:title", content: "Incidents" },
      { property: "og:description", content: "Browse forensic incidents." },
    ],
  }),
  component: IncidentsLayout,
});

function scoreColor(s: number) {
  if (s >= 70) return "bg-brut-red";
  if (s >= 40) return "bg-brut-orange";
  return "bg-brut-mint";
}

function IncidentsLayout() {
  // If a child route is active (e.g. /incidents/$id), render it
  const childMatch = useMatch({ from: "/incidents/$id", shouldThrow: false });
  if (childMatch) return <Outlet />;
  // Otherwise, show the incidents list
  return <IncidentsList />;
}

function IncidentsList() {
  const [incidents, setIncidents] = useState(MOCK_INCIDENTS);

  useEffect(() => {
    api.incidents().then((d) => setIncidents(d.incidents));
  }, []);

  const remove = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    await api.deleteIncident(id);
    setIncidents((prev) => prev.filter((i) => i.id !== id));
    toast.success("Incident deleted");
  };

  return (
    <PageShell>
      <div className="mb-8 flex items-end justify-between">
        <div>
          <h1 className="font-display font-bold text-4xl uppercase tracking-tight">Incidents</h1>
          <p className="font-mono text-sm text-muted-foreground mt-1">// {incidents.length} stored</p>
        </div>
        <Link to="/upload"><BrutButton>+ New Analysis</BrutButton></Link>
      </div>

      {incidents.length === 0 ? (
        <EmptyState title="No Incidents Yet" action={<Link to="/upload"><BrutButton variant="black">Upload Logs</BrutButton></Link>} />
      ) : (
        <BrutCard color="white">
          <div className="brut-border-2 overflow-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-brut-yellow border-b-[3px] border-black font-display uppercase">
                  <th className="text-left p-3">ID</th>
                  <th className="text-left p-3">Created</th>
                  <th className="text-left p-3">Score</th>
                  <th className="text-right p-3">Events</th>
                  <th className="text-right p-3">Alerts</th>
                  <th className="text-left p-3">Top Attacker</th>
                  <th className="text-left p-3">Status</th>
                  <th className="text-right p-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc, i) => (
                  <tr key={inc.id} className={`${i % 2 ? "bg-secondary" : "bg-white"} border-b-2 border-black last:border-b-0`}>
                    <td className="p-3 font-mono font-bold">
                      <Link to="/incidents/$id" params={{ id: inc.id }} className="underline-offset-2 hover:underline">
                        {inc.id}
                      </Link>
                    </td>
                    <td className="p-3 font-mono text-xs">{new Date(inc.createdAt).toLocaleString("en-GB", { hour12: false })}</td>
                    <td className="p-3">
                      <span className={`brut-border-2 px-2 py-0.5 font-mono font-bold ${scoreColor(inc.threatScore)}`}>
                        {inc.threatScore}
                      </span>
                    </td>
                    <td className="p-3 text-right font-mono">{inc.totalEvents.toLocaleString()}</td>
                    <td className="p-3 text-right font-mono">{inc.totalAlerts}</td>
                    <td className="p-3 font-mono">{inc.topAttackerIp}</td>
                    <td className="p-3"><span className="brut-border-2 px-2 py-0.5 bg-brut-mint font-mono text-xs uppercase font-bold">{inc.status}</span></td>
                    <td className="p-3 text-right">
                      <BrutButton variant="red" className="text-xs px-2 py-1" onClick={(e) => remove(inc.id, e)}>Delete</BrutButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </BrutCard>
      )}
    </PageShell>
  );
}
