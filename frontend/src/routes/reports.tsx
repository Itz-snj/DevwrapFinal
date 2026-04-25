import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageShell } from "@/components/Sidebar";
import { BrutCard, BrutButton, SectionHeader, EmptyState } from "@/components/brut";
import { api } from "@/lib/api";
import { MOCK_INCIDENTS } from "@/data/mock";
import { FileText, FileType } from "lucide-react";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports — Project Phoenix" },
      { name: "description", content: "Download incident reports as Markdown or PDF." },
      { property: "og:title", content: "Reports" },
      { property: "og:description", content: "Export forensic reports." },
    ],
  }),
  component: Reports,
});

function scoreBadge(s: number) {
  return s >= 70 ? "bg-brut-red" : s >= 40 ? "bg-brut-orange" : "bg-brut-mint";
}

function Reports() {
  const [incidents, setIncidents] = useState(MOCK_INCIDENTS);

  useEffect(() => {
    api.incidents().then((d) => setIncidents(d.incidents));
  }, []);

  if (incidents.length === 0) return <PageShell><EmptyState title="No Reports" /></PageShell>;

  return (
    <PageShell>
      <div className="mb-8">
        <h1 className="font-display font-bold text-4xl uppercase tracking-tight">Reports</h1>
        <p className="font-mono text-sm text-muted-foreground mt-1">// download incident reports</p>
      </div>

      <div className="grid md:grid-cols-2 gap-5">
        {incidents.map((inc) => (
          <BrutCard color="white" key={inc.id}>
            <div className="flex items-baseline justify-between mb-2">
              <span className="font-mono font-bold text-lg">{inc.id}</span>
              <span className={`brut-border-2 px-2 py-0.5 font-mono font-bold ${scoreBadge(inc.threatScore)}`}>{inc.threatScore}/100</span>
            </div>
            <p className="font-mono text-xs text-muted-foreground mb-1">{new Date(inc.createdAt).toLocaleString("en-GB", { hour12: false })}</p>
            <p className="font-mono text-sm mb-4">{inc.totalEvents.toLocaleString()} events · {inc.totalAlerts} alerts · top: {inc.topAttackerIp}</p>
            <div className="flex gap-2 flex-wrap">
              <a href={api.reportUrl(inc.id, "md")} target="_blank" rel="noreferrer">
                <BrutButton variant="yellow"><FileText size={16} /> Markdown</BrutButton>
              </a>
              <a href={api.reportUrl(inc.id, "pdf")} target="_blank" rel="noreferrer">
                <BrutButton variant="red"><FileType size={16} /> PDF</BrutButton>
              </a>
            </div>
          </BrutCard>
        ))}
      </div>
    </PageShell>
  );
}
