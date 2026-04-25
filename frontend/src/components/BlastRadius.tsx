import { useEffect, useRef, useState } from "react";
import { BrutCard, BrutButton, SectionHeader } from "@/components/brut";
import { api } from "@/lib/api";
import { MOCK_GRAPH } from "@/data/mock";

type Node = { id: string; type: "attacker" | "endpoint" | "resource"; label: string; threatScore?: number; requestCount?: number; severity?: string; geo?: { country: string; city: string } };
type Edge = { source: string; target: string; weight: number; severity: string };

export function BlastRadius({ id }: { id: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 800, h: 520 });
  const [graph, setGraph] = useState<{ nodes: Node[]; edges: Edge[] }>(MOCK_GRAPH);
  const [selected, setSelected] = useState<Node | null>(null);
  const [Comp, setComp] = useState<any>(null);
  const [filters, setFilters] = useState({ attacker: true, endpoint: true, resource: true });

  useEffect(() => {
    api.graph(id).then((d) => setGraph(d as any));
  }, [id]);

  useEffect(() => {
    import("react-force-graph-2d").then((m) => setComp(() => m.default));
  }, []);

  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(() => {
      if (ref.current) setSize({ w: ref.current.clientWidth, h: 520 });
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);

  const visibleNodes = graph.nodes.filter((n) => filters[n.type]);
  const visIds = new Set(visibleNodes.map((n) => n.id));
  const visibleLinks = graph.edges.filter((e) => visIds.has(e.source as string) && visIds.has(e.target as string));

  const nodeColor = (n: Node) =>
    n.type === "attacker" ? "#FF6B6B" : n.type === "endpoint" ? "#FFD803" : "#A8E6CF";
  const edgeColor = (e: Edge) =>
    e.severity === "CRITICAL" ? "#FF6B6B" : e.severity === "HIGH" ? "#FFB347" : e.severity === "MEDIUM" ? "#FFD803" : "#A8E6CF";

  return (
    <div className="grid lg:grid-cols-[1fr_320px] gap-4">
      <BrutCard color="white" className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b-[3px] border-black flex flex-wrap gap-2 items-center bg-brut-yellow">
          <span className="font-display font-bold uppercase tracking-wider text-sm">Blast Radius</span>
          <div className="ml-auto flex gap-2 text-xs font-mono font-bold">
            {(["attacker", "endpoint", "resource"] as const).map((t) => (
              <label key={t} className="flex items-center gap-1 brut-border-2 bg-white px-2 py-1 cursor-pointer">
                <input type="checkbox" checked={filters[t]} onChange={(e) => setFilters((f) => ({ ...f, [t]: e.target.checked }))} />
                {t.toUpperCase()}
              </label>
            ))}
          </div>
        </div>
        <div ref={ref} className="bg-[#F5F0EB]" style={{ height: 520 }}>
          {Comp && (
            <Comp
              graphData={{ nodes: visibleNodes, links: visibleLinks }}
              width={size.w}
              height={size.h}
              backgroundColor="#F5F0EB"
              nodeLabel={(n: Node) => n.label}
              linkWidth={(l: Edge) => Math.max(1, Math.min(8, l.weight / 3))}
              linkColor={(l: Edge) => edgeColor(l)}
              nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D) => {
                const r = node.type === "attacker" ? 12 : node.type === "endpoint" ? 9 : 8;
                ctx.fillStyle = nodeColor(node);
                ctx.strokeStyle = "#000";
                ctx.lineWidth = 2.5;
                if (node.type === "endpoint") {
                  ctx.beginPath();
                  ctx.rect(node.x - r, node.y - r * 0.7, r * 2, r * 1.4);
                  ctx.fill(); ctx.stroke();
                } else if (node.type === "resource") {
                  ctx.beginPath();
                  ctx.moveTo(node.x, node.y - r);
                  ctx.lineTo(node.x + r, node.y);
                  ctx.lineTo(node.x, node.y + r);
                  ctx.lineTo(node.x - r, node.y);
                  ctx.closePath();
                  ctx.fill(); ctx.stroke();
                } else {
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
                  ctx.fill(); ctx.stroke();
                }
                ctx.fillStyle = "#000";
                ctx.font = "bold 10px JetBrains Mono";
                ctx.textAlign = "center";
                ctx.fillText(node.label, node.x, node.y + r + 12);
              }}
              onNodeClick={(n: Node) => setSelected(n)}
            />
          )}
        </div>
      </BrutCard>

      <BrutCard color="white">
        <SectionHeader>Node Details</SectionHeader>
        {selected ? (
          <div className="space-y-2 font-mono text-sm">
            <div><span className="text-muted-foreground">Type:</span> <b className="uppercase">{selected.type}</b></div>
            <div><span className="text-muted-foreground">Label:</span> <b>{selected.label}</b></div>
            {selected.threatScore != null && <div><span className="text-muted-foreground">Score:</span> <b>{selected.threatScore}</b></div>}
            {selected.requestCount != null && <div><span className="text-muted-foreground">Requests:</span> <b>{selected.requestCount}</b></div>}
            {selected.geo && <div><span className="text-muted-foreground">Geo:</span> <b>{selected.geo.city}, {selected.geo.country}</b></div>}
            {selected.severity && <div><span className="text-muted-foreground">Severity:</span> <b>{selected.severity}</b></div>}
            <div className="pt-2"><BrutButton variant="white" onClick={() => setSelected(null)}>Clear</BrutButton></div>
          </div>
        ) : (
          <p className="font-mono text-sm text-muted-foreground">Click a node to view details.</p>
        )}
      </BrutCard>
    </div>
  );
}
