import { createFileRoute, Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { PageShell } from "@/components/Sidebar";
import { BrutCard, BrutButton, SectionHeader, SevBadge } from "@/components/brut";
import { api } from "@/lib/api";
import { UploadCloud, FileText, Check, X } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/upload")({
  head: () => ({
    meta: [
      { title: "Upload Logs — Project Phoenix" },
      { name: "description", content: "Upload and analyze nginx, auth, and JSON application logs." },
      { property: "og:title", content: "Upload Logs" },
      { property: "og:description", content: "Drop log files for forensic analysis." },
    ],
  }),
  component: UploadPage,
});

const STEPS = [
  "Ingesting files",
  "Deobfuscating payloads",
  "Normalizing events",
  "Detecting patterns (28 rules)",
  "Correlating events",
  "Enriching IP intelligence",
  "Building incident report",
];

function UploadPage() {
  const [files, setFiles] = useState<File[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [step, setStep] = useState(-1);
  const [result, setResult] = useState<{ incidentId: string } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const onFiles = (list: FileList | null) => {
    if (!list) return;
    setFiles(Array.from(list));
    setResult(null);
    setStep(-1);
  };

  const detectFormat = (name: string) => {
    if (name.endsWith(".json")) return "json";
    if (name.includes("auth")) return "auth";
    return "nginx";
  };

  const analyze = async () => {
    if (!files.length) return;
    setResult(null);
    for (let i = 0; i < STEPS.length; i++) {
      setStep(i);
      await new Promise((r) => setTimeout(r, 380));
    }
    try {
      const r = await api.upload(files);
      setResult({ incidentId: r.incidentId });
      toast.success("Analysis complete");
    } catch {
      toast.error("Analysis failed");
    }
  };

  return (
    <PageShell>
      <div className="mb-8">
        <h1 className="font-display font-bold text-4xl uppercase tracking-tight">Upload Logs</h1>
        <p className="font-mono text-sm text-muted-foreground mt-1">// drop files to begin forensic analysis</p>
      </div>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          onFiles(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        className={`brut-shadow cursor-pointer p-12 text-center mb-6 transition-colors ${
          dragOver ? "bg-brut-yellow" : "bg-white"
        }`}
        style={{ border: "4px dashed #000" }}
      >
        <UploadCloud size={56} className="mx-auto mb-4" />
        <p className="font-display font-bold uppercase tracking-widest text-2xl">Drop Log Files Here</p>
        <p className="font-mono text-sm text-muted-foreground mt-2">
          Supports: Nginx access logs, Linux auth.log, JSON application logs
        </p>
        <input
          ref={inputRef}
          type="file"
          multiple
          hidden
          onChange={(e) => onFiles(e.target.files)}
        />
      </div>

      {files.length > 0 && (
        <BrutCard color="white" className="mb-6">
          <SectionHeader
            action={
              <BrutButton onClick={analyze} disabled={step >= 0 && step < STEPS.length - 1}>
                Analyze
              </BrutButton>
            }
          >
            Selected Files ({files.length})
          </SectionHeader>
          <div className="space-y-2">
            {files.map((f, i) => (
              <div key={i} className="flex items-center gap-3 brut-border-2 bg-secondary px-3 py-2">
                <FileText size={18} />
                <span className="font-mono text-sm flex-1 truncate">{f.name}</span>
                <span className="font-mono text-xs text-muted-foreground">{(f.size / 1024).toFixed(1)} KB</span>
                <SevBadge severity="LOW" />
                <span className="brut-border-2 px-2 py-0.5 bg-brut-sky text-xs font-mono font-bold uppercase">
                  {detectFormat(f.name)}
                </span>
                <button
                  onClick={() => setFiles(files.filter((_, j) => j !== i))}
                  className="brut-border-2 bg-brut-red w-6 h-6 flex items-center justify-center"
                  aria-label="remove"
                >
                  <X size={14} />
                </button>
              </div>
            ))}
          </div>
        </BrutCard>
      )}

      {step >= 0 && (
        <BrutCard color="white" className="mb-6">
          <SectionHeader>Pipeline</SectionHeader>
          <ul className="space-y-2 font-mono text-sm">
            {STEPS.map((s, i) => (
              <li key={s} className="flex items-center gap-3 brut-border-2 bg-secondary px-3 py-2">
                <span
                  className={`brut-border-2 w-6 h-6 flex items-center justify-center ${
                    i < step ? "bg-brut-mint" : i === step ? "bg-brut-yellow" : "bg-white"
                  }`}
                >
                  {i < step ? <Check size={14} /> : i === step ? "…" : ""}
                </span>
                <span className={i <= step ? "font-bold" : "text-muted-foreground"}>{i + 1}. {s}</span>
              </li>
            ))}
          </ul>
        </BrutCard>
      )}

      {result && (
        <BrutCard color="mint">
          <SectionHeader>Analysis Complete</SectionHeader>
          <p className="font-mono mb-4">Incident ID: <span className="font-bold">{result.incidentId}</span></p>
          <Link to="/incidents/$id" params={{ id: result.incidentId }}>
            <BrutButton variant="black">View Incident →</BrutButton>
          </Link>
        </BrutCard>
      )}
    </PageShell>
  );
}
