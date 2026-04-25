import { Link, useRouterState } from "@tanstack/react-router";
import { LayoutDashboard, Upload, AlertTriangle, Activity, FileText, Flame, Menu, X } from "lucide-react";
import { useState } from "react";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/upload", label: "Upload", icon: Upload },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle },
  { to: "/live", label: "Live Monitor", icon: Activity },
  { to: "/reports", label: "Reports", icon: FileText },
] as const;

export function Sidebar() {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [open, setOpen] = useState(false);

  return (
    <>
      {/* Mobile top bar */}
      <div className="md:hidden fixed top-0 left-0 right-0 h-14 bg-brut-black text-white flex items-center justify-between px-4 z-40 brut-border-2 border-t-0 border-x-0">
        <div className="flex items-center gap-2">
          <Flame className="text-brut-yellow" size={22} />
          <span className="font-display font-bold text-brut-yellow tracking-wider">PHOENIX</span>
        </div>
        <button onClick={() => setOpen((v) => !v)} className="p-1">
          {open ? <X /> : <Menu />}
        </button>
      </div>

      <aside
        className={`fixed top-0 left-0 h-screen w-64 bg-brut-black text-white flex flex-col z-30 transition-transform md:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        } pt-14 md:pt-0`}
      >
        <div className="hidden md:flex items-center gap-2 px-6 py-6 border-b-[3px] border-brut-yellow">
          <Flame className="text-brut-yellow" size={28} />
          <span className="font-display font-bold text-2xl text-brut-yellow tracking-widest">PHOENIX</span>
        </div>

        <nav className="flex-1 py-6 flex flex-col gap-1">
          {NAV.map((item) => {
            const active = item.to === "/" ? path === "/" : path.startsWith(item.to);
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setOpen(false)}
                className={`flex items-center gap-3 px-6 py-3 font-display font-semibold uppercase text-sm tracking-wider border-l-[6px] ${
                  active
                    ? "border-brut-yellow bg-white/5 text-brut-yellow"
                    : "border-transparent text-white/70 hover:text-white hover:border-white/30"
                }`}
              >
                <Icon size={18} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="px-6 py-4 border-t border-white/20 font-mono text-xs text-white/40">
          v1.0.0
        </div>
      </aside>
    </>
  );
}

export function PageShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <main className="md:ml-64 pt-14 md:pt-0 min-h-screen">
        <div className="p-4 md:p-8 max-w-[1400px]">{children}</div>
      </main>
    </div>
  );
}
