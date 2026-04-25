import { cn } from "@/lib/utils";
import type { ReactNode, ButtonHTMLAttributes, HTMLAttributes } from "react";
import type { Severity } from "@/data/mock";

export function BrutCard({
  children,
  className,
  color = "white",
  ...rest
}: HTMLAttributes<HTMLDivElement> & { color?: "white" | "yellow" | "red" | "mint" | "sky" | "lavender" | "orange" }) {
  const bg = {
    white: "bg-white",
    yellow: "bg-brut-yellow",
    red: "bg-brut-red",
    mint: "bg-brut-mint",
    sky: "bg-brut-sky",
    lavender: "bg-brut-lavender",
    orange: "bg-brut-orange",
  }[color];
  return (
    <div className={cn("brut-border brut-shadow", bg, "text-black p-5", className)} {...rest}>
      {children}
    </div>
  );
}

export function BrutButton({
  children,
  className,
  variant = "yellow",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "yellow" | "red" | "mint" | "white" | "black" }) {
  const bg = {
    yellow: "bg-brut-yellow text-black",
    red: "bg-brut-red text-black",
    mint: "bg-brut-mint text-black",
    white: "bg-white text-black",
    black: "bg-brut-black text-white",
  }[variant];
  return (
    <button
      className={cn(
        "brut-border brut-shadow brut-press font-display font-bold uppercase tracking-wider px-4 py-2 text-sm inline-flex items-center gap-2",
        bg,
        "disabled:opacity-50 disabled:cursor-not-allowed",
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}

export function SevBadge({ severity, className }: { severity: Severity; className?: string }) {
  const bg = {
    CRITICAL: "bg-brut-red",
    HIGH: "bg-brut-orange",
    MEDIUM: "bg-brut-yellow",
    LOW: "bg-brut-mint",
  }[severity];
  return (
    <span
      className={cn(
        "inline-block brut-border-2 px-2 py-0.5 text-[11px] font-mono font-bold uppercase tracking-wider text-black",
        bg,
        className,
      )}
    >
      {severity}
    </span>
  );
}

export function Bar({ value, max = 100, color = "yellow" }: { value: number; max?: number; color?: "yellow" | "red" | "mint" | "orange" }) {
  const pct = Math.min(100, Math.round((value / max) * 100));
  const bg = {
    yellow: "bg-brut-yellow",
    red: "bg-brut-red",
    mint: "bg-brut-mint",
    orange: "bg-brut-orange",
  }[color];
  return (
    <div className="brut-border-2 bg-white h-3 w-full">
      <div className={cn("h-full", bg)} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function SectionHeader({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex items-end justify-between mb-4">
      <h2 className="font-display font-bold uppercase tracking-wider text-xl">{children}</h2>
      {action}
    </div>
  );
}

export function EmptyState({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="brut-border brut-shadow bg-brut-yellow p-10 text-center">
      <p className="font-display font-bold uppercase tracking-widest text-2xl mb-4">{title}</p>
      {action}
    </div>
  );
}

export function LoadingBox({ label = "LOADING..." }: { label?: string }) {
  return (
    <div className="brut-border brut-shadow bg-white p-6 inline-block font-mono font-bold tracking-widest">
      {label}
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="brut-border brut-shadow bg-brut-red p-6">
      <p className="font-display font-bold uppercase tracking-wider text-lg mb-2">ERROR</p>
      <p className="font-mono text-sm mb-4">{message}</p>
      {onRetry && (
        <BrutButton variant="black" onClick={onRetry}>
          RETRY
        </BrutButton>
      )}
    </div>
  );
}
