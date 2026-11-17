import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { ReactNode, useEffect, useRef } from "react";

export function Alert({ kind = "error", children }: { kind?: "error" | "info" | "ok"; children: ReactNode }) {
  if (!children) return null;
  const Icon = kind === "error" ? AlertTriangle : kind === "ok" ? CheckCircle2 : Info;
  const color = kind === "error" ? "var(--bad)" : kind === "ok" ? "var(--ok)" : "var(--primary-2)";
  return <div role={kind === "error" ? "alert" : "status"} className="flex gap-2.5 items-start rounded-xl px-3.5 py-2.5 text-sm my-3"
    style={{ background: `color-mix(in srgb, ${color} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 35%, transparent)` }}>
    <Icon size={17} style={{ color, flex: "none", marginTop: 2 }} aria-hidden="true" /><div>{children}</div></div>;
}

export function Field({ id, label, hint, children }: { id: string; label: string; hint?: string; children: ReactNode }) {
  return <div className="mb-3.5">
    <label htmlFor={id} className="block text-sm font-semibold mb-1.5">{label}</label>
    {children}
    {hint && <p id={`${id}-hint`} className="muted text-xs mt-1">{hint}</p>}
  </div>;
}

export function Card({ title, actions, children, className = "" }: { title?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`card p-5 ${className}`} aria-label={title}>
    {(title || actions) && <div className="flex items-center justify-between gap-3 mb-4">
      {title && <h2 className="text-base font-semibold m-0">{title}</h2>}{actions}</div>}
    {children}
  </section>;
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.querySelector<HTMLElement>("input, button, select, textarea")?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); prev?.focus(); };
  }, [onClose]);
  return <div className="fixed inset-0 z-50 grid place-items-center p-4 backdrop-blur-sm" style={{ background: "rgb(2 6 23 / .72)" }} onMouseDown={onClose}>
    <div ref={ref} role="dialog" aria-modal="true" aria-label={title} className="glass glass-solid rounded-3xl w-full max-w-lg p-6 max-h-[90vh] overflow-auto"
      onMouseDown={(e) => e.stopPropagation()}>
      <div className="flex items-center justify-between mb-3"><h2 className="text-lg font-semibold m-0">{title}</h2>
        <button className="btn !p-1.5" onClick={onClose} aria-label="Close dialog"><X size={18} /></button></div>
      {children}
    </div>
  </div>;
}

export function Empty({ icon, title, text, action }: { icon: ReactNode; title: string; text: string; action?: ReactNode }) {
  return <div className="card text-center px-6 py-12">
    <div className="mx-auto mb-3 w-12 h-12 rounded-2xl grid place-items-center" style={{ background: "var(--surface-2)", color: "var(--primary-2)" }}>{icon}</div>
    <h3 className="text-base font-semibold m-0 mb-1">{title}</h3>
    <p className="muted text-sm max-w-md mx-auto m-0 mb-4">{text}</p>{action}
  </div>;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <div role="status" className="flex items-center gap-2 muted text-sm py-6">
    <span className="w-4 h-4 rounded-full border-2 border-current border-t-transparent animate-spin" aria-hidden="true" />{label}…</div>;
}
