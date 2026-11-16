import { Activity, ArrowDownLeft, ArrowUpRight, Cpu, HardDrive, MemoryStick, Server, ShieldCheck, ShieldAlert, Users } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { api, fmtBytes, fmtDate } from "../api";
import { Alert, Card, Spinner } from "../components/ui";
import { Onboarding } from "../components/Onboarding";

type M = { cpu_percent: number; cpu_count: number; load: number[]; mem_total: number; mem_used: number; disk_total: number;
  disk_used: number; net_rx_total: number; net_tx_total: number; net_rate: { rx: number; tx: number } | null; uptime_s: number };
type O = { version: string; vpn: { instances: number; running: number; stopped: number; clients: number; connected: number; rx_bytes: number; tx_bytes: number }; audit_chain_ok: boolean; failed_logins_24h: number;
  metrics: M; recent_events: { ts: string; actor: string | null; category: string; action: string; success: boolean; ip: string | null }[] };

function Meter({ label, icon, pct, detail }: { label: string; icon: ReactNode; pct: number; detail: string }) {
  const color = pct > 90 ? "var(--bad)" : pct > 75 ? "var(--warn)" : "linear-gradient(90deg, var(--primary), var(--primary-2))";
  return <div className="card p-4">
    <div className="flex items-center justify-between text-sm font-semibold mb-2.5"><span className="flex items-center gap-2">{icon}{label}</span>
      <span className="tabular-nums">{pct.toFixed(0)}%</span></div>
    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "var(--surface-2)" }} role="progressbar"
      aria-label={label} aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100}>
      <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${Math.min(100, pct)}%`, background: color }} /></div>
    <p className="muted text-xs mt-2 mb-0">{detail}</p>
  </div>;
}

function Stat({ label, value, hint, icon }: { label: string; value: ReactNode; hint?: string; icon: ReactNode }) {
  return <div className="card p-4">
    <div className="flex items-center gap-2 muted text-[13px]">{icon}{label}</div>
    <div className="text-2xl font-semibold mt-1 tabular-nums">{value}</div>
    {hint && <div className="muted text-xs mt-0.5">{hint}</div>}
  </div>;
}

const uptime = (s: number) => `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h ${Math.floor((s % 3600) / 60)}m`;

export default function Overview({ isAdmin }: { isAdmin: boolean }) {
  const [o, setO] = useState<O | null>(null); const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    const load = () => api<O>("/api/system/overview").then((r) => { setO(r); setErr(null); }).catch((e) => setErr(e.message));
    load(); const t = setInterval(load, 10000); return () => clearInterval(t);
  }, []);
  if (!o) return err ? <Alert>{err}</Alert> : <Spinner label="Loading overview" />;
  const m = o.metrics;
  return <>
    <div className="flex flex-wrap items-end justify-between gap-3 mb-6">
      <div><h1 className="text-2xl font-semibold tracking-tight m-0">Overview</h1>
        <p className="muted m-0 mt-1">Live from this server · version {o.version} · up {uptime(m.uptime_s)}</p></div>
    </div>
    <Alert>{err}</Alert>
    {isAdmin && (o.vpn.instances === 0 || o.vpn.clients === 0) && <Onboarding instances={o.vpn.instances} clients={o.vpn.clients} />}
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-3">
      <Meter label="CPU" icon={<Cpu size={16} aria-hidden="true" />} pct={m.cpu_percent} detail={`${m.cpu_count} cores · load ${m.load.map((l) => l.toFixed(2)).join(" / ")}`} />
      <Meter label="Memory" icon={<MemoryStick size={16} aria-hidden="true" />} pct={(m.mem_used / m.mem_total) * 100} detail={`${fmtBytes(m.mem_used)} of ${fmtBytes(m.mem_total)}`} />
      <Meter label="Disk" icon={<HardDrive size={16} aria-hidden="true" />} pct={(m.disk_used / m.disk_total) * 100} detail={`${fmtBytes(m.disk_used)} of ${fmtBytes(m.disk_total)}`} />
      <div className="card p-4">
        <div className="flex items-center gap-2 text-sm font-semibold mb-2"><Activity size={16} aria-hidden="true" />Network</div>
        <div className="flex gap-4 text-sm tabular-nums">
          <span className="flex items-center gap-1" style={{ color: "var(--primary-2)" }}><ArrowDownLeft size={15} aria-label="in" />{m.net_rate ? `${fmtBytes(m.net_rate.rx)}/s` : "measuring…"}</span>
          <span className="flex items-center gap-1" style={{ color: "var(--ok)" }}><ArrowUpRight size={15} aria-label="out" />{m.net_rate ? `${fmtBytes(m.net_rate.tx)}/s` : "measuring…"}</span></div>
        <p className="muted text-xs mt-2 mb-0">Since boot: ↓ {fmtBytes(m.net_rx_total)} · ↑ {fmtBytes(m.net_tx_total)}</p>
      </div>
    </div>
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5 mb-6">
      <Stat label="VPN instances" icon={<Server size={15} aria-hidden="true" />} value={o.vpn.instances} hint={`${o.vpn.running} running · ${o.vpn.stopped} stopped`} />
      <Stat label="VPN clients" icon={<Users size={15} aria-hidden="true" />} value={o.vpn.clients} hint={`${o.vpn.connected} connected now`} />
      <Stat label="VPN traffic" icon={<Activity size={15} aria-hidden="true" />} value={fmtBytes(o.vpn.rx_bytes + o.vpn.tx_bytes)} hint={`↓ ${fmtBytes(o.vpn.tx_bytes)} to clients · ↑ ${fmtBytes(o.vpn.rx_bytes)} from clients`} />
      <Stat label="Failed sign-ins (24 h)" icon={<ShieldAlert size={15} aria-hidden="true" />} value={o.failed_logins_24h} />
      <Stat label="Audit trail" icon={<ShieldCheck size={15} aria-hidden="true" />} value={o.audit_chain_ok ? "Intact" : "Tampered"} hint={o.audit_chain_ok ? "Hash chain verified" : "An entry was modified"} />
    </div>
    <Card title="Recent events">
      {o.recent_events.length === 0 ? <p className="muted text-sm m-0">No events yet.</p> :
        <ul className="list-none p-0 m-0 divide-y divide-[var(--border)]">{o.recent_events.map((e, i) =>
          <li key={i} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-sm">
            <span className="pill" style={{ color: e.success ? "var(--ok)" : "var(--bad)" }}>{e.success ? "OK" : "Failed"}</span>
            <code className="text-[13px]">{e.category}.{e.action}</code><span className="muted">{e.actor ?? "unknown user"}{e.ip ? ` · ${e.ip}` : ""}</span>
            <span className="muted ml-auto text-xs">{fmtDate(e.ts)}</span></li>)}</ul>}
    </Card>
  </>;
}
