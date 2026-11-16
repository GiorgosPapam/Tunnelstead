import { Activity, AlertTriangle } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtAgo, fmtBytes, fmtRate } from "../api";
import { LineChart } from "../components/Chart";
import { Alert, Card, Empty, Spinner } from "../components/ui";

type Pt = Record<string, number> & { t: number };
type Inst = { id: number; name: string; protocol: string; state: string; availability: number | null; series: Pt[] };
type M = { range: string; host: Pt[]; instances: Inst[]; health: { down: string[]; samples: number; last_sample: string | null } };
const RANGES = [["1h", "1 hour"], ["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"]] as const;

export default function Monitoring() {
  const [range, setRange] = useState("24h"); const [m, setM] = useState<M | null>(null); const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => api<M>(`/api/monitoring?range=${range}`).then((x) => { setM(x); setErr(null); }).catch((e) => setErr(e.message)), [range]);
  useEffect(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t); }, [load]);
  const h = m?.host ?? []; const t = h.map((p) => p.t);
  const pct = (v: number) => `${v.toFixed(0)} %`;
  return <>
    <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
      <div><h1 className="text-2xl font-semibold tracking-tight m-0">Monitoring</h1>
        <p className="muted m-0 mt-1">Measured on this server every 30 seconds{m?.health.last_sample ? ` · last sample ${fmtAgo(m.health.last_sample)}` : ""}</p></div>
      <div role="tablist" aria-label="Time range" className="inline-flex gap-1 p-1 rounded-2xl" style={{ background: "var(--surface-2)" }}>
        {RANGES.map(([k, l]) => <button key={k} role="tab" aria-selected={range === k} onClick={() => setRange(k)}
          className={`rounded-xl px-3 py-1.5 text-sm font-medium border-0 cursor-pointer ${range === k ? "bg-[var(--bg-2)] text-[var(--text)] shadow" : "bg-transparent text-[var(--muted)]"}`}>{l}</button>)}
      </div>
    </div>
    <Alert>{err}</Alert>
    {m && m.health.down.length > 0 && <div role="alert" className="card p-4 mb-4 flex gap-3 items-center" style={{ borderColor: "var(--bad)" }}>
      <AlertTriangle size={18} style={{ color: "var(--bad)" }} aria-hidden="true" />
      <span><strong>Not running:</strong> {m.health.down.join(", ")}. Clients of {m.health.down.length > 1 ? "these servers" : "this server"} cannot connect.</span></div>}
    {!m ? <Spinner /> : <>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="VPN clients online"><LineChart t={t} format={(v) => v.toFixed(0)} series={[{ label: "Online", color: "var(--ok)", values: h.map((p) => p.clients_online) }]} /></Card>
        <Card title="Network traffic (all interfaces)"><LineChart t={t} format={fmtRate} series={[
          { label: "In", color: "var(--primary)", values: h.map((p) => p.net_rx) }, { label: "Out", color: "var(--primary-2)", values: h.map((p) => p.net_tx) }]} /></Card>
        <Card title="CPU"><LineChart t={t} format={pct} max={100} series={[{ label: "CPU", color: "var(--primary)", values: h.map((p) => p.cpu) }]} /></Card>
        <Card title="Memory and disk"><LineChart t={t} format={pct} max={100} series={[
          { label: "Memory", color: "var(--primary-2)", values: h.map((p) => (p.mem_total ? (100 * p.mem_used) / p.mem_total : 0)) },
          { label: "Disk", color: "var(--warn)", values: h.map((p) => (p.disk_total ? (100 * p.disk_used) / p.disk_total : 0)) }]} />
          {h.length > 0 && <p className="muted text-xs m-0 mt-2">Disk {fmtBytes(h[h.length - 1].disk_used)} of {fmtBytes(h[h.length - 1].disk_total)}</p>}</Card>
      </div>
      <h2 className="text-lg font-semibold mt-7 mb-3">VPN servers</h2>
      {m.instances.length === 0 ? <Empty icon={<Activity size={22} />} title="No VPN servers yet" text="Throughput and availability appear here once a VPN server exists." /> :
        <div className="grid gap-4 lg:grid-cols-2">{m.instances.map((i) => <section key={i.id} className="card p-5" aria-label={`${i.name} monitoring`}>
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <h3 className="text-base font-semibold m-0"><Link to={`/servers/${i.id}`} className="no-underline text-[var(--text)] hover:text-[var(--primary-2)]">{i.name}</Link></h3>
            <span className="pill">{i.protocol === "openvpn" ? "OpenVPN" : "WireGuard"}</span>
            <span className="pill" style={{ color: i.availability == null ? "var(--muted)" : i.availability >= 99 ? "var(--ok)" : "var(--warn)" }}>
              {i.state !== "running" ? "Stopped" : i.availability == null ? "No data yet" : `${i.availability} % available`}</span></div>
          <LineChart t={i.series.map((p) => p.t)} format={fmtRate} height={120} series={[
            { label: "Download", color: "var(--primary)", values: i.series.map((p) => p.tx) }, { label: "Upload", color: "var(--primary-2)", values: i.series.map((p) => p.rx) }]} />
        </section>)}</div>}
    </>}
  </>;
}
