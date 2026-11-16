import { AlertTriangle, CheckCircle2, Info, Network, XCircle } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, can, Me } from "../api";
import { Alert, Empty, Modal, Spinner } from "../components/ui";

type Check = { name: string; ok: boolean; detail: string; severity: "error" | "warning" | "info" };
type Row = { instance: string; id: number; state: string; routing_mode: string; checks: Check[] };
type Preset = { label: string; mode: string; routes: string[] | null; explain: string };
type Preview = { before: string[]; after: string[]; affected_clients: string[]; explain: string; applied?: boolean };

function CheckIcon({ c }: { c: Check }) {
  if (c.ok) return <CheckCircle2 size={17} style={{ color: "var(--ok)" }} aria-label="passed" />;
  if (c.severity === "error") return <XCircle size={17} style={{ color: "var(--bad)" }} aria-label="problem" />;
  if (c.severity === "warning") return <AlertTriangle size={17} style={{ color: "var(--warn)" }} aria-label="warning" />;
  return <Info size={17} style={{ color: "var(--muted)" }} aria-label="note" />;
}

export default function Networks({ me }: { me: Me }) {
  const [rows, setRows] = useState<Row[] | null>(null); const [presets, setPresets] = useState<Record<string, Preset>>({});
  const [err, setErr] = useState<string | null>(null); const [edit, setEdit] = useState<Row | null>(null);
  const load = useCallback(() => api<Row[]>("/api/network/checks").then(setRows).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); api<Record<string, Preset>>("/api/network/presets").then(setPresets).catch(() => {}); }, [load]);
  const admin = can(me, "instances.manage");
  return <>
    <h1 className="text-2xl font-semibold tracking-tight m-0">Networks</h1>
    <p className="muted m-0 mt-1 mb-6">Routing for each VPN server, with live leak and health checks against this server.</p>
    <Alert>{err}</Alert>
    {!rows ? <Spinner /> : rows.length === 0 ? <Empty icon={<Network size={22} />} title="No VPN servers yet" text="Create a VPN server to configure its routing." action={<Link className="btn btn-primary no-underline" to="/servers">VPN Servers</Link>} /> :
      <div className="grid gap-4 md:grid-cols-2">{rows.map((r) => {
        const problems = r.checks.filter((c) => !c.ok && c.severity !== "info").length;
        return <section key={r.id} className="card p-5" aria-label={r.instance}>
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <h2 className="text-base font-semibold m-0"><Link to={`/servers/${r.id}`} className="no-underline text-[var(--text)] hover:text-[var(--primary-2)]">{r.instance}</Link></h2>
            <span className="pill">{r.routing_mode === "full" ? "Full tunnel" : "Split tunnel"}</span>
            <span className="pill" style={{ color: problems ? "var(--warn)" : "var(--ok)" }}>{problems ? `${problems} to review` : "All checks passed"}</span>
            {admin && <button className="btn !py-1 ml-auto" onClick={() => setEdit(r)}>Change routing</button>}
          </div>
          <ul className="list-none p-0 m-0">{r.checks.map((c) => <li key={c.name} className="flex gap-2.5 py-1.5 text-sm">
            <span className="mt-0.5"><CheckIcon c={c} /></span>
            <span><span className="font-medium">{c.name}</span>{!c.ok && <span className="muted block text-xs">{c.detail}</span>}</span></li>)}</ul>
        </section>;
      })}</div>}
    {edit && <RoutingModal row={edit} presets={presets} onClose={() => setEdit(null)} onDone={() => { setEdit(null); load(); }} />}
  </>;
}

function RoutingModal({ row, presets, onClose, onDone }: { row: Row; presets: Record<string, Preset>; onClose: () => void; onDone: () => void }) {
  const [preset, setPreset] = useState(row.routing_mode === "full" ? "full" : "vpn_only"); const [custom, setCustom] = useState("");
  const [pv, setPv] = useState<Preview | null>(null); const [err, setErr] = useState<string | null>(null);
  const body = (apply: boolean) => ({ preset, routes: custom.split(/[\s,]+/).filter(Boolean), apply });
  useEffect(() => {
    const t = setTimeout(() => api<Preview>(`/api/instances/${row.id}/routing`, { method: "POST", body: body(false) })
      .then((p) => { setPv(p); setErr(null); }).catch((e) => { setPv(null); setErr(e.message); }), 250);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preset, custom, row.id]);
  return <Modal title={`Routing for ${row.instance}`} onClose={onClose}>
    <fieldset className="border-0 p-0 m-0"><legend className="text-sm font-semibold mb-2">Preset</legend>
      {Object.entries(presets).map(([k, p]) => <label key={k} className={`card p-3 mb-2 flex gap-3 cursor-pointer ${preset === k ? "!border-[var(--primary-2)]" : ""}`}>
        <input type="radio" name="preset" checked={preset === k} onChange={() => setPreset(k)} />
        <span><strong className="text-sm">{p.label}</strong><span className="muted text-xs block">{p.explain}</span></span></label>)}</fieldset>
    {preset === "custom" && <><label htmlFor="rt-custom" className="block text-sm font-semibold mb-1.5">Networks to route through the VPN</label>
      <input id="rt-custom" className="field mb-3" placeholder="e.g. 192.168.1.0/24, 10.20.0.0/16" value={custom} onChange={(e) => setCustom(e.target.value)} /></>}
    <Alert>{err}</Alert>
    {pv && <>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div className="card p-3"><div className="muted text-xs font-semibold mb-1">CLIENT ROUTES NOW</div>{pv.before.map((r) => <code key={r} className="block">{r}</code>)}</div>
        <div className="card p-3"><div className="muted text-xs font-semibold mb-1">AFTER THE CHANGE</div>{pv.after.map((r) => <code key={r} className="block">{r}</code>)}</div></div>
      {pv.affected_clients.length > 0 && <Alert kind="info">Routes are part of each client's configuration: {pv.affected_clients.length} client(s)
        ({pv.affected_clients.slice(0, 5).join(", ")}{pv.affected_clients.length > 5 ? "…" : ""}) must download or scan their configuration again after this change.</Alert>}
    </>}
    <div className="flex gap-2 justify-end mt-3"><button className="btn" onClick={onClose}>Cancel</button>
      <button className="btn btn-primary" disabled={!pv} onClick={async () => {
        try { await api(`/api/instances/${row.id}/routing`, { method: "POST", body: body(true) }); onDone(); } catch (e) { setErr((e as Error).message); }
      }}>Apply routing</button></div>
  </Modal>;
}
