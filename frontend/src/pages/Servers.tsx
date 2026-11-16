import { ArrowDownLeft, ArrowUpRight, Pause, Play, Plus, RotateCw, Server, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api, can, fmtBytes, Me } from "../api";
import { Alert, Empty, Modal, Spinner } from "../components/ui";
import Wizard from "./Wizard";

export type Inst = { id: number; name: string; protocol: string; transport: string; iface: string; listen_port: number;
  endpoint_host: string; ipv4_cidr: string; ipv6_cidr: string | null; dns: string[]; mtu: number; keepalive: number;
  routing_mode: string; split_routes: string[]; nat: boolean; isolate_clients: boolean; public_key: string; state: string;
  live: { active: boolean; enabled: boolean } | null; clients_total: number; clients_active: number; clients_connected: number;
  rx_bytes: number; tx_bytes: number };

export function StateBadge({ i }: { i: Inst }) {
  const running = i.live ? i.live.active : null;
  const [color, label] = running === null ? ["var(--muted)", "Status unavailable"]
    : running ? ["var(--ok)", "Running"] : i.state === "stopped" ? ["var(--muted)", "Stopped"] : ["var(--bad)", "Not running"];
  return <span className="pill" style={{ color }}><span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />{label}</span>;
}

export default function Servers({ me }: { me: Me }) {
  const [list, setList] = useState<Inst[] | null>(null); const [err, setErr] = useState<string | null>(null);
  const [wizard, setWizard] = useState(false); const [del, setDel] = useState<Inst | null>(null); const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const admin = can(me, "instances.manage");
  const load = useCallback(() => api<Inst[]>("/api/instances").then(setList).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);
  const act = async (i: Inst, action: string) => {
    setErr(null); setBusy(i.id);
    try { await api(`/api/instances/${i.id}/${action}`, { method: "POST" }); await load(); } catch (e) { setErr((e as Error).message); } finally { setBusy(null); }
  };
  if (wizard) return <Wizard onClose={() => setWizard(false)} onDone={() => { setWizard(false); load(); }} />;
  return <>
    <div className="flex flex-wrap items-end justify-between gap-3 mb-6">
      <div><h1 className="text-2xl font-semibold tracking-tight m-0">VPN Servers</h1>
        <p className="muted m-0 mt-1">Each instance has its own interface, port and subnet. Changes to one never affect another.</p></div>
      {admin && <button className="btn btn-primary" onClick={() => setWizard(true)}><Plus size={16} aria-hidden="true" />New VPN instance</button>}
    </div>
    <Alert>{err}</Alert>
    {!list ? <Spinner /> : list.length === 0 ? <Empty icon={<Server size={22} />} title="No VPN instances yet"
      text="Deploy your first WireGuard server with the guided wizard. It checks ports, interfaces and subnets on this server before changing anything."
      action={admin ? <button className="btn btn-primary" onClick={() => setWizard(true)}><Plus size={16} aria-hidden="true" />Deploy a VPN instance</button> : undefined} /> :
      <div className="grid gap-4 md:grid-cols-2">{list.map((i) => <article key={i.id} className="card overflow-hidden" aria-label={i.name}>
        <header className="flex flex-wrap items-center gap-2.5 px-5 py-4 border-b border-[var(--border)]">
          <h2 className="text-base font-semibold m-0">{i.name}</h2>
          <span className="pill" style={{ background: "linear-gradient(135deg, var(--primary), var(--primary-2))", color: "#fff" }}>WireGuard</span>
          <StateBadge i={i} />
          <span className="muted text-xs ml-auto"><code>{i.iface}</code> · {i.transport.toUpperCase()} {i.listen_port}</span>
        </header>
        <div className="px-5 py-4 grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
          <div><span className="muted">Subnet</span><br /><code>{i.ipv4_cidr}</code>{i.ipv6_cidr && <><br /><code>{i.ipv6_cidr}</code></>}</div>
          <div><span className="muted">Clients</span><br />{i.clients_connected} connected · {i.clients_active} active · {i.clients_total} total</div>
          <div><span className="muted">Routing</span><br />{i.routing_mode === "full" ? "Full tunnel" : "Split tunnel"}{i.nat ? " · NAT" : ""}</div>
          <div><span className="muted">Traffic</span><br /><span className="inline-flex gap-3 tabular-nums">
            <span style={{ color: "var(--primary-2)" }}><ArrowDownLeft size={13} className="inline" aria-label="received" />{fmtBytes(i.rx_bytes)}</span>
            <span style={{ color: "var(--ok)" }}><ArrowUpRight size={13} className="inline" aria-label="sent" />{fmtBytes(i.tx_bytes)}</span></span></div>
          <div className="col-span-2 muted text-xs break-all">Endpoint {i.endpoint_host}:{i.listen_port} · Public key <code>{i.public_key}</code></div>
        </div>
        {admin && <footer className="flex flex-wrap gap-2 px-5 py-3 border-t border-[var(--border)]">
          {i.state === "stopped" ? <button className="btn !py-1.5" disabled={busy === i.id} onClick={() => act(i, "start")}><Play size={15} aria-hidden="true" />Start</button>
            : <button className="btn !py-1.5" disabled={busy === i.id} onClick={() => act(i, "stop")}><Pause size={15} aria-hidden="true" />Stop</button>}
          <button className="btn !py-1.5" disabled={busy === i.id} onClick={() => act(i, "restart")}><RotateCw size={15} aria-hidden="true" />Restart</button>
          <button className="btn btn-danger !py-1.5 ml-auto" onClick={() => { setDel(i); setTyped(""); }}><Trash2 size={15} aria-hidden="true" />Delete</button>
        </footer>}
      </article>)}</div>}
    {del && <Modal title={`Delete ${del.name}?`} onClose={() => setDel(null)}>
      <Alert>This stops the interface {del.iface}, removes its configuration and deletes its {del.clients_total} client(s). Their configurations stop working. This cannot be undone.</Alert>
      <label htmlFor="del-confirm" className="block text-sm font-semibold mb-1.5">Type <strong>{del.name}</strong> to confirm</label>
      <input id="del-confirm" className="field" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
      <div className="flex gap-2 justify-end mt-4"><button className="btn" onClick={() => setDel(null)}>Cancel</button>
        <button className="btn btn-danger" disabled={typed !== del.name} onClick={async () => {
          const i = del; setDel(null); setErr(null);
          try { await api(`/api/instances/${i.id}?confirm=${encodeURIComponent(typed)}`, { method: "DELETE" }); load(); } catch (e) { setErr((e as Error).message); }
        }}>Delete instance</button></div>
    </Modal>}
  </>;
}
