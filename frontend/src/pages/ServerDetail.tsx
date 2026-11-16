import { ArrowLeft, ArrowDownLeft, ArrowUpRight, Copy, Pause, Play, RotateCw, ShieldCheck, Trash2 } from "lucide-react";
import { ReactNode, useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, can, fmtBytes, fmtDate, Me } from "../api";
import { Alert, Modal, Spinner } from "../components/ui";
import Clients from "./Clients";
import { Inst, StateBadge } from "./Servers";

function Info({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return <div className={wide ? "sm:col-span-2" : ""}>
    <dt className="muted text-xs uppercase tracking-wide font-semibold">{label}</dt>
    <dd className="m-0 mt-1 text-sm break-words">{children}</dd></div>;
}

const daysLeft = (s: string | null) => (s ? Math.floor((new Date(s).getTime() - Date.now()) / 86400000) : null);

export default function ServerDetail({ me }: { me: Me }) {
  const { id } = useParams(); const nav = useNavigate();
  const [i, setI] = useState<Inst & { ca_expires_at: string | null; server_cert_expires_at: string | null; egress_iface: string | null; created_at: string } | null>(null);
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const [del, setDel] = useState(false); const [typed, setTyped] = useState("");
  const admin = can(me, "instances.manage");
  const load = useCallback(() => api<NonNullable<typeof i>>(`/api/instances/${id}`).then(setI).catch((e) => setErr(e.message)), [id]);
  useEffect(() => { load(); }, [load]);  // refreshed whenever the client list reloads (every 15 s and after changes)
  const act = async (action: string) => {
    setErr(null); setBusy(true);
    try { await api(`/api/instances/${id}/${action}`, { method: "POST" }); await load(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  if (!i) return err ? <><Link to="/servers" className="btn no-underline mb-4"><ArrowLeft size={16} />All servers</Link><Alert>{err}</Alert></> : <Spinner />;
  const ovpn = i.protocol === "openvpn";
  return <>
    <Link to="/servers" className="inline-flex items-center gap-1.5 muted text-sm no-underline mb-3 hover:text-[var(--text)]"><ArrowLeft size={15} aria-hidden="true" />All VPN servers</Link>
    <div className="flex flex-wrap items-center gap-3 mb-5">
      <h1 className="text-2xl font-semibold tracking-tight m-0">{i.name}</h1>
      <span className="pill" style={{ background: "linear-gradient(135deg, var(--primary), var(--primary-2))", color: "#fff" }}>{ovpn ? "OpenVPN" : "WireGuard"}</span>
      <StateBadge i={i} />
      {admin && <div className="flex gap-2 ml-auto">
        {i.state === "stopped" ? <button className="btn" disabled={busy} onClick={() => act("start")}><Play size={15} aria-hidden="true" />Start</button>
          : <button className="btn" disabled={busy} onClick={() => act("stop")}><Pause size={15} aria-hidden="true" />Stop</button>}
        <button className="btn" disabled={busy} onClick={() => act("restart")}><RotateCw size={15} aria-hidden="true" />Restart</button>
        <button className="btn btn-danger" onClick={() => { setDel(true); setTyped(""); }}><Trash2 size={15} aria-hidden="true" />Delete</button></div>}
    </div>
    <Alert>{err}</Alert>
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-4">
      {[["Online now", `${i.clients_connected}`], ["Active clients", `${i.clients_active} of ${i.clients_total}`],
        ["Received from clients", fmtBytes(i.rx_bytes)], ["Sent to clients", fmtBytes(i.tx_bytes)]].map(([l, v], n) =>
        <div key={l} className="card p-4"><div className="muted text-[13px] flex items-center gap-1.5">
          {n === 2 && <ArrowUpRight size={14} aria-hidden="true" />}{n === 3 && <ArrowDownLeft size={14} aria-hidden="true" />}{l}</div>
          <div className="text-2xl font-semibold mt-1 tabular-nums">{v}</div></div>)}
    </div>
    <section className="card p-5" aria-label="Server details">
      <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-4 m-0">
        <Info label="Endpoint"><code>{i.endpoint_host}:{i.listen_port}</code></Info>
        <Info label="Interface / transport"><code>{i.iface}</code> · {i.transport.toUpperCase()} {i.listen_port}</Info>
        <Info label="Tunnel subnets"><code>{i.ipv4_cidr}</code>{i.ipv6_cidr && <><br /><code>{i.ipv6_cidr}</code></>}</Info>
        <Info label="Outgoing interface">{i.egress_iface ?? "default route"}</Info>
        <Info label="Routing">{i.routing_mode === "full" ? "Full tunnel (all traffic)" : `Split tunnel${i.split_routes.length ? `: ${i.split_routes.join(", ")}` : ""}`}</Info>
        <Info label="DNS">{i.dns.length ? i.dns.join(", ") : "Clients keep their own"}</Info>
        <Info label="NAT / isolation">{i.nat ? "NAT on" : "NAT off"} · {i.isolate_clients ? "clients isolated" : "clients can reach each other"}</Info>
        <Info label="MTU / keepalive">{i.mtu} · {i.keepalive ? `${i.keepalive} s` : "off"}</Info>
        <Info label={ovpn ? "CA fingerprint (SHA-256)" : "Server public key"} wide>
          <span className="inline-flex items-center gap-2"><code className="text-xs">{i.public_key}</code>
            <button className="btn !p-1" aria-label="Copy" onClick={() => navigator.clipboard?.writeText(i.public_key)}><Copy size={13} /></button></span></Info>
        {ovpn && <Info label="Certificates" wide>{([["CA", i.ca_expires_at], ["Server", i.server_cert_expires_at]] as const).map(([n, d]) => {
          const left = daysLeft(d);
          return <span key={n} className="inline-flex items-center gap-1.5 mr-4"><ShieldCheck size={14} aria-hidden="true"
            style={{ color: left === null ? "var(--muted)" : left < 30 ? "var(--warn)" : "var(--ok)" }} />{n} valid until {fmtDate(d)}{left !== null && ` (${left} days)`}</span>;
        })}</Info>}
        <Info label="Created">{fmtDate(i.created_at)}</Info>
      </dl>
    </section>
    <Clients me={me} instance={i} onChange={load} />
    {del && <Modal title={`Delete ${i.name}?`} onClose={() => setDel(false)}>
      <Alert>This stops {i.iface}, removes its configuration and deletes its {i.clients_total} client(s). Their configurations stop working. This cannot be undone.</Alert>
      <label htmlFor="del-confirm" className="block text-sm font-semibold mb-1.5">Type <strong>{i.name}</strong> to confirm</label>
      <input id="del-confirm" className="field" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
      <div className="flex gap-2 justify-end mt-4"><button className="btn" onClick={() => setDel(false)}>Cancel</button>
        <button className="btn btn-danger" disabled={typed !== i.name} onClick={async () => {
          try { await api(`/api/instances/${i.id}?confirm=${encodeURIComponent(typed)}`, { method: "DELETE" }); nav("/servers"); } catch (e) { setDel(false); setErr((e as Error).message); }
        }}>Delete server</button></div>
    </Modal>}
  </>;
}
