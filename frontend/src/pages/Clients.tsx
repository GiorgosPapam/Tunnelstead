import { Download, KeyRound, Pencil, Plus, QrCode, Search, Trash2, UserX, Users } from "lucide-react";
import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, can, fmtAgo, fmtBytes, fmtDate, Me } from "../api";
import { Alert, Empty, Field, Modal, Spinner } from "../components/ui";
import type { Inst } from "./Servers";

export type Cl = { id: number; instance_id: number; instance_name: string; name: string; description: string; tags: string[];
  public_key: string; ipv4: string; ipv6: string | null; allowed_ips: string[] | null; dns: string[] | null; keepalive: number | null;
  status: string; connected: boolean; expires_at: string | null; quota_bytes: number | null; rx_bytes: number; tx_bytes: number;
  last_handshake: string | null; last_endpoint: string | null; has_private_key: boolean; protocol: string;
  cert_expires_at: string | null; created_at: string };

const STATUS: Record<string, [string, string]> = { active: ["var(--ok)", "Active"], disabled: ["var(--muted)", "Disabled"],
  revoked: ["var(--bad)", "Revoked"], expired: ["var(--warn)", "Expired"], over_quota: ["var(--warn)", "Over quota"] };

// Client table for one VPN server (shown on its detail page). Pass `instance` to scope it.
export default function Clients({ me, instance, onChange }: { me: Me; instance: Inst; onChange?: () => void }) {
  const [rows, setRows] = useState<Cl[] | null>(null); const [insts, setInsts] = useState<Inst[]>([]);
  const [q, setQ] = useState(""); const inst = String(instance.id); const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false); const [editing, setEditing] = useState<Cl | null>(null);
  const [showing, setShowing] = useState<Cl | null>(null); const [confirm, setConfirm] = useState<{ c: Cl; action: string } | null>(null);
  const manage = can(me, "clients.manage");
  const load = useCallback(() => {
    const p = new URLSearchParams({ ...(q ? { q } : {}), ...(inst ? { instance_id: inst } : {}) });
    return api<Cl[]>(`/api/clients?${p}`).then((r) => { setRows(r); onChange?.(); }).catch((e) => setErr(e.message));
  }, [q, inst, onChange]);
  useEffect(() => { const t = setTimeout(load, 200); return () => clearTimeout(t); }, [load]);
  useEffect(() => { setInsts([instance]); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load, instance]);
  const act = async (c: Cl, action: string) => {
    setErr(null);
    try { action === "delete" ? await api(`/api/clients/${c.id}`, { method: "DELETE" }) : await api(`/api/clients/${c.id}/${action}`, { method: "POST" }); load(); }
    catch (e) { setErr((e as Error).message); }
  };
  const exportCsv = () => {
    const head = ["name", "instance", "status", "ipv4", "ipv6", "rx_bytes", "tx_bytes", "last_handshake", "expires_at", "tags"];
    const csv = [head, ...(rows ?? []).map((c) => [c.name, c.instance_name, c.status, c.ipv4, c.ipv6 ?? "", c.rx_bytes, c.tx_bytes, c.last_handshake ?? "", c.expires_at ?? "", c.tags.join(" ")])]
      .map((r) => r.map((v) => `"${String(v).replaceAll('"', '""')}"`).join(",")).join("\n");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = "tunnelstead-clients.csv"; a.click();
  };

  return <>
    <div className="flex flex-wrap items-end justify-between gap-3 mb-4 mt-8">
      <div><h2 className="text-xl font-semibold tracking-tight m-0">Clients <span className="muted font-normal">({rows?.length ?? 0})</span></h2>
        <p className="muted m-0 mt-1 text-sm">{instance.protocol === "openvpn" ? "Online = an active OpenVPN session right now." : "Online = a WireGuard handshake in the last 3 minutes."}</p></div>
      <div className="flex gap-2"><button className="btn" onClick={exportCsv} disabled={!rows?.length}><Download size={16} aria-hidden="true" />Export</button>
        {manage && <button className="btn btn-primary" onClick={() => setCreating(true)} disabled={!insts.length}><Plus size={16} aria-hidden="true" />New client</button>}</div>
    </div>
    <Alert>{err}</Alert>
    <div className="flex flex-wrap gap-2 mb-4">
      <div className="relative"><Search size={15} className="absolute left-3 top-3 muted" aria-hidden="true" />
        <label htmlFor="cl-q" className="sr-only">Search clients</label>
        <input id="cl-q" className="field !pl-9 !w-72" placeholder="Search name, tag, description, IP" value={q} onChange={(e) => setQ(e.target.value)} /></div>
    </div>
    {!rows ? <Spinner /> : rows.length === 0 ? <Empty icon={<Users size={22} />} title={q || inst ? "No matching clients" : "No clients yet"}
      text={insts.length ? "Create a client for each device. You get a configuration file and a QR code for the WireGuard app." : "Deploy a VPN instance first (VPN Servers)."}
      action={manage && insts.length && !q ? <button className="btn btn-primary" onClick={() => setCreating(true)}><Plus size={16} aria-hidden="true" />New client</button> : undefined} /> :
      <div className="card overflow-x-auto"><table className="w-full text-sm border-collapse">
        <thead><tr className="muted text-left text-xs uppercase tracking-wide">{["Client", "Connection", "Status", "Address", "Usage", "Expires", ""].map((h) =>
          <th key={h} scope="col" className="py-3 px-4 font-semibold whitespace-nowrap">{h}</th>)}</tr></thead>
        <tbody>{rows.map((c) => { const [color, label] = STATUS[c.status] ?? ["var(--muted)", c.status]; return <tr key={c.id} className="border-t border-[var(--border)]">
          <td className="py-3 px-4"><div className="font-semibold flex items-center gap-2">
            {c.name}</div>
            <div className="muted text-xs">{c.description || `added ${fmtDate(c.created_at)}`}</div>
            {c.tags.length > 0 && <div className="flex gap-1 mt-1">{c.tags.map((t) => <span key={t} className="pill !text-[11px]">{t}</span>)}</div>}</td>
          <td className="py-3 px-4 whitespace-nowrap">
            <span className="pill" style={{ color: c.connected ? "var(--ok)" : "var(--muted)" }}>
              <span className={`w-1.5 h-1.5 rounded-full ${c.connected ? "animate-pulse" : ""}`} style={{ background: c.connected ? "var(--ok)" : "var(--border-strong)" }} />
              {c.connected ? "Online now" : "Offline"}</span>
            <div className="muted text-xs mt-1">Last connected {fmtAgo(c.last_handshake)}</div>
            {c.last_endpoint && <div className="muted text-xs">from {c.last_endpoint}</div>}</td>
          <td className="py-3 px-4"><span className="pill" style={{ color }}>{label}</span></td>
          <td className="py-3 px-4"><code className="text-xs">{c.ipv4}</code>{c.ipv6 && <><br /><code className="text-xs muted">{c.ipv6}</code></>}</td>
          <td className="py-3 px-4 tabular-nums whitespace-nowrap">↓ {fmtBytes(c.tx_bytes)} · ↑ {fmtBytes(c.rx_bytes)}
            {c.quota_bytes && <div className="muted text-xs">{Math.min(100, ((c.rx_bytes + c.tx_bytes) / c.quota_bytes) * 100).toFixed(0)}% of {fmtBytes(c.quota_bytes)}</div>}</td>
          <td className="py-3 px-4 whitespace-nowrap">{c.expires_at ? fmtDate(c.expires_at) : "Never"}
            {c.cert_expires_at && <div className="muted text-xs">certificate until {new Date(c.cert_expires_at).toLocaleDateString()}</div>}</td>
          <td className="py-3 px-4"><div className="flex gap-1 justify-end">
            {can(me, "clients.manage") && c.status !== "revoked" && c.has_private_key && <button className="btn !p-1.5" title="Config & QR" aria-label={`Configuration for ${c.name}`} onClick={() => setShowing(c)}><QrCode size={16} /></button>}
            {manage && c.status !== "revoked" && <>
              <button className="btn !p-1.5" title="Edit" aria-label={`Edit ${c.name}`} onClick={() => setEditing(c)}><Pencil size={16} /></button>
              <button className="btn !py-1 !px-2.5 text-xs" onClick={() => act(c, c.status === "active" ? "disable" : "enable")}>{c.status === "active" ? "Disable" : "Enable"}</button>
              <button className="btn !p-1.5" title="New keys" aria-label={`Regenerate keys for ${c.name}`} onClick={() => setConfirm({ c, action: "regenerate" })}><KeyRound size={16} /></button>
              <button className="btn btn-danger !p-1.5" title="Revoke" aria-label={`Revoke ${c.name}`} onClick={() => setConfirm({ c, action: "revoke" })}><UserX size={16} /></button></>}
            {manage && <button className="btn btn-danger !p-1.5" title="Delete" aria-label={`Delete ${c.name}`} onClick={() => setConfirm({ c, action: "delete" })}><Trash2 size={16} /></button>}
          </div></td></tr>; })}</tbody></table></div>}
    {creating && <ClientForm insts={insts} onClose={() => setCreating(false)} onDone={(c) => { setCreating(false); load(); if (c.has_private_key) setShowing(c); }} />}
    {editing && <ClientForm insts={insts} client={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); load(); }} />}
    {showing && <ConfigModal c={showing} onClose={() => setShowing(null)} />}
    {confirm && <Modal title={{ revoke: "Revoke client?", regenerate: "Regenerate keys?", delete: "Delete client?" }[confirm.action]!} onClose={() => setConfirm(null)}>
      <p className="text-sm">{{ revoke: `"${confirm.c.name}" is disconnected immediately and can never connect again. Its record is kept for history.`,
        regenerate: `"${confirm.c.name}" gets new keys. Its current configuration stops working immediately; download the new one afterwards.`,
        delete: `"${confirm.c.name}" and its history are removed permanently and it is disconnected.` }[confirm.action]} This cannot be undone.</p>
      <div className="flex gap-2 justify-end"><button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
        <button className="btn btn-danger" onClick={() => { const x = confirm; setConfirm(null); act(x.c, x.action); }}>
          {{ revoke: "Revoke", regenerate: "Regenerate", delete: "Delete" }[confirm.action]}</button></div>
    </Modal>}
  </>;
}

function ClientForm({ insts, client, onClose, onDone }: { insts: Inst[]; client?: Cl; onClose: () => void; onDone: (c: Cl) => void }) {
  const [f, setF] = useState({ instance_id: client?.instance_id ?? insts[0]?.id ?? 0, name: client?.name ?? "", description: client?.description ?? "",
    tags: client?.tags.join(", ") ?? "", expires: client?.expires_at ? client.expires_at.slice(0, 10) : "",
    quota: client?.quota_bytes ? String(+(client.quota_bytes / 1024 ** 3).toFixed(2)) : "", routes: client?.allowed_ips?.join(", ") ?? "",
    dns: client?.dns?.join(", ") ?? "", public_key: "" });
  const [err, setErr] = useState<string | null>(null);
  const list = (s: string) => s.split(/[\s,]+/).filter(Boolean);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    const common = { name: f.name, description: f.description, tags: list(f.tags), allowed_ips: f.routes ? list(f.routes) : null, dns: f.dns ? list(f.dns) : null };
    try {
      if (client) {
        onDone(await api<Cl>(`/api/clients/${client.id}`, { method: "PATCH", body: { ...common,
          ...(f.expires ? { expires_at: new Date(f.expires + "T23:59:59").toISOString() } : { clear_expiry: true }),
          ...(f.quota ? { quota_gb: Number(f.quota) } : { clear_quota: true }) } }));
      } else {
        onDone(await api<Cl>("/api/clients", { method: "POST", body: { ...common, instance_id: f.instance_id, public_key: f.public_key || null,
          expires_at: f.expires ? new Date(f.expires + "T23:59:59").toISOString() : null, quota_gb: f.quota ? Number(f.quota) : null } }));
      }
    } catch (e) { setErr((e as Error).message); }
  };
  return <Modal title={client ? `Edit ${client.name}` : "New client"} onClose={onClose}><form onSubmit={submit}>
    <Alert>{err}</Alert>
    {!client && insts.length > 1 && <Field id="cf-inst" label="VPN instance"><select id="cf-inst" className="field" value={f.instance_id} onChange={(e) => setF({ ...f, instance_id: Number(e.target.value) })}>
      {insts.map((i) => <option key={i.id} value={i.id}>{i.name} ({i.iface}, {i.ipv4_cidr})</option>)}</select></Field>}
    <Field id="cf-name" label="Device name"><input id="cf-name" className="field" required maxLength={64} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. Maria's laptop" /></Field>
    <Field id="cf-desc" label="Description (optional)"><input id="cf-desc" className="field" maxLength={500} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
    <Field id="cf-tags" label="Tags (optional)" hint="Comma-separated, e.g. staff, laptop"><input id="cf-tags" className="field" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} /></Field>
    <div className="grid grid-cols-2 gap-3">
      <Field id="cf-exp" label="Expires on (optional)"><input id="cf-exp" className="field" type="date" value={f.expires} onChange={(e) => setF({ ...f, expires: e.target.value })} /></Field>
      <Field id="cf-quota" label="Data limit in GB (optional)"><input id="cf-quota" className="field" type="number" min={0.01} step={0.01} value={f.quota} onChange={(e) => setF({ ...f, quota: e.target.value })} /></Field></div>
    <details><summary className="cursor-pointer text-sm font-semibold mb-3">Advanced</summary>
      <Field id="cf-routes" label="Allowed networks (client routes)" hint="Leave empty to use the instance's routing (full or split tunnel). Example: 10.0.0.0/8, 192.168.1.0/24">
        <input id="cf-routes" className="field" value={f.routes} onChange={(e) => setF({ ...f, routes: e.target.value })} /></Field>
      <Field id="cf-dns" label="DNS override" hint="Leave empty to use the instance's DNS."><input id="cf-dns" className="field" value={f.dns} onChange={(e) => setF({ ...f, dns: e.target.value })} /></Field>
      {!client && insts[0]?.protocol !== "openvpn" && <Field id="cf-pub" label="Use my own public key (optional)" hint="If set, the server never sees this device's private key (no download/QR)."><input id="cf-pub" className="field" value={f.public_key} onChange={(e) => setF({ ...f, public_key: e.target.value })} /></Field>}
    </details>
    <div className="flex gap-2 justify-end mt-2"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary">{client ? "Save" : "Create client"}</button></div>
  </form></Modal>;
}

function ConfigModal({ c, onClose }: { c: Cl; onClose: () => void }) {
  const [cfg, setCfg] = useState<string | null>(null); const [qr, setQr] = useState<string | null>(null); const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    fetch(`/api/clients/${c.id}/config`, { credentials: "same-origin" }).then(async (r) => r.ok ? setCfg(await r.text()) : setErr((await r.json()).detail)).catch((e) => setErr(String(e)));
    if (c.protocol !== "openvpn") fetch(`/api/clients/${c.id}/qr`, { credentials: "same-origin" }).then(async (r) => r.ok && setQr(URL.createObjectURL(await r.blob()))).catch(() => {});
  }, [c.id]);
  const ovpn = c.protocol === "openvpn";
  const file = `${c.name.replace(/[^A-Za-z0-9_-]+/g, "-")}.${ovpn ? "ovpn" : "conf"}`;
  return <Modal title={`${c.name}: configuration`} onClose={onClose}>
    <Alert>{err}</Alert>
    <Alert kind="info">This contains the device's private key. Share it only with the device owner.</Alert>
    {qr && <div className="rounded-2xl bg-white p-3 grid place-items-center mb-3"><img src={qr} alt={`WireGuard QR code for ${c.name}`} className="w-full max-w-[300px]" /></div>}
    <p className="muted text-sm">{ovpn ? "Import the .ovpn file in OpenVPN Connect (Windows, macOS, iOS, Android) or run openvpn --config on Linux. OpenVPN profiles are too large for a QR code."
      : "Phones: scan with the WireGuard app (+ → Scan from QR code). Computers: import the file in the WireGuard app."}</p>
    {cfg && <div className="flex gap-2"><a className="btn btn-primary no-underline" href={URL.createObjectURL(new Blob([cfg], { type: "text/plain" }))} download={file}><Download size={16} aria-hidden="true" />Download {file}</a>
      <button className="btn" onClick={() => { navigator.clipboard?.writeText(cfg); setCopied(true); }}>{copied ? "Copied" : "Copy"}</button></div>}
  </Modal>;
}
