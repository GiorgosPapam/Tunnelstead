import { Plus, ShieldAlert, Trash2 } from "lucide-react";
import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, can, Me } from "../api";
import { Alert, Card, Field, Modal, Spinner } from "../components/ui";

type Rule = { id: number; action: string; proto: string; ports: string | null; source: string | null; comment: string; enabled: boolean };
type State = { rules: Rule[]; management: { enabled: boolean; networks: string[]; include_ssh: boolean }; your_ip: string;
  pending: { seconds_left: number } | null; managed_ports: { instance: string; port: number; transport: string }[];
  own_table: string; host_ruleset: string };

export default function Firewall({ me }: { me: Me }) {
  const [s, setS] = useState<State | null>(null); const [err, setErr] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null); const [left, setLeft] = useState(0);
  const [adding, setAdding] = useState(false); const [mgmt, setMgmt] = useState(false); const [msg, setMsg] = useState<string | null>(null);
  const admin = can(me, "instances.manage");
  const load = useCallback(() => api<State>("/api/firewall").then((x) => { setS(x); if (!x.pending) setToken(null); }).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {  // countdown; when it reaches zero the server has already rolled back
    if (!token) return;
    const t = setInterval(() => setLeft((l) => { if (l <= 1) { clearInterval(t); setTimeout(load, 1500); return 0; } return l - 1; }), 1000);
    return () => clearInterval(t);
  }, [token, load]);
  const applied = (r: { confirm_token: string; rollback_seconds: number }) => { setToken(r.confirm_token); setLeft(r.rollback_seconds); setMsg(null); load(); };
  const change = async (fn: () => Promise<{ confirm_token: string; rollback_seconds: number }>) => {
    setErr(null); try { applied(await fn()); } catch (e) { setErr((e as Error).message); }
  };
  const keep = async () => {
    try { await api("/api/firewall/confirm", { method: "POST", body: { token } }); setToken(null); setMsg("Change kept."); load(); }
    catch (e) { setErr((e as Error).message); setToken(null); load(); }
  };
  if (!s) return err ? <Alert>{err}</Alert> : <Spinner />;
  return <>
    <h1 className="text-2xl font-semibold tracking-tight m-0">Firewall</h1>
    <p className="muted m-0 mt-1 mb-5">VPNix Manager only manages its own nftables table. Your other firewall rules are never changed.</p>
    {token && left > 0 && <div role="alert" className="glass rounded-2xl p-4 mb-4 flex flex-wrap items-center gap-3" style={{ borderColor: "var(--warn)" }}>
      <ShieldAlert size={20} style={{ color: "var(--warn)" }} aria-hidden="true" />
      <div className="flex-1 min-w-[16rem]"><strong>Keep this firewall change?</strong>
        <div className="muted text-sm">It is undone automatically in <strong className="tabular-nums">{left} s</strong> unless you keep it. If you can see this, your connection still works.</div></div>
      <button className="btn btn-primary" onClick={keep}>Keep changes</button></div>}
    {!token && s.pending && <Alert kind="info">An earlier change is waiting for confirmation and will be undone in {s.pending.seconds_left} s.</Alert>}
    <Alert>{err}</Alert><Alert kind="ok">{msg}</Alert>
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Your rules" actions={admin ? <button className="btn btn-primary" onClick={() => setAdding(true)}><Plus size={16} aria-hidden="true" />Add rule</button> : undefined}>
        <p className="muted text-sm mt-0">Incoming traffic to this server. Evaluated in order, after the management restriction and before VPN ports.</p>
        {s.rules.length === 0 ? <p className="muted text-sm m-0">No custom rules.</p> :
          <ul className="list-none p-0 m-0 divide-y divide-[var(--border)]">{s.rules.map((r) => <li key={r.id} className="flex flex-wrap items-center gap-2 py-2.5 text-sm">
            <span className="pill" style={{ color: r.action === "accept" ? "var(--ok)" : "var(--bad)" }}>{r.action === "accept" ? "Allow" : "Block"}</span>
            <code>{r.proto.toUpperCase()}{r.ports ? ` ${r.ports}` : ""}</code><span className="muted">from {r.source ?? "anywhere"}</span>
            {r.comment && <span className="muted">· {r.comment}</span>}
            {admin && <span className="ml-auto flex gap-1">
              <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={r.enabled} onChange={(e) => change(() => api(`/api/firewall/rules/${r.id}?enabled=${e.target.checked}`, { method: "PATCH" }))} />On</label>
              <button className="btn btn-danger !p-1.5" aria-label={`Delete rule ${r.id}`} onClick={() => change(() => api(`/api/firewall/rules/${r.id}`, { method: "DELETE" }))}><Trash2 size={15} /></button></span>}
          </li>)}</ul>}
      </Card>
      <Card title="Management access" actions={admin ? <button className="btn" onClick={() => setMgmt(true)}>Configure</button> : undefined}>
        <p className="text-sm mt-0">{s.management.enabled
          ? <>The dashboard (TCP 80/443){s.management.include_ssh ? " and SSH (TCP 22)" : ""} is reachable only from <code>{s.management.networks.join(", ")}</code>.</>
          : "The dashboard is reachable from anywhere. Restrict it to your own networks for extra protection."}</p>
        <p className="muted text-sm m-0">Your current address: <code>{s.your_ip}</code></p>
        <h3 className="text-sm font-semibold mt-4 mb-1">VPN ports opened automatically</h3>
        {s.managed_ports.length === 0 ? <p className="muted text-sm m-0">None (no running VPN servers).</p> :
          <ul className="text-sm m-0 pl-4">{s.managed_ports.map((p) => <li key={p.instance}>{p.transport.toUpperCase()} {p.port} · {p.instance}</li>)}</ul>}
      </Card>
    </div>
    <details className="card p-5 mt-4"><summary className="cursor-pointer font-semibold">Server firewall ruleset (read-only)</summary>
      <p className="muted text-sm">Everything currently loaded in nftables. VPNix Manager's table is <code>inet vpnix_manager</code>; everything else belongs to the system or other software and is never modified.</p>
      <pre className="text-xs overflow-auto max-h-96 p-3 rounded-xl" style={{ background: "var(--surface-2)" }}>{s.host_ruleset || "(empty)"}</pre></details>
    {adding && <RuleForm onClose={() => setAdding(false)} onDone={(r) => { setAdding(false); applied(r); }} />}
    {mgmt && <MgmtForm s={s} onClose={() => setMgmt(false)} onDone={(r) => { setMgmt(false); applied(r); }} />}
  </>;
}

type Applied = { confirm_token: string; rollback_seconds: number };

function RuleForm({ onClose, onDone }: { onClose: () => void; onDone: (r: Applied) => void }) {
  const [f, setF] = useState({ action: "accept", proto: "tcp", ports: "", source: "", comment: "" }); const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => { e.preventDefault(); setErr(null);
    try { onDone(await api<Applied>("/api/firewall/rules", { method: "POST", body: { ...f, ports: f.ports || null, source: f.source || null } })); }
    catch (e) { setErr((e as Error).message); } };
  return <Modal title="Add firewall rule" onClose={onClose}><form onSubmit={submit}>
    <Alert>{err}</Alert>
    <div className="grid grid-cols-2 gap-3">
      <Field id="fr-action" label="Action"><select id="fr-action" className="field" value={f.action} onChange={(e) => setF({ ...f, action: e.target.value })}><option value="accept">Allow</option><option value="drop">Block</option></select></Field>
      <Field id="fr-proto" label="Protocol"><select id="fr-proto" className="field" value={f.proto} onChange={(e) => setF({ ...f, proto: e.target.value })}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">Any</option></select></Field></div>
    <Field id="fr-ports" label="Port or range (optional)" hint="e.g. 8080 or 8000-8100. Needs TCP or UDP."><input id="fr-ports" className="field" value={f.ports} onChange={(e) => setF({ ...f, ports: e.target.value })} /></Field>
    <Field id="fr-src" label="From (optional)" hint="An IPv4/IPv6 address or network, e.g. 198.51.100.0/24. Empty = anywhere."><input id="fr-src" className="field" value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })} /></Field>
    <Field id="fr-comment" label="Comment (optional)"><input id="fr-comment" className="field" maxLength={64} value={f.comment} onChange={(e) => setF({ ...f, comment: e.target.value })} /></Field>
    <Alert kind="info">The rule is applied immediately and undone after 60 seconds unless you keep it.</Alert>
    <div className="flex gap-2 justify-end"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary">Apply rule</button></div>
  </form></Modal>;
}

function MgmtForm({ s, onClose, onDone }: { s: State; onClose: () => void; onDone: (r: Applied) => void }) {
  const [enabled, setEnabled] = useState(s.management.enabled); const [nets, setNets] = useState(s.management.networks.join(", ") || s.your_ip);
  const [ssh, setSsh] = useState(s.management.include_ssh); const [risk, setRisk] = useState(false); const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => { e.preventDefault(); setErr(null);
    try { onDone(await api<Applied>("/api/firewall/management", { method: "PUT", body: { enabled, networks: nets.split(/[\s,]+/).filter(Boolean), include_ssh: ssh, i_understand_lockout_risk: risk } })); }
    catch (e) { setErr((e as Error).message); } };
  return <Modal title="Management access" onClose={onClose}><form onSubmit={submit}>
    <Alert>{err}</Alert>
    <label className="flex gap-2 items-center text-sm mb-3"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Only allow these networks to reach the dashboard</label>
    <Field id="mg-nets" label="Allowed networks" hint={`Your current address is ${s.your_ip}. Keep it in the list.`}><input id="mg-nets" className="field" value={nets} onChange={(e) => setNets(e.target.value)} /></Field>
    <label className="flex gap-2 items-center text-sm mb-3"><input type="checkbox" checked={ssh} onChange={(e) => setSsh(e.target.checked)} />Also restrict SSH (TCP 22)</label>
    {err?.includes("lock you out") && <label className="flex gap-2 items-center text-sm mb-3" style={{ color: "var(--warn)" }}><input type="checkbox" checked={risk} onChange={(e) => setRisk(e.target.checked)} />I understand I may lose access (it is undone after 60 s unless kept)</label>}
    <div className="flex gap-2 justify-end"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary">Apply</button></div>
  </form></Modal>;
}
