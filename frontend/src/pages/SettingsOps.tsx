import { Download, RotateCcw, Send, Trash2, Upload } from "lucide-react";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { api, apiUpload, fmtBytes, fmtDate } from "../api";
import { Alert, Card, Field, Modal, Spinner } from "../components/ui";

type B = { name: string; size: number; created_at: string; kind: string };
type BL = { backups: B[]; directory: string; schedule: { enabled: boolean; hour: number; keep: number; has_passphrase: boolean; last_day: string | null } };
type Preview = { created_at: string; app_version: string; kind: string; contents: Record<string, number | string>; integrity_ok: boolean; same_secret_key: boolean; compatible: boolean };
const KIND: Record<string, string> = { manual: "Manual", scheduled: "Scheduled", "pre-restore": "Safety copy", uploaded: "Uploaded" };

export function Backups() {
  const [d, setD] = useState<BL | null>(null); const [err, setErr] = useState<string | null>(null); const [msg, setMsg] = useState<string | null>(null);
  const [creating, setCreating] = useState(false); const [restore, setRestore] = useState<B | null>(null); const file = useRef<HTMLInputElement>(null);
  const load = useCallback(() => api<BL>("/api/backups").then(setD).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);
  if (!d) return err ? <Alert>{err}</Alert> : <Spinner />;
  const upload = async (f: File | undefined) => {
    if (!f) return; setErr(null);
    try { const b = await apiUpload<B>("/api/backups/upload", f); setMsg(`Uploaded as ${b.name}. Choose Restore to check and restore it.`); load(); }
    catch (e) { setErr((e as Error).message); } finally { if (file.current) file.current.value = ""; }
  };
  return <div className="grid gap-4 lg:grid-cols-3">
    <Card title="Backups" className="lg:col-span-2" actions={<div className="flex gap-2">
      <button className="btn" onClick={() => file.current?.click()}><Upload size={16} aria-hidden="true" />Upload</button>
      <input ref={file} type="file" accept=".tsbk,.vbk" className="hidden" aria-label="Upload backup file" onChange={(e) => upload(e.target.files?.[0])} />
      <button className="btn btn-primary" onClick={() => setCreating(true)}>Back up now</button></div>}>
      <p className="muted text-sm mt-0">Everything is included: VPN servers, keys, certificates, clients, users, firewall and settings. Backups are encrypted with your passphrase; keep a copy somewhere other than this server.</p>
      <Alert>{err}</Alert><Alert kind="ok">{msg}</Alert>
      {d.backups.length === 0 ? <p className="muted text-sm m-0">No backups yet.</p> :
        <ul className="list-none p-0 m-0 divide-y divide-[var(--border)]">{d.backups.map((b) => <li key={b.name} className="flex flex-wrap items-center gap-2 py-2.5 text-sm">
          <span className="min-w-0"><span className="font-medium">{fmtDate(b.created_at)}</span> <span className="pill">{KIND[b.kind] ?? b.kind}</span>
            <span className="muted block text-xs break-all">{b.name} · {fmtBytes(b.size)}</span></span>
          <span className="ml-auto flex gap-1">
            <a className="btn !p-1.5" href={`/api/backups/${b.name}/download`} aria-label={`Download ${b.name}`} download><Download size={15} /></a>
            <button className="btn !py-1" onClick={() => setRestore(b)}><RotateCcw size={15} aria-hidden="true" />Restore</button>
            <button className="btn btn-danger !p-1.5" aria-label={`Delete ${b.name}`} onClick={async () => {
              if (!confirm(`Delete ${b.name}? This cannot be undone.`)) return;
              try { await api(`/api/backups/${b.name}`, { method: "DELETE" }); load(); } catch (e) { setErr((e as Error).message); }
            }}><Trash2 size={15} /></button></span></li>)}</ul>}
    </Card>
    <Schedule d={d} onSaved={(x) => { setD(x); setMsg("Schedule saved."); }} />
    {creating && <CreateBackup onClose={() => setCreating(false)} onDone={(b) => { setCreating(false); setMsg(`Backup ${b.name} created.`); load(); }} />}
    {restore && <RestoreBackup b={restore} onClose={() => setRestore(null)} />}
  </div>;
}

function Schedule({ d, onSaved }: { d: BL; onSaved: (x: BL) => void }) {
  const [s, setS] = useState({ ...d.schedule, passphrase: "" }); const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => { e.preventDefault(); setErr(null);
    try { onSaved(await api<BL>("/api/backups/schedule", { method: "PUT", body: { enabled: s.enabled, hour: s.hour, keep: s.keep, passphrase: s.passphrase || null } })); setS({ ...s, passphrase: "" }); }
    catch (e) { setErr((e as Error).message); } };
  return <Card title="Automatic backups"><form onSubmit={submit}>
    <Alert>{err}</Alert>
    <label className="flex gap-2 items-center text-sm mb-3"><input type="checkbox" checked={s.enabled} onChange={(e) => setS({ ...s, enabled: e.target.checked })} />Back up every day</label>
    <div className="grid grid-cols-2 gap-3">
      <Field id="bs-hour" label="At (UTC)"><select id="bs-hour" className="field" value={s.hour} onChange={(e) => setS({ ...s, hour: +e.target.value })}>
        {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>)}</select></Field>
      <Field id="bs-keep" label="Keep last"><input id="bs-keep" className="field" type="number" min={1} max={90} value={s.keep} onChange={(e) => setS({ ...s, keep: +e.target.value })} /></Field></div>
    <Field id="bs-pass" label={d.schedule.has_passphrase ? "New passphrase (optional)" : "Passphrase"} hint="At least 12 characters. Stored encrypted so backups can run unattended. You need it to restore.">
      <input id="bs-pass" className="field" type="password" autoComplete="new-password" value={s.passphrase} onChange={(e) => setS({ ...s, passphrase: e.target.value })} /></Field>
    {d.schedule.last_day && <p className="muted text-xs mt-0">Last run: {d.schedule.last_day}</p>}
    <button className="btn btn-primary w-full">Save schedule</button>
  </form></Card>;
}

function CreateBackup({ onClose, onDone }: { onClose: () => void; onDone: (b: B) => void }) {
  const [p, setP] = useState(""); const [p2, setP2] = useState(""); const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => { e.preventDefault(); if (p !== p2) { setErr("The passphrases do not match"); return; }
    setBusy(true); setErr(null);
    try { onDone(await api<B>("/api/backups", { method: "POST", body: { passphrase: p } })); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  return <Modal title="Create a backup" onClose={onClose}><form onSubmit={submit}>
    <Alert>{err}</Alert>
    <Field id="cb-p" label="Passphrase" hint="At least 12 characters. Without it the backup cannot be restored; it is not stored."><input id="cb-p" className="field" type="password" autoComplete="new-password" value={p} onChange={(e) => setP(e.target.value)} /></Field>
    <Field id="cb-p2" label="Repeat passphrase"><input id="cb-p2" className="field" type="password" autoComplete="new-password" value={p2} onChange={(e) => setP2(e.target.value)} /></Field>
    <div className="flex gap-2 justify-end"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy ? "Encrypting…" : "Create backup"}</button></div>
  </form></Modal>;
}

function RestoreBackup({ b, onClose }: { b: B; onClose: () => void }) {
  const [p, setP] = useState(""); const [pv, setPv] = useState<Preview | null>(null); const [confirmName, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ safety_backup: string; warnings: string[]; message: string } | null>(null);
  const check = async (e: FormEvent) => { e.preventDefault(); setErr(null); setBusy(true);
    try { setPv(await api<Preview>(`/api/backups/${b.name}/preview`, { method: "POST", body: { passphrase: p } })); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  const run = async () => { setErr(null); setBusy(true);
    try { setDone(await api(`/api/backups/${b.name}/restore`, { method: "POST", body: { passphrase: p, confirm: confirmName } })); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  const labels: Record<string, string> = { vpn_servers: "VPN servers", clients: "Clients", users: "Users", firewall_rules: "Firewall rules" };
  if (done) return <Modal title="Restore complete" onClose={() => { window.location.href = "/"; }}>
    <Alert kind="ok">{done.message}</Alert>
    {done.warnings.length > 0 && <Alert>{`Some parts need attention: ${done.warnings.join("; ")}`}</Alert>}
    <p className="text-sm">Your previous data was saved first as <code className="break-all">{done.safety_backup}</code>.</p>
    <button className="btn btn-primary" onClick={() => { window.location.href = "/"; }}>Sign in again</button></Modal>;
  return <Modal title="Restore backup" onClose={onClose}>
    <p className="muted text-sm mt-0 break-all">{b.name}</p>
    <Alert>{err}</Alert>
    {!pv ? <form onSubmit={check}>
      <Field id="rb-p" label="Backup passphrase"><input id="rb-p" className="field" type="password" autoComplete="off" value={p} onChange={(e) => setP(e.target.value)} /></Field>
      <div className="flex gap-2 justify-end"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy || !p}>{busy ? "Checking…" : "Check backup"}</button></div>
    </form> : <>
      <Alert kind="ok">Decrypted and verified: the file is complete and unmodified.</Alert>
      <div className="card p-3 text-sm mb-3"><div className="muted text-xs font-semibold mb-1">THIS BACKUP CONTAINS</div>
        <div>Made {fmtDate(pv.created_at)} by Tunnelstead {pv.app_version}</div>
        {Object.entries(labels).map(([k, l]) => <div key={k}>{l}: <strong>{pv.contents[k]}</strong></div>)}</div>
      {!pv.compatible ? <Alert>This backup is from a newer version of Tunnelstead. Update this server first.</Alert>
        : !pv.same_secret_key ? <Alert kind="info">This backup comes from another server. Restore it on the command line: <code>sudo /opt/tunnelstead/installer/restore.sh FILE</code></Alert>
        : <>
          <Alert kind="info">All current data is replaced by the backup. A safety copy of the current data is made first. VPN servers and the firewall are redeployed to match, and everyone must sign in again.</Alert>
          <Field id="rb-c" label={`Type the backup name to confirm`} hint={b.name}><input id="rb-c" className="field" value={confirmName} onChange={(e) => setConfirm(e.target.value)} /></Field>
          <div className="flex gap-2 justify-end"><button className="btn" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" disabled={busy || confirmName !== b.name} onClick={run}>{busy ? "Restoring…" : "Restore now"}</button></div></>}
    </>}
  </Modal>;
}

type NC = { webhook_url: string; events: string[]; available_events: Record<string, string>;
  email: { host?: string; port?: number; username?: string; sender?: string; recipients?: string[]; starttls?: boolean; has_password: boolean } };

export function Notifications() {
  const [c, setC] = useState<NC | null>(null); const [pw, setPw] = useState(""); const [rcpt, setRcpt] = useState("");
  const [err, setErr] = useState<string | null>(null); const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => { api<NC>("/api/notifications").then((x) => { setC(x); setRcpt((x.email.recipients ?? []).join(", ")); }).catch((e) => setErr(e.message)); }, []);
  if (!c) return err ? <Alert>{err}</Alert> : <Spinner />;
  const e = c.email; const setE = (p: Partial<NC["email"]>) => setC({ ...c, email: { ...e, ...p } });
  const save = async (ev?: FormEvent) => { ev?.preventDefault(); setErr(null); setMsg(null);
    try {
      const x = await api<NC>("/api/notifications", { method: "PUT", body: { webhook_url: c.webhook_url, events: c.events,
        email: { host: e.host ?? "", port: e.port ?? 587, username: e.username ?? "", sender: e.sender ?? "", starttls: e.starttls ?? true,
          recipients: rcpt.split(/[\s,]+/).filter(Boolean), password: pw || null } } });
      setC(x); setPw(""); setMsg("Notification settings saved."); return true;
    } catch (er) { setErr((er as Error).message); return false; } };
  const test = async () => { if (!(await save())) return;
    try { const r = await api<{ ok: boolean; errors: string[] }>("/api/notifications/test", { method: "POST" });
      r.ok ? setMsg("Test notification sent.") : setErr(r.errors.join("; ")); } catch (er) { setErr((er as Error).message); } };
  return <form onSubmit={save} className="grid gap-4 lg:grid-cols-2">
    <div className="lg:col-span-2"><Alert>{err}</Alert><Alert kind="ok">{msg}</Alert></div>
    <Card title="Webhook">
      <Field id="nt-hook" label="Webhook URL" hint="https only. Works with Slack, Discord, Microsoft Teams (workflows), ntfy, Gotify and similar.">
        <input id="nt-hook" className="field" placeholder="https://hooks.slack.com/services/…" value={c.webhook_url} onChange={(x) => setC({ ...c, webhook_url: x.target.value })} /></Field>
      <h3 className="text-sm font-semibold mt-5 mb-2">Send an alert when</h3>
      {Object.entries(c.available_events).map(([k, l]) => <label key={k} className="flex gap-2 items-center text-sm py-1">
        <input type="checkbox" checked={c.events.includes(k)} onChange={(x) => setC({ ...c, events: x.target.checked ? [...c.events, k] : c.events.filter((y) => y !== k) })} />{l}</label>)}
      <p className="muted text-xs mb-0">The same alert is repeated at most every 6 hours.</p>
    </Card>
    <Card title="E-mail (SMTP)">
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2"><Field id="nt-host" label="SMTP server"><input id="nt-host" className="field" placeholder="smtp.example.org" value={e.host ?? ""} onChange={(x) => setE({ host: x.target.value })} /></Field></div>
        <Field id="nt-port" label="Port"><input id="nt-port" className="field" type="number" value={e.port ?? 587} onChange={(x) => setE({ port: +x.target.value })} /></Field></div>
      <div className="grid grid-cols-2 gap-3">
        <Field id="nt-user" label="Username"><input id="nt-user" className="field" autoComplete="off" value={e.username ?? ""} onChange={(x) => setE({ username: x.target.value })} /></Field>
        <Field id="nt-pw" label="Password" hint={e.has_password ? "Stored (encrypted). Leave empty to keep it." : undefined}>
          <input id="nt-pw" className="field" type="password" autoComplete="new-password" value={pw} onChange={(x) => setPw(x.target.value)} /></Field></div>
      <Field id="nt-from" label="From"><input id="nt-from" className="field" placeholder="vpn@example.org" value={e.sender ?? ""} onChange={(x) => setE({ sender: x.target.value })} /></Field>
      <Field id="nt-to" label="Send to" hint="One or more addresses, separated by commas."><input id="nt-to" className="field" value={rcpt} onChange={(x) => setRcpt(x.target.value)} /></Field>
      <label className="flex gap-2 items-center text-sm"><input type="checkbox" checked={e.starttls ?? true} onChange={(x) => setE({ starttls: x.target.checked })} />Use STARTTLS (port 465 always uses TLS)</label>
    </Card>
    <div className="lg:col-span-2 flex gap-2 justify-end">
      <button type="button" className="btn" onClick={test}><Send size={16} aria-hidden="true" />Save and send test</button>
      <button className="btn btn-primary">Save</button></div>
  </form>;
}
