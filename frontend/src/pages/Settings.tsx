import { KeyRound, Monitor, Shield, Trash2, UserPlus, Users } from "lucide-react";
import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, can, fmtDate, Me, setCsrf } from "../api";
import { Alert, Card, Field, Modal } from "../components/ui";
import { Backups, Notifications } from "./SettingsOps";

export default function SettingsPage({ me, reload }: { me: Me; reload: () => void }) {
  const tabs = [{ id: "account", label: "Account & security" }, ...(can(me, "users.manage") ? [{ id: "users", label: "Users & roles" }, { id: "backups", label: "Backups" }, { id: "notifications", label: "Notifications" }] : [])];
  const [tab, setTab] = useState("account");
  return <>
    <h1 className="text-2xl font-semibold tracking-tight m-0">Settings</h1>
    <p className="muted m-0 mt-1 mb-5">Your account, two-factor authentication, sessions{can(me, "users.manage") ? ", users, backups and notifications" : ""}</p>
    <div role="tablist" aria-label="Settings sections" className="inline-flex gap-1 p-1 rounded-2xl mb-5" style={{ background: "var(--surface-2)" }}>
      {tabs.map((t) => <button key={t.id} role="tab" aria-selected={tab === t.id} onClick={() => setTab(t.id)}
        className={`rounded-xl px-4 py-1.5 text-sm font-medium border-0 cursor-pointer ${tab === t.id ? "bg-[var(--bg-2)] text-[var(--text)] shadow" : "bg-transparent text-[var(--muted)]"}`}>{t.label}</button>)}
    </div>
    {tab === "account" ? <Account me={me} reload={reload} /> : tab === "users" ? <UsersAdmin me={me} /> : tab === "backups" ? <Backups /> : <Notifications />}
  </>;
}

function Account({ me, reload }: { me: Me; reload: () => void }) {
  const [msg, setMsg] = useState<string | null>(null); const [err, setErr] = useState<string | null>(null);
  const [cur, setCur] = useState(""); const [pw, setPw] = useState("");
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null); const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [sessions, setSessions] = useState<{ id: number; created_at: string; last_seen_at: string; ip: string; user_agent: string; current: boolean }[]>([]);
  const loadSessions = useCallback(() => api<typeof sessions>("/api/auth/sessions").then(setSessions).catch(() => {}), []);
  useEffect(() => { loadSessions(); }, [loadSessions]);
  const run = async (fn: () => Promise<void>) => { setErr(null); setMsg(null); try { await fn(); } catch (e) { setErr((e as Error).message); } };

  const changePw = (e: FormEvent) => { e.preventDefault(); run(async () => {
    setCsrf((await api<{ csrf_token: string }>("/api/auth/password", { method: "POST", body: { current_password: cur, new_password: pw } })).csrf_token);
    setCur(""); setPw(""); setMsg("Password changed. All other sessions were signed out."); loadSessions(); }); };

  return <div className="grid gap-4 lg:grid-cols-2">
    <div className="lg:col-span-2"><Alert kind="ok">{msg}</Alert><Alert>{err}</Alert></div>
    <Card title="Change password">
      <form onSubmit={changePw}>
        <Field id="acc-cur" label="Current password"><input id="acc-cur" className="field" type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
        <Field id="acc-new" label="New password" hint="At least 12 characters."><input id="acc-new" className="field" type="password" autoComplete="new-password" minLength={12} required value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
        <button className="btn btn-primary"><KeyRound size={16} aria-hidden="true" />Update password</button>
      </form>
    </Card>
    <Card title="Two-factor authentication" actions={<span className="pill" style={{ color: me.mfa_enabled ? "var(--ok)" : "var(--muted)" }}>{me.mfa_enabled ? "On" : "Off"}</span>}>
      {codes && <><Alert kind="info">Save these recovery codes now. Each works once if you lose your authenticator; they will not be shown again.</Alert>
        <pre className="card p-3 text-sm grid grid-cols-2 gap-1 m-0 mb-3">{codes.map((c) => <code key={c}>{c}</code>)}</pre></>}
      {me.mfa_enabled ? <form onSubmit={(e) => { e.preventDefault(); run(async () => { setCodes((await api<{ recovery_codes: string[] }>("/api/auth/mfa/recovery-codes", { method: "POST", body: { code } })).recovery_codes); setCode(""); }); }}>
          <Field id="mfa-regen" label="Authenticator code" hint="Needed to create new recovery codes (old ones stop working)."><input id="mfa-regen" className="field" inputMode="numeric" pattern="\d{6}" required value={code} onChange={(e) => setCode(e.target.value)} /></Field>
          <button className="btn">New recovery codes</button>
        </form>
        : !setup ? <><p className="muted text-sm mt-0">Protect your account with an authenticator app such as Aegis, 2FAS or Google Authenticator.</p>
          <button className="btn btn-primary" onClick={() => run(async () => setSetup(await api("/api/auth/mfa/setup", { method: "POST" })))}><Shield size={16} aria-hidden="true" />Set up</button></>
        : <form onSubmit={(e) => { e.preventDefault(); run(async () => { setCodes((await api<{ recovery_codes: string[] }>("/api/auth/mfa/enable", { method: "POST", body: { code } })).recovery_codes); setSetup(null); setCode(""); reload(); }); }}>
          <p className="text-sm mt-0">Add this key in your authenticator app (manual entry), then enter the 6-digit code it shows.</p>
          <code className="card block p-3 text-sm break-all mb-3">{setup.secret}</code>
          <Field id="mfa-code" label="Code"><input id="mfa-code" className="field" inputMode="numeric" pattern="\d{6}" required value={code} onChange={(e) => setCode(e.target.value)} /></Field>
          <button className="btn btn-primary">Turn on</button>
        </form>}
    </Card>
    <Card title="Active sessions" className="lg:col-span-2">
      <ul className="list-none p-0 m-0 divide-y divide-[var(--border)]">{sessions.map((s) => <li key={s.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
        <Monitor size={16} aria-hidden="true" className="muted" /><span className="truncate max-w-[22rem]" title={s.user_agent}>{s.user_agent || "Unknown device"}</span>
        <span className="muted">{s.ip} · last active {fmtDate(s.last_seen_at)}</span>
        {s.current ? <span className="pill ml-auto" style={{ color: "var(--ok)" }}>This device</span> :
          <button className="btn btn-danger ml-auto !py-1" onClick={() => run(async () => { await api(`/api/auth/sessions/${s.id}`, { method: "DELETE" }); loadSessions(); })}>Sign out</button>}
      </li>)}</ul>
    </Card>
  </div>;
}

type U = { id: number; username: string; email: string | null; role: string; active: boolean; mfa_enabled: boolean; last_login_at: string | null };

function UsersAdmin({ me }: { me: Me }) {
  const [users, setUsers] = useState<U[]>([]); const [err, setErr] = useState<string | null>(null);
  const [adding, setAdding] = useState(false); const [temp, setTemp] = useState<{ user: string; pw: string } | null>(null);
  const [confirmDel, setConfirmDel] = useState<U | null>(null);
  const load = useCallback(() => api<U[]>("/api/users").then(setUsers).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const run = async (fn: () => Promise<unknown>) => { setErr(null); try { await fn(); load(); } catch (e) { setErr((e as Error).message); } };
  return <Card title="Users & roles" actions={<button className="btn btn-primary" onClick={() => setAdding(true)}><UserPlus size={16} aria-hidden="true" />Add user</button>}>
    <Alert>{err}</Alert>
    <p className="muted text-sm mt-0"><strong>Admin</strong>: everything. <strong>Operator</strong>: manages VPN clients. <strong>Viewer</strong>: read-only, never sees secrets.</p>
    <div className="overflow-x-auto"><table className="w-full text-sm border-collapse">
      <thead><tr className="muted text-left text-xs uppercase tracking-wide">{["User", "Role", "Status", "2FA", "Last sign-in", ""].map((h) => <th key={h} scope="col" className="py-2 pr-4 font-semibold">{h}</th>)}</tr></thead>
      <tbody>{users.map((u) => <tr key={u.id} className="border-t border-[var(--border)]">
        <td className="py-2.5 pr-4 font-medium"><Users size={14} className="inline mr-1.5 muted" aria-hidden="true" />{u.username}</td>
        <td className="py-2.5 pr-4"><label className="sr-only" htmlFor={`role-${u.id}`}>Role for {u.username}</label>
          <select id={`role-${u.id}`} className="field !w-auto !py-1" value={u.role} disabled={u.id === me.id}
            onChange={(e) => run(() => api(`/api/users/${u.id}`, { method: "PATCH", body: { role: e.target.value } }))}>
            <option value="admin">Admin</option><option value="operator">Operator</option><option value="viewer">Viewer</option></select></td>
        <td className="py-2.5 pr-4"><span className="pill" style={{ color: u.active ? "var(--ok)" : "var(--bad)" }}>{u.active ? "Active" : "Disabled"}</span></td>
        <td className="py-2.5 pr-4">{u.mfa_enabled ? "On" : "Off"}</td><td className="py-2.5 pr-4 muted">{fmtDate(u.last_login_at)}</td>
        <td className="py-2.5 text-right whitespace-nowrap">{u.id !== me.id && <>
          <button className="btn !py-1 mr-1" onClick={() => run(() => api(`/api/users/${u.id}`, { method: "PATCH", body: { active: !u.active } }))}>{u.active ? "Disable" : "Enable"}</button>
          <button className="btn !py-1 mr-1" onClick={() => run(async () => setTemp({ user: u.username, pw: (await api<{ temporary_password: string }>(`/api/users/${u.id}/reset-password`, { method: "POST" })).temporary_password }))}>Reset password</button>
          <button className="btn btn-danger !py-1" aria-label={`Delete ${u.username}`} onClick={() => setConfirmDel(u)}><Trash2 size={15} /></button></>}</td>
      </tr>)}</tbody></table></div>
    {adding && <AddUser onClose={() => setAdding(false)} onDone={() => { setAdding(false); load(); }} />}
    {temp && <Modal title="Temporary password" onClose={() => setTemp(null)}>
      <Alert kind="info">Shown once. Give it to <strong>{temp.user}</strong> securely; they must change it when they sign in.</Alert>
      <code className="card block p-3 break-all select-all">{temp.pw}</code>
      <button className="btn mt-3" onClick={() => navigator.clipboard?.writeText(temp.pw)}>Copy</button></Modal>}
    {confirmDel && <Modal title={`Delete ${confirmDel.username}?`} onClose={() => setConfirmDel(null)}>
      <p className="text-sm">This permanently removes the account and signs it out everywhere. It cannot be undone.</p>
      <div className="flex gap-2 justify-end"><button className="btn" onClick={() => setConfirmDel(null)}>Cancel</button>
        <button className="btn btn-danger" onClick={() => { const u = confirmDel; setConfirmDel(null); run(() => api(`/api/users/${u.id}`, { method: "DELETE" })); }}>Delete user</button></div>
    </Modal>}
  </Card>;
}

function AddUser({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ username: "", email: "", role: "viewer", password: "" }); const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => { e.preventDefault(); setErr(null);
    try { await api("/api/users", { method: "POST", body: { ...f, email: f.email || null } }); onDone(); } catch (e) { setErr((e as Error).message); } };
  return <Modal title="Add user" onClose={onClose}><form onSubmit={submit}>
    <Alert>{err}</Alert>
    <Field id="nu-name" label="Username" hint="3–64 characters: letters, numbers, dot, dash, underscore."><input id="nu-name" className="field" required pattern="[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
    <Field id="nu-email" label="Email (optional)"><input id="nu-email" className="field" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
    <Field id="nu-role" label="Role"><select id="nu-role" className="field" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
      <option value="viewer">Viewer (read-only)</option><option value="operator">Operator (manage clients)</option><option value="admin">Admin (full access)</option></select></Field>
    <Field id="nu-pw" label="Temporary password" hint="At least 12 characters. The user must change it at first sign-in."><input id="nu-pw" className="field" type="password" autoComplete="new-password" minLength={12} required value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
    <div className="flex gap-2 justify-end"><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary">Create user</button></div>
  </form></Modal>;
}
