import { CheckCircle2, Download, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";
import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, fmtAgo } from "../api";
import { Alert, Card, Field, Modal, Spinner } from "../components/ui";

type Rel = { version: string; notes: string; published_at: string | null };
type St = { state: string; version?: string; previous?: string; running?: string; error?: string; step?: string; log?: string[]; manual?: boolean; updated_at?: string };
type O = { current: string; settings: { repo: string; mode: string; day: string; hour: number };
  check: { checked_at: number; latest: Rel | null; newer: Rel[] } | null; status: St; rollback_to: string | null; downloaded: string[] };
const STEP: Record<string, string> = { verify: "Checking the signature", snapshot: "Saving a snapshot", install: "Installing", rollback: "Rolling back" };

export default function Updates() {
  const [o, setO] = useState<O | null>(null); const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState<string | null>(null);
  const [restarting, setRestarting] = useState(false); const [confirmRb, setConfirmRb] = useState(false);
  const load = useCallback(() => api<O>("/api/updates").then((x) => { setO(x); setRestarting(false); }).catch((e) => {
    if (e.status === 502 || e.status === 503 || e.message.startsWith("Request failed") || e instanceof TypeError) setRestarting(true); else setErr(e.message);
  }), []);
  useEffect(() => { load(); }, [load]);
  const running = restarting || o?.status.state === "running" || busy === "install" || busy === "rollback";
  useEffect(() => { if (!running) return; const t = setInterval(load, 3000); return () => clearInterval(t); }, [running, load]);
  const act = async (key: string, fn: () => Promise<unknown>) => { setErr(null); setBusy(key);
    try { await fn(); await load(); } catch (e) { setErr((e as Error).message); } finally { setBusy(null); } };
  if (!o) return err ? <Alert>{err}</Alert> : <Spinner />;
  const st = o.status; const latest = o.check?.latest;
  return <>
    <h1 className="text-2xl font-semibold tracking-tight m-0">Updates</h1>
    <p className="muted m-0 mt-1 mb-5">Installed version <strong>{o.current}</strong>. Only releases signed with the VPNix Create release key are installed; a snapshot is taken first and a failed update is undone automatically.</p>
    <Alert>{err}</Alert>
    {running && <div role="status" className="card p-4 mb-4 flex items-center gap-3"><Spinner label="" />
      <div><strong>{restarting ? "Restarting VPNix Create…" : STEP[st.step ?? ""] ?? "Updating…"}</strong>
        <div className="muted text-sm">VPN connections keep working. This page reconnects by itself.</div></div></div>}
    {!running && st.state === "success" && st.updated_at && <Alert kind="ok">Updated from {st.previous} to {st.version} {fmtAgo(st.updated_at)}.</Alert>}
    {!running && st.state === "rolled_back" && <Alert kind={st.manual ? "ok" : "error"}>{st.manual ? `Rolled back to ${st.running}.` : `The update to ${st.version} failed and was undone: ${st.error}. Version ${st.running} is running.`}</Alert>}
    {!running && st.state === "failed" && <Alert>{`Update not installed: ${st.error}`}</Alert>}
    <div className="grid gap-4 lg:grid-cols-3">
      <Card title="Available update" className="lg:col-span-2" actions={<button className="btn" disabled={!!busy || running} onClick={() => act("check", () => api("/api/updates/check", { method: "POST" }))}>
        <RefreshCw size={16} aria-hidden="true" className={busy === "check" ? "animate-spin" : ""} />Check now</button>}>
        {!o.check ? <p className="muted text-sm m-0">Not checked yet.</p> : !latest ? <p className="text-sm m-0 flex items-center gap-2">
          <CheckCircle2 size={18} style={{ color: "var(--ok)" }} aria-hidden="true" />You are up to date. Checked {fmtAgo(new Date(o.check.checked_at * 1000).toISOString())}.</p> : <>
          <div className="flex flex-wrap items-center gap-2 mb-2"><span className="text-lg font-semibold">Version {latest.version}</span>
            {latest.published_at && <span className="muted text-sm">released {fmtAgo(latest.published_at)}</span>}
            {o.downloaded.includes(latest.version) && <span className="pill" style={{ color: "var(--ok)" }}><ShieldCheck size={13} aria-hidden="true" className="inline mr-1" />Downloaded, signature valid</span>}</div>
          {o.check.newer.map((r) => r.notes && <details key={r.version} open={r.version === latest.version} className="mb-2">
            <summary className="cursor-pointer text-sm font-medium">What's new in {r.version}</summary>
            <pre className="text-sm whitespace-pre-wrap font-sans m-0 mt-2 p-3 rounded-xl" style={{ background: "var(--surface-2)" }}>{r.notes}</pre></details>)}
          <div className="flex flex-wrap gap-2 mt-3">
            {!o.downloaded.includes(latest.version) ? <button className="btn btn-primary" disabled={!!busy || running} onClick={() => act("dl", () => api(`/api/updates/${latest.version}/download`, { method: "POST" }))}>
              <Download size={16} aria-hidden="true" />{busy === "dl" ? "Downloading and verifying…" : "Download"}</button>
              : <button className="btn btn-primary" disabled={!!busy || running} onClick={() => act("install", () => api(`/api/updates/${latest.version}/install`, { method: "POST" }))}>Install {latest.version} now</button>}
          </div></>}
        {o.rollback_to && !running && <div className="border-t border-[var(--border)] mt-4 pt-4 flex flex-wrap items-center gap-3 text-sm">
          <span className="flex-1 min-w-[14rem]">Problems after the update? Go back to <strong>{o.rollback_to}</strong>, the version before the last update.</span>
          <button className="btn" onClick={() => setConfirmRb(true)}><RotateCcw size={16} aria-hidden="true" />Roll back</button></div>}
        {st.log && st.log.length > 0 && <details className="mt-4"><summary className="cursor-pointer text-sm muted">Details of the last update</summary>
          <pre className="text-xs overflow-auto max-h-72 p-3 rounded-xl mt-2" style={{ background: "var(--surface-2)" }}>{st.log.join("\n")}</pre></details>}
      </Card>
      <Schedule o={o} onSaved={setO} />
    </div>
    {confirmRb && <Modal title={`Roll back to ${o.rollback_to}?`} onClose={() => setConfirmRb(false)}>
      <p className="text-sm mt-0">VPNix Create and its database go back to the snapshot taken just before the update. Changes made since then (new clients, settings, users) are lost.</p>
      <div className="flex gap-2 justify-end"><button className="btn" onClick={() => setConfirmRb(false)}>Cancel</button>
        <button className="btn btn-danger" onClick={() => { setConfirmRb(false); act("rollback", () => api("/api/updates/rollback", { method: "POST" })); }}>Roll back</button></div></Modal>}
  </>;
}

function Schedule({ o, onSaved }: { o: O; onSaved: (x: O) => void }) {
  const [s, setS] = useState(o.settings); const [err, setErr] = useState<string | null>(null); const [ok, setOk] = useState(false);
  const submit = async (e: FormEvent) => { e.preventDefault(); setErr(null); setOk(false);
    try { onSaved(await api<O>("/api/updates/settings", { method: "PUT", body: s })); setOk(true); } catch (er) { setErr((er as Error).message); } };
  const days = [["any", "Every day"], ["mon", "Monday"], ["tue", "Tuesday"], ["wed", "Wednesday"], ["thu", "Thursday"], ["fri", "Friday"], ["sat", "Saturday"], ["sun", "Sunday"]];
  return <Card title="Update settings"><form onSubmit={submit}>
    <Alert>{err}</Alert>{ok && <Alert kind="ok">Saved.</Alert>}
    <Field id="up-repo" label="GitHub repository" hint="owner/name of the official VPNix Create repository"><input id="up-repo" className="field" placeholder="owner/vpnix-create" value={s.repo} onChange={(e) => setS({ ...s, repo: e.target.value })} /></Field>
    <fieldset className="border-0 p-0 m-0 mb-3"><legend className="text-sm font-semibold mb-1.5">When a new version is released</legend>
      {[["off", "Do nothing"], ["notify", "Tell me (dashboard and notifications)"], ["auto", "Install it automatically in the window below"]].map(([k, l]) =>
        <label key={k} className="flex gap-2 items-center text-sm py-0.5"><input type="radio" name="up-mode" checked={s.mode === k} onChange={() => setS({ ...s, mode: k })} />{l}</label>)}</fieldset>
    {s.mode === "auto" && <div className="grid grid-cols-2 gap-3">
      <Field id="up-day" label="Day"><select id="up-day" className="field" value={s.day} onChange={(e) => setS({ ...s, day: e.target.value })}>{days.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
      <Field id="up-hour" label="Hour (UTC)"><select id="up-hour" className="field" value={s.hour} onChange={(e) => setS({ ...s, hour: +e.target.value })}>
        {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>)}</select></Field></div>}
    <button className="btn btn-primary w-full">Save</button>
  </form></Card>;
}
