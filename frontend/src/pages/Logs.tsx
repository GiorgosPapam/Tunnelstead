import { Download, Search } from "lucide-react";
import { useEffect, useState } from "react";
import { api, can, fmtDate, Me } from "../api";
import { Alert, Card, Empty, Spinner } from "../components/ui";

type E = { id: number; ts: string; actor: string | null; category: string; action: string; target: string | null; ip: string | null; success: boolean };

export default function Logs({ me }: { me: Me }) {
  const [tab, setTab] = useState("audit");
  if (!can(me, "audit.view")) return <Empty icon={<Search size={22} />} title="Administrators only" text="Logs are available to administrators." />;
  return <>
    <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
      <div><h1 className="text-2xl font-semibold tracking-tight m-0">Logs</h1>
        <p className="muted m-0 mt-1">{tab === "audit" ? "Tamper-evident audit trail of sign-ins and administrative actions" : "System logs of VPNix Manager, Caddy and every VPN server (journald, rotated by the system)"}</p></div>
      <div role="tablist" aria-label="Log type" className="inline-flex gap-1 p-1 rounded-2xl" style={{ background: "var(--surface-2)" }}>
        {[["audit", "Audit log"], ["services", "Service logs"]].map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}
          className={`rounded-xl px-4 py-1.5 text-sm font-medium border-0 cursor-pointer ${tab === k ? "bg-[var(--bg-2)] text-[var(--text)] shadow" : "bg-transparent text-[var(--muted)]"}`}>{l}</button>)}
      </div>
    </div>
    {tab === "audit" ? <AuditLog me={me} /> : <ServiceLogs />}
  </>;
}

type SE = { ts: number; unit: string; priority: number; message: string };

function ServiceLogs() {
  const [unit, setUnit] = useState("all"); const [prio, setPrio] = useState("info"); const [hours, setHours] = useState("24"); const [q, setQ] = useState("");
  const [d, setD] = useState<{ units: string[]; entries: SE[] } | null>(null); const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    const p = new URLSearchParams({ unit, priority: prio, hours, lines: "500", ...(q ? { q } : {}) });
    const t = setTimeout(() => api<typeof d>(`/api/logs/services?${p}`).then((x) => { setD(x); setErr(null); }).catch((e) => setErr(e.message)), 250);
    return () => clearTimeout(t);
  }, [unit, prio, hours, q]);
  const color = (p: number) => (p <= 3 ? "var(--bad)" : p === 4 ? "var(--warn)" : "var(--muted)");
  return <Card>
    <Alert>{err}</Alert>
    <div className="flex flex-wrap gap-2 mb-4">
      <label className="sr-only" htmlFor="sl-unit">Service</label>
      <select id="sl-unit" className="field !w-auto" value={unit} onChange={(e) => setUnit(e.target.value)}>
        <option value="all">All services</option>{(d?.units ?? []).map((u) => <option key={u} value={u}>{u}</option>)}</select>
      <label className="sr-only" htmlFor="sl-prio">Level</label>
      <select id="sl-prio" className="field !w-auto" value={prio} onChange={(e) => setPrio(e.target.value)}>
        <option value="info">All levels</option><option value="warning">Warnings and errors</option><option value="error">Errors only</option></select>
      <label className="sr-only" htmlFor="sl-hours">Period</label>
      <select id="sl-hours" className="field !w-auto" value={hours} onChange={(e) => setHours(e.target.value)}>
        <option value="1">Last hour</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option><option value="720">Last 30 days</option></select>
      <label className="sr-only" htmlFor="sl-q">Search</label>
      <input id="sl-q" className="field !w-64" placeholder="Search messages" value={q} onChange={(e) => setQ(e.target.value)} />
    </div>
    {!d ? <Spinner /> : d.entries.length === 0 ? <p className="muted text-sm m-0">No matching log lines.</p> :
      <div className="overflow-auto max-h-[60vh] rounded-xl p-3 text-xs font-mono" style={{ background: "var(--surface-2)" }}>
        {d.entries.map((e, i) => <div key={i} className="whitespace-pre-wrap break-words py-0.5">
          <span className="muted">{new Date(e.ts * 1000).toLocaleString()}</span>{" "}
          <span style={{ color: "var(--primary-2)" }}>{e.unit.replace(/\.service$/, "")}</span>{" "}
          <span style={{ color: color(e.priority) }}>{e.message}</span></div>)}</div>}
  </Card>;
}

function AuditLog({ me }: { me: Me }) {
  const [d, setD] = useState<{ chain_ok: boolean; first_bad: number | null; entries: E[] } | null>(null);
  const [cat, setCat] = useState(""); const [q, setQ] = useState(""); const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!can(me, "audit.view")) return;
    const p = new URLSearchParams({ limit: "500", ...(cat ? { category: cat } : {}), ...(q ? { q } : {}) });
    const t = setTimeout(() => api<typeof d>(`/api/system/audit?${p}`).then(setD).catch((e) => setErr(e.message)), 250);
    return () => clearTimeout(t);
  }, [cat, q, me]);
  const exportCsv = () => {
    const rows = [["time", "category", "action", "actor", "target", "ip", "result"], ...(d?.entries ?? []).map((e) =>
      [e.ts, e.category, e.action, e.actor ?? "", e.target ?? "", e.ip ?? "", e.success ? "ok" : "failed"])];
    const csv = rows.map((r) => r.map((v) => `"${String(v).replaceAll('"', '""')}"`).join(",")).join("\n");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = "vpnix-audit.csv"; a.click();
  };
  return <>
    <div className="flex justify-end mb-3"><button className="btn" onClick={exportCsv} disabled={!d?.entries.length}><Download size={16} aria-hidden="true" />Export CSV</button></div>
    <Alert>{err}</Alert>
    {d && <Alert kind={d.chain_ok ? "ok" : "error"}>{d.chain_ok ? "Integrity verified: no entry has been altered or removed." : `Integrity check failed at entry #${d.first_bad}. The log may have been tampered with.`}</Alert>}
    <Card>
      <div className="flex flex-wrap gap-2 mb-4">
        <label className="sr-only" htmlFor="log-cat">Category</label>
        <select id="log-cat" className="field !w-auto" value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="">All categories</option><option value="auth">Authentication</option><option value="admin">Administration</option>
          <option value="vpn">VPN</option><option value="system">System</option></select>
        <label className="sr-only" htmlFor="log-q">Search</label>
        <input id="log-q" className="field !w-64" placeholder="Search action, user or target" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {!d ? <Spinner /> : d.entries.length === 0 ? <p className="muted text-sm m-0">No matching entries.</p> :
        <div className="overflow-x-auto"><table className="w-full text-sm border-collapse">
          <thead><tr className="muted text-left text-xs uppercase tracking-wide">{["Time", "Event", "User", "Target", "IP", "Result"].map((h) =>
            <th key={h} scope="col" className="py-2 pr-4 font-semibold">{h}</th>)}</tr></thead>
          <tbody>{d.entries.map((e) => <tr key={e.id} className="border-t border-[var(--border)]">
            <td className="py-2 pr-4 whitespace-nowrap">{fmtDate(e.ts)}</td><td className="py-2 pr-4"><code>{e.category}.{e.action}</code></td>
            <td className="py-2 pr-4">{e.actor ?? "—"}</td><td className="py-2 pr-4">{e.target ?? "—"}</td><td className="py-2 pr-4">{e.ip ?? "—"}</td>
            <td className="py-2"><span className="pill" style={{ color: e.success ? "var(--ok)" : "var(--bad)" }}>{e.success ? "OK" : "Failed"}</span></td></tr>)}</tbody>
        </table></div>}
    </Card>
  </>;
}
