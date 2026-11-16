import { Download, Search } from "lucide-react";
import { useEffect, useState } from "react";
import { api, can, fmtDate, Me } from "../api";
import { Alert, Card, Empty, Spinner } from "../components/ui";

type E = { id: number; ts: string; actor: string | null; category: string; action: string; target: string | null; ip: string | null; success: boolean };

export default function Logs({ me }: { me: Me }) {
  const [d, setD] = useState<{ chain_ok: boolean; first_bad: number | null; entries: E[] } | null>(null);
  const [cat, setCat] = useState(""); const [q, setQ] = useState(""); const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!can(me, "audit.view")) return;
    const p = new URLSearchParams({ limit: "500", ...(cat ? { category: cat } : {}), ...(q ? { q } : {}) });
    const t = setTimeout(() => api<typeof d>(`/api/system/audit?${p}`).then(setD).catch((e) => setErr(e.message)), 250);
    return () => clearTimeout(t);
  }, [cat, q, me]);
  if (!can(me, "audit.view")) return <Empty icon={<Search size={22} />} title="Administrators only" text="The audit log is available to administrators." />;
  const exportCsv = () => {
    const rows = [["time", "category", "action", "actor", "target", "ip", "result"], ...(d?.entries ?? []).map((e) =>
      [e.ts, e.category, e.action, e.actor ?? "", e.target ?? "", e.ip ?? "", e.success ? "ok" : "failed"])];
    const csv = rows.map((r) => r.map((v) => `"${String(v).replaceAll('"', '""')}"`).join(",")).join("\n");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = "vpnix-audit.csv"; a.click();
  };
  return <>
    <div className="flex flex-wrap items-end justify-between gap-3 mb-6">
      <div><h1 className="text-2xl font-semibold tracking-tight m-0">Logs</h1><p className="muted m-0 mt-1">Tamper-evident audit trail of sign-ins and administrative actions</p></div>
      <button className="btn" onClick={exportCsv} disabled={!d?.entries.length}><Download size={16} aria-hidden="true" />Export CSV</button>
    </div>
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
