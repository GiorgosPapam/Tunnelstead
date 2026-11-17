import { Check, ChevronLeft, ChevronRight, Rocket } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { api } from "../api";
import { Alert, Field, Spinner } from "../components/ui";

const STEPS = ["Protocol", "Name", "Network interface", "Transport", "Port", "Subnet", "DNS", "Routing", "Firewall & NAT", "Review"];
type Facts = { interfaces: { default: string | null; interfaces: { name: string; up: boolean; addresses: string[]; managed_wg: boolean }[] };
  dns_presets: Record<string, string[]>; protocols: string[] };
type Preview = { ok: boolean; errors: Record<string, string>; warnings: string[];
  preview: { server_config: string[]; client_routes: string[]; firewall: string[]; dns: string[] } };
const FIELD_STEP: Record<string, number> = { protocol: 0, name: 1, endpoint_host: 1, egress_iface: 2, transport: 3, listen_port: 4,
  ipv4_cidr: 5, ipv6_cidr: 5, dns: 6, routing_mode: 7, split_routes: 7, iface: 9, mtu: 9 };

function Choice({ checked, onSelect, title, text, disabled }: { checked: boolean; onSelect: () => void; title: string; text: string; disabled?: boolean }) {
  return <label className={`card p-4 block cursor-pointer transition ${checked ? "!border-[var(--primary-2)] shadow-[0_0_0_3px_rgb(34_211_238_/_.15)]" : ""} ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}>
    <input type="radio" className="sr-only" checked={checked} disabled={disabled} onChange={onSelect} />
    <span className="flex items-center gap-2 font-semibold">{checked && <Check size={16} style={{ color: "var(--primary-2)" }} aria-hidden="true" />}{title}</span>
    <span className="muted text-sm block mt-1">{text}</span></label>;
}

export default function Wizard({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [step, setStep] = useState(0);
  const [facts, setFacts] = useState<Facts | null>(null); const [err, setErr] = useState<string | null>(null);
  const [f, setF] = useState({ protocol: "wireguard", name: "WG-Primary", endpoint_host: location.hostname, egress_iface: "",
    transport: "udp", listen_port: 51820, port_note: "", ipv4_cidr: "", ipv6_cidr: "", enable_v6: true, dns_preset: "cloudflare",
    dns_custom: "", routing_mode: "full", split_routes: "", nat: true, isolate_clients: true, iface: "wg0", mtu: 1420, keepalive: 25 });
  const [portState, setPortState] = useState<{ free: boolean; message: string } | null>(null);
  const [review, setReview] = useState<Preview | null>(null); const [deploying, setDeploying] = useState(false);
  const set = (patch: Partial<typeof f>) => setF((x) => ({ ...x, ...patch }));

  useEffect(() => { api<Facts>("/api/network/facts").then(setFacts).catch((e) => setErr(e.message)); }, []);
  useEffect(() => {  // recommendations depend on protocol + transport and on what is in use on the server right now
    api<{ port: number; iface: string; ipv4_cidr: string; ipv6_cidr: string; egress_iface: string; port_note: string }>(
      `/api/instances/recommend?protocol=${f.protocol}&transport=${f.transport}`)
      .then((r) => setF((x) => ({ ...x, listen_port: r.port, iface: r.iface, ipv4_cidr: x.ipv4_cidr || r.ipv4_cidr, ipv6_cidr: x.ipv6_cidr || r.ipv6_cidr,
        egress_iface: x.egress_iface || (r.egress_iface ?? ""), port_note: r.port_note, mtu: f.protocol === "openvpn" ? 1500 : 1420 })))
      .catch((e) => setErr(e.message));
  }, [f.protocol, f.transport]);
  useEffect(() => {  // live port availability, debounced
    if (!f.listen_port) return;
    const t = setTimeout(() => api<{ free: boolean; message: string }>(`/api/instances/port-check?port=${f.listen_port}&transport=${f.transport}`)
      .then(setPortState).catch(() => setPortState(null)), 350);
    return () => clearTimeout(t);
  }, [f.listen_port, f.transport]);

  const dns = f.dns_preset === "custom" ? f.dns_custom.split(/[\s,]+/).filter(Boolean)
    : f.dns_preset === "none" ? [] : (facts?.dns_presets[f.dns_preset] ?? []).filter((d) => f.enable_v6 || !d.includes(":"));
  const body = { protocol: f.protocol, name: f.name.trim(), endpoint_host: f.endpoint_host.trim(), egress_iface: f.egress_iface || null,
    transport: f.transport, listen_port: Number(f.listen_port), ipv4_cidr: f.ipv4_cidr.trim(), ipv6_cidr: f.enable_v6 ? f.ipv6_cidr.trim() : null,
    dns, routing_mode: f.routing_mode, split_routes: f.split_routes.split(/[\s,]+/).filter(Boolean), nat: f.nat,
    isolate_clients: f.isolate_clients, iface: f.iface.trim(), mtu: Number(f.mtu), keepalive: Number(f.keepalive), start: true };

  const goReview = async () => {
    setErr(null);
    try { const r = await api<Preview>("/api/instances/validate", { method: "POST", body }); setReview(r); setStep(9); }
    catch (e) { setErr((e as Error).message); }
  };
  const deploy = async () => {
    setErr(null); setDeploying(true);
    try { await api("/api/instances", { method: "POST", body }); onDone(); }
    catch (e) { setErr((e as Error).message); await goReview(); } finally { setDeploying(false); }
  };
  const next = () => (step === 8 ? goReview() : setStep(step + 1));
  const fieldErr = (k: string) => review?.errors[k] ? <p className="text-xs mt-1 mb-0" style={{ color: "var(--bad)" }} role="alert">{review.errors[k]}</p> : null;

  if (!facts) return err ? <Alert>{err}</Alert> : <Spinner label="Inspecting this server" />;
  const panes: ReactNode[] = [
    <div className="grid gap-3 sm:grid-cols-2" role="radiogroup" aria-label="VPN protocol">
      <Choice checked={f.protocol === "wireguard"} onSelect={() => set({ protocol: "wireguard", transport: "udp", name: f.name === "OVPN-Primary" ? "WG-Primary" : f.name })} title="WireGuard" text="Modern, fast and simple. Best choice for most setups; QR codes for phones." />
      <Choice checked={f.protocol === "openvpn"} onSelect={() => set({ protocol: "openvpn", name: f.name === "WG-Primary" ? "OVPN-Primary" : f.name })} title="OpenVPN" text="Certificate-based, works on restrictive networks over TCP, very broad client support. Downloads a .ovpn file (no QR code)." />
    </div>,
    <><Field id="w-name" label="Instance name" hint="Shown in the dashboard, e.g. WG-Primary, WG-Remote.">
      <input id="w-name" className="field" value={f.name} onChange={(e) => set({ name: e.target.value })} /></Field>{fieldErr("name")}
      <Field id="w-host" label="Public endpoint" hint="The public IP address or DNS name your devices connect to.">
        <input id="w-host" className="field" value={f.endpoint_host} onChange={(e) => set({ endpoint_host: e.target.value })} /></Field>{fieldErr("endpoint_host")}</>,
    <><Field id="w-egress" label="Internet-facing interface" hint="VPN traffic to the internet leaves through this interface (used for NAT).">
      <select id="w-egress" className="field" value={f.egress_iface} onChange={(e) => set({ egress_iface: e.target.value })}>
        {facts.interfaces.interfaces.filter((i) => !i.managed_wg).map((i) => <option key={i.name} value={i.name}>
          {i.name}{i.name === facts.interfaces.default ? " (default route)" : ""} {i.addresses.join(", ")}</option>)}</select></Field>{fieldErr("egress_iface")}</>,
    <div className="grid gap-3 sm:grid-cols-2" role="radiogroup" aria-label="Transport">
      <Choice checked={f.transport === "udp"} onSelect={() => set({ transport: "udp" })} title="UDP" text={f.protocol === "wireguard" ? "WireGuard always uses UDP. It is connectionless and fast." : "Recommended: faster, no TCP-over-TCP slowdowns."} />
      <Choice checked={f.transport === "tcp"} disabled={f.protocol === "wireguard"} onSelect={() => set({ transport: "tcp" })} title="TCP"
        text={f.protocol === "wireguard" ? "Not supported by WireGuard." : "Use when networks block UDP (hotels, corporate Wi-Fi). Often on port 443."} />
    </div>,
    <><Field id="w-port" label={`Listening port (${f.transport.toUpperCase()})`} hint={f.port_note}>
      <input id="w-port" className="field" type="number" min={1024} max={65535} value={f.listen_port} onChange={(e) => set({ listen_port: Number(e.target.value) })} /></Field>
      {portState && <Alert kind={portState.free ? "ok" : "error"}>{portState.message}</Alert>}{fieldErr("listen_port")}</>,
    <><Field id="w-v4" label="IPv4 tunnel subnet" hint="Private range for VPN clients. The first address is the server's.">
      <input id="w-v4" className="field" value={f.ipv4_cidr} onChange={(e) => set({ ipv4_cidr: e.target.value })} /></Field>{fieldErr("ipv4_cidr")}
      <label className="flex items-center gap-2 text-sm mb-3"><input type="checkbox" checked={f.enable_v6} onChange={(e) => set({ enable_v6: e.target.checked })} />Also give clients IPv6 (recommended: prevents IPv6 leaks in full tunnel)</label>
      {f.enable_v6 && <><Field id="w-v6" label="IPv6 tunnel subnet (ULA)"><input id="w-v6" className="field" value={f.ipv6_cidr} onChange={(e) => set({ ipv6_cidr: e.target.value })} /></Field>{fieldErr("ipv6_cidr")}</>}</>,
    <><div className="grid gap-3 sm:grid-cols-3" role="radiogroup" aria-label="DNS servers">
      {Object.entries(facts.dns_presets).map(([k, v]) => <Choice key={k} checked={f.dns_preset === k} onSelect={() => set({ dns_preset: k })} title={k[0].toUpperCase() + k.slice(1)} text={v.join(", ")} />)}
      <Choice checked={f.dns_preset === "custom"} onSelect={() => set({ dns_preset: "custom" })} title="Custom" text="Your own resolvers, e.g. a Pi-hole." />
      <Choice checked={f.dns_preset === "none"} onSelect={() => set({ dns_preset: "none" })} title="None" text="Clients keep their own DNS (can leak lookups)." /></div>
      {f.dns_preset === "custom" && <Field id="w-dns" label="DNS servers" hint="Separate with commas."><input id="w-dns" className="field" value={f.dns_custom} onChange={(e) => set({ dns_custom: e.target.value })} /></Field>}{fieldErr("dns")}</>,
    <><div className="grid gap-3 sm:grid-cols-2" role="radiogroup" aria-label="Routing mode">
      <Choice checked={f.routing_mode === "full"} onSelect={() => set({ routing_mode: "full" })} title="Full tunnel" text="All internet traffic goes through the VPN. Hides the client's traffic from the local network." />
      <Choice checked={f.routing_mode === "split"} onSelect={() => set({ routing_mode: "split" })} title="Split tunnel" text="Only the VPN subnet and networks you list use the VPN; everything else goes direct." /></div>
      {f.routing_mode === "split" && <Field id="w-routes" label="Extra networks to route through the VPN" hint="Optional, comma-separated, e.g. 192.168.1.0/24 for your office LAN.">
        <input id="w-routes" className="field" value={f.split_routes} onChange={(e) => set({ split_routes: e.target.value })} /></Field>}{fieldErr("split_routes")}</>,
    <div className="grid gap-3">
      <label className="card p-4 flex gap-3 items-start cursor-pointer"><input type="checkbox" checked={f.nat} onChange={(e) => set({ nat: e.target.checked })} />
        <span><strong>NAT (masquerade)</strong><span className="muted text-sm block">Lets clients reach the internet through this server. Needed for full tunnel unless your router routes the VPN subnet back here.</span></span></label>
      <label className="card p-4 flex gap-3 items-start cursor-pointer"><input type="checkbox" checked={f.isolate_clients} onChange={(e) => set({ isolate_clients: e.target.checked })} />
        <span><strong>Isolate clients from each other</strong><span className="muted text-sm block">Recommended. Devices on this VPN cannot reach each other.</span></span></label>
      <p className="muted text-sm m-0">Tunnelstead opens {f.transport.toUpperCase()} {f.listen_port} and forwards VPN traffic in its own nftables table. Your other firewall rules are not modified; also allow the port in your hosting provider's firewall.</p>
    </div>,
    review ? <>
      {review.ok ? <Alert kind="ok">All checks passed against the live server.</Alert> : <Alert>Fix the highlighted problems before deploying.</Alert>}
      {Object.entries(review.errors).map(([k, v]) => <p key={k} className="text-sm m-0 mb-1"><button className="underline bg-transparent border-0 p-0 cursor-pointer" style={{ color: "var(--bad)" }} onClick={() => setStep(FIELD_STEP[k] ?? 0)}>{k}</button>: {v}</p>)}
      {review.warnings.map((w) => <Alert key={w} kind="info">{w}</Alert>)}
      <div className="grid gap-3 sm:grid-cols-2 mt-3">{([["Server", review.preview.server_config], ["Client routes", review.preview.client_routes], ["Firewall", review.preview.firewall], ["DNS", review.preview.dns]] as const).map(([t, rows]) =>
        <div key={t} className="card p-4"><h3 className="text-sm font-semibold m-0 mb-2">{t}</h3><ul className="text-sm m-0 pl-4">{rows.map((r) => <li key={r}>{r}</li>)}</ul></div>)}</div>
      <details className="mt-4"><summary className="cursor-pointer text-sm font-semibold">Advanced settings</summary>
        <div className="grid gap-3 sm:grid-cols-3 mt-3">
          <Field id="w-iface" label="Interface name"><input id="w-iface" className="field" value={f.iface} onChange={(e) => set({ iface: e.target.value })} /></Field>
          <Field id="w-mtu" label="MTU" hint={f.protocol === "openvpn" ? "1500 for OpenVPN." : "1420 suits most networks."}><input id="w-mtu" className="field" type="number" min={1280} max={1500} value={f.mtu} onChange={(e) => set({ mtu: Number(e.target.value) })} /></Field>
          <Field id="w-ka" label="PersistentKeepalive (s)" hint="Keeps NAT mappings open; 0 = off."><input id="w-ka" className="field" type="number" min={0} max={600} value={f.keepalive} onChange={(e) => set({ keepalive: Number(e.target.value) })} /></Field>
        </div>{fieldErr("iface")}{fieldErr("mtu")}
        <button className="btn mt-1" onClick={goReview}>Re-check</button></details>
    </> : <Spinner label="Checking" />,
  ];

  return <>
    <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
      <div><h1 className="text-2xl font-semibold tracking-tight m-0">New VPN instance</h1><p className="muted m-0 mt-1">Step {step + 1} of {STEPS.length}: {STEPS[step]}</p></div>
      <button className="btn" onClick={onClose}>Cancel</button></div>
    <ol className="flex gap-1.5 list-none p-0 m-0 mb-5 overflow-x-auto" aria-label="Wizard steps">
      {STEPS.map((s, i) => <li key={s} aria-current={i === step ? "step" : undefined} className="shrink-0">
        <button onClick={() => i < step && setStep(i)} disabled={i > step} className="rounded-full px-3 py-1 text-xs font-semibold border-0 cursor-pointer disabled:cursor-default"
          style={{ background: i === step ? "linear-gradient(135deg, var(--primary), var(--primary-2))" : i < step ? "var(--surface-2)" : "transparent", color: i === step ? "#fff" : i < step ? "var(--text)" : "var(--muted)" }}>
          {i < step ? "✓ " : `${i + 1}. `}{s}</button></li>)}</ol>
    <section className="glass rounded-[24px] p-6 max-w-3xl" aria-label={STEPS[step]}>
      <h2 className="text-lg font-semibold m-0 mb-4">{STEPS[step]}</h2>
      <Alert>{err}</Alert>
      {panes[step]}
      <div className="flex justify-between mt-6">
        <button className="btn" disabled={step === 0} onClick={() => setStep(step - 1)}><ChevronLeft size={16} aria-hidden="true" />Back</button>
        {step < 9 ? <button className="btn btn-primary" onClick={next}>{step === 8 ? "Review" : "Next"}<ChevronRight size={16} aria-hidden="true" /></button>
          : <button className="btn btn-primary" disabled={!review?.ok || deploying} onClick={deploy}><Rocket size={16} aria-hidden="true" />{deploying ? "Deploying…" : "Deploy"}</button>}
      </div>
    </section>
  </>;
}
