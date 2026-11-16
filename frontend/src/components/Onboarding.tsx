import { CheckCircle2, Circle } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

type Sys = { ipv4_forwarding: boolean; ipv6_forwarding: boolean; wireguard_tools: boolean; nftables: boolean; kernel: string };

function Item({ done, title, children }: { done: boolean | null; title: string; children: ReactNode }) {
  return <li className="flex gap-3 py-3 border-t border-[var(--border)] first:border-0">
    {done ? <CheckCircle2 size={20} style={{ color: "var(--ok)", flex: "none" }} aria-label="done" />
      : <Circle size={20} style={{ color: "var(--muted)", flex: "none" }} aria-label="to do" />}
    <div><div className="font-semibold text-sm">{title}</div><div className="muted text-sm">{children}</div></div></li>;
}

// Shown to administrators until the first instance and first client exist. Every item reflects live state.
export function Onboarding({ instances, clients }: { instances: number; clients: number }) {
  const [sys, setSys] = useState<Sys | null>(null); const [err, setErr] = useState(false);
  useEffect(() => { api<{ system: Sys }>("/api/network/facts").then((f) => setSys(f.system)).catch(() => setErr(true)); }, []);
  return <section className="glass rounded-[24px] p-6 mb-6" aria-label="Getting started">
    <h2 className="text-lg font-semibold m-0">Getting started</h2>
    <p className="muted text-sm mt-1 mb-2">A few steps to your first working VPN. Each one is checked against this server.</p>
    {err && <p className="text-sm" style={{ color: "var(--warn)" }}>The system helper is not reachable, so server checks are unavailable (is vpnix-create-helper running?).</p>}
    <ol className="list-none p-0 m-0">
      <Item done={sys ? sys.wireguard_tools && sys.nftables : null} title="VPN tools installed">WireGuard tools and nftables on kernel {sys?.kernel ?? "…"}.</Item>
      <Item done={null} title="Open the VPN port in your provider's firewall">Allow the UDP port you choose (51820 by default) in your hosting provider's control panel. VPNix Create opens it on this server automatically.</Item>
      <Item done={instances > 0} title="Create your first VPN instance">The wizard sets the public endpoint, DNS, routing, forwarding and NAT. {instances === 0 && <Link to="/servers">Open the wizard →</Link>}</Item>
      <Item done={sys ? sys.ipv4_forwarding : null} title="Forwarding and NAT enabled">{sys?.ipv4_forwarding ? `IPv4 forwarding on${sys.ipv6_forwarding ? ", IPv6 forwarding on" : ""}.` : "Enabled automatically when you deploy an instance with NAT."}</Item>
      <Item done={clients > 0} title="Add your first client">Get a QR code or configuration file for a phone or laptop. {instances > 0 && clients === 0 && <Link to="/servers">Open your VPN server →</Link>}</Item>
    </ol>
  </section>;
}
