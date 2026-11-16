import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api, Me, setCsrf } from "./api";
import { TopNav } from "./components/TopNav";
import { Spinner } from "./components/ui";
import Login from "./pages/Login";
import ForcePassword from "./pages/ForcePassword";
import Overview from "./pages/Overview";
import Logs from "./pages/Logs";
import SettingsPage from "./pages/Settings";
import Upcoming from "./pages/Upcoming";
import Servers from "./pages/Servers";
import Clients from "./pages/Clients";

function useTheme() {
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem("vpnix_theme") ?? "dark"; } catch { return "dark"; } });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("vpnix_theme", theme); } catch { /* storage unavailable: theme still applies */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))] as const;
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [theme, toggle] = useTheme();
  const load = useCallback(() => api<Me>("/api/auth/me").then(setMe).catch(() => setMe(null)), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const out = () => setMe(null);
    window.addEventListener("vpnix:signed-out", out);
    return () => window.removeEventListener("vpnix:signed-out", out);
  }, []);
  const signOut = async () => { await api("/api/auth/logout", { method: "POST" }).catch(() => {}); setCsrf(null); setMe(null); };

  if (me === undefined) return <div className="grid place-items-center min-h-screen"><Spinner /></div>;
  if (me === null) return <Login onDone={load} />;
  if (me.must_change_password) return <ForcePassword me={me} onDone={load} onSignOut={signOut} />;

  return <div className="min-h-screen pb-10">
    <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 btn">Skip to content</a>
    <TopNav me={me} theme={theme} onTheme={toggle} onSignOut={signOut} />
    <main id="main" className="max-w-[1280px] mx-auto px-4 sm:px-6 pt-7">
      <Routes>
        <Route path="/" element={<Overview isAdmin={me.role === "admin"} />} />
        <Route path="/servers" element={<Servers me={me} />} />
        <Route path="/clients" element={<Clients me={me} />} />
        <Route path="/networks" element={<Upcoming title="Networks" phase={4} text="Full-tunnel and split-tunnel routing, IPv4 and IPv6, NAT and DNS leak checks." />} />
        <Route path="/firewall" element={<Upcoming title="Firewall" phase={4} text="Application-managed nftables rules with validation, preview and automatic rollback." />} />
        <Route path="/monitoring" element={<Upcoming title="Monitoring" phase={5} text="Throughput, connection history and service health charts." />} />
        <Route path="/logs" element={<Logs me={me} />} />
        <Route path="/updates" element={<Upcoming title="Updates" phase={6} text="Signed GitHub releases with install-now or scheduled updates and automatic rollback." />} />
        <Route path="/settings" element={<SettingsPage me={me} reload={load} />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </main>
  </div>;
}
