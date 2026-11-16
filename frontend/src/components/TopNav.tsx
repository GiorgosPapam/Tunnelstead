import { Activity, FileText, Flame, LayoutDashboard, Menu, Moon, Network, RefreshCcw, Server, Settings, Sun, Users, X, LogOut } from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { Me } from "../api";
import { Wordmark } from "./Logo";

export const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/servers", label: "VPN Servers", icon: Server },
  { to: "/clients", label: "Clients", icon: Users },
  { to: "/networks", label: "Networks", icon: Network },
  { to: "/firewall", label: "Firewall", icon: Flame },
  { to: "/monitoring", label: "Monitoring", icon: Activity },
  { to: "/logs", label: "Logs", icon: FileText },
  { to: "/updates", label: "Updates", icon: RefreshCcw },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function TopNav({ me, theme, onTheme, onSignOut }: { me: Me; theme: string; onTheme: () => void; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  useEffect(() => setOpen(false), [loc.pathname]);
  return <header className="sticky top-3 z-40 mx-3 sm:mx-5 mt-3">
    <nav aria-label="Main" className="glass rounded-[22px] px-3 py-2 flex items-center gap-2">
      <div className="px-2 shrink-0"><Wordmark /></div>
      <ul className="hidden lg:flex items-center gap-0.5 mx-auto list-none p-0 m-0">
        {NAV.map(({ to, label, icon: Icon }) => <li key={to}>
          <NavLink to={to} end={to === "/"} className={({ isActive }) =>
            `flex items-center gap-1.5 whitespace-nowrap rounded-xl px-2.5 xl:px-3 py-2 text-[13.5px] font-medium no-underline transition-all duration-200 ${
              isActive ? "text-[var(--text)] bg-[var(--surface-2)] shadow-[inset_0_1px_0_var(--glass-edge)]" : "text-[var(--muted)] hover:text-[var(--text)] hover:bg-[var(--surface)]"}`}>
            {({ isActive }) => <><Icon size={16} aria-hidden="true" style={{ color: isActive ? "var(--primary-2)" : undefined }} />{label}</>}
          </NavLink></li>)}
      </ul>
      <div className="flex items-center gap-1.5 ml-auto lg:ml-0 shrink-0">
        <span className="hidden 2xl:inline muted text-xs px-2">{me.username} · {me.role}</span>
        <button className="btn !p-2" onClick={onTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
          {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}</button>
        <button className="btn !p-2 hidden lg:inline-flex" onClick={onSignOut} aria-label="Sign out"><LogOut size={16} /></button>
        <button className="btn !p-2 lg:hidden" onClick={() => setOpen(!open)} aria-expanded={open} aria-controls="mobile-nav"
          aria-label={open ? "Close menu" : "Open menu"}>{open ? <X size={18} /> : <Menu size={18} />}</button>
      </div>
    </nav>
    {open && <div id="mobile-nav" className="glass rounded-[22px] mt-2 p-2 lg:hidden">
      <ul className="grid grid-cols-2 gap-1 list-none p-0 m-0">
        {NAV.map(({ to, label, icon: Icon }) => <li key={to}><NavLink to={to} end={to === "/"} className={({ isActive }) =>
          `flex items-center gap-2 rounded-xl px-3 py-2.5 text-sm font-medium no-underline ${isActive ? "bg-[var(--surface-2)] text-[var(--text)]" : "text-[var(--muted)]"}`}>
          <Icon size={16} aria-hidden="true" />{label}</NavLink></li>)}
        <li><button className="flex items-center gap-2 rounded-xl px-3 py-2.5 text-sm font-medium w-full text-left bg-transparent border-0 cursor-pointer"
          style={{ color: "var(--bad)" }} onClick={onSignOut}><LogOut size={16} />Sign out</button></li>
      </ul>
    </div>}
  </header>;
}
