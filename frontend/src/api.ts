// API client. The session is an HttpOnly cookie the browser manages; JavaScript never sees it.
// The CSRF token is kept in memory only (re-issued on every sign-in), never in localStorage.
let csrf: string | null = null;
export const setCsrf = (t: string | null) => { csrf = t; };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function api<T = unknown>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
  const r = await fetch(path, { method, headers, credentials: "same-origin",
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  if (!r.ok) {
    let msg = `Request failed (${r.status})`;
    try {
      const j = await r.json();
      msg = typeof j.detail === "string" ? j.detail
        : Array.isArray(j.detail) ? j.detail.map((d: { loc?: string[]; msg: string }) => `${d.loc?.at(-1) ?? "field"}: ${d.msg}`).join("; ")
        : msg;
    } catch { /* not JSON */ }
    if (r.status === 401) window.dispatchEvent(new Event("vpnix:signed-out"));
    throw new ApiError(r.status, msg);
  }
  return r.status === 204 ? (undefined as T) : r.json();
}

export const fmtBytes = (n: number | null | undefined) => {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
};
export const fmtDate = (s: string | null | undefined) =>
  s ? new Date(/([zZ]|[+-]\d\d:\d\d)$/.test(s) ? s : s + "Z").toLocaleString() : "—";

export type Me = { id: number; username: string; email: string | null; role: "admin" | "operator" | "viewer";
  mfa_enabled: boolean; must_change_password: boolean };
export const can = (me: Me, perm: "users.manage" | "audit.view" | "instances.manage" | "clients.manage") =>
  me.role === "admin" || (perm === "clients.manage" && me.role === "operator");
