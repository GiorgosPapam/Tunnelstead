import { FormEvent, useState } from "react";
import { api, setCsrf } from "../api";
import { Wordmark } from "../components/Logo";
import { Alert, Field } from "../components/ui";

export default function Login({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState(""); const [password, setPassword] = useState("");
  const [code, setCode] = useState(""); const [mfa, setMfa] = useState(false);
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null); setBusy(true);
    try {
      if (!mfa) {
        const r = await api<{ csrf_token: string; mfa_required: boolean }>("/api/auth/login", { method: "POST", body: { username, password } });
        setCsrf(r.csrf_token); setPassword("");
        if (r.mfa_required) { setMfa(true); return; }
      } else {
        setCsrf((await api<{ csrf_token: string }>("/api/auth/mfa/verify", { method: "POST", body: { code: code.trim() } })).csrf_token);
      }
      onDone();
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  return <main className="min-h-screen grid place-items-center p-4">
    <form onSubmit={submit} className="glass rounded-[28px] w-full max-w-sm p-7" aria-labelledby="login-title">
      <div className="flex justify-center mb-5"><Wordmark /></div>
      <h1 id="login-title" className="text-xl font-semibold text-center m-0">{mfa ? "Two-factor verification" : "Sign in"}</h1>
      <p className="muted text-sm text-center mt-1 mb-4">{mfa ? "Enter the 6-digit code from your authenticator app, or a recovery code." : "Manage your VPN servers securely."}</p>
      <Alert>{err}</Alert>
      {!mfa ? <>
        <Field id="username" label="Username"><input id="username" className="field" autoComplete="username" required autoFocus
          value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        <Field id="password" label="Password"><input id="password" className="field" type="password" autoComplete="current-password"
          required value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
      </> : <Field id="code" label="Authentication code"><input id="code" className="field tracking-widest" autoComplete="one-time-code"
        required autoFocus pattern="\d{6}|[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}" value={code} onChange={(e) => setCode(e.target.value)} /></Field>}
      <button className="btn btn-primary w-full mt-2" disabled={busy}>{busy ? "Checking…" : mfa ? "Verify" : "Sign in"}</button>
      <p className="muted text-xs text-center mt-5 mb-0">Forgot your password? An administrator can reset it, or run<br />
        <code>vpnix-create-cli reset-admin</code> on the server.</p>
    </form>
  </main>;
}
