import { FormEvent, useState } from "react";
import { api, Me, setCsrf } from "../api";
import { Wordmark } from "../components/Logo";
import { Alert, Field } from "../components/ui";

export default function ForcePassword({ me, onDone, onSignOut }: { me: Me; onDone: () => void; onSignOut: () => void }) {
  const [cur, setCur] = useState(""); const [pw, setPw] = useState(""); const [pw2, setPw2] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    if (pw !== pw2) { setErr("The new passwords do not match."); return; }
    try {
      setCsrf((await api<{ csrf_token: string }>("/api/auth/password", { method: "POST", body: { current_password: cur, new_password: pw } })).csrf_token);
      onDone();
    } catch (e) { setErr((e as Error).message); }
  };
  return <main className="min-h-screen grid place-items-center p-4">
    <form onSubmit={submit} className="glass rounded-[28px] w-full max-w-sm p-7">
      <div className="flex justify-center mb-5"><Wordmark /></div>
      <h1 className="text-xl font-semibold text-center m-0">Set your password</h1>
      <p className="muted text-sm text-center mt-1 mb-4">Hi {me.username}. Your current password is temporary. Choose your own to continue.</p>
      <Alert>{err}</Alert>
      <Field id="cur" label="Temporary password"><input id="cur" className="field" type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></Field>
      <Field id="pw" label="New password" hint="At least 12 characters, not containing your username."><input id="pw" className="field" type="password" autoComplete="new-password" minLength={12} required aria-describedby="pw-hint" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
      <Field id="pw2" label="Repeat new password"><input id="pw2" className="field" type="password" autoComplete="new-password" minLength={12} required value={pw2} onChange={(e) => setPw2(e.target.value)} /></Field>
      <button className="btn btn-primary w-full mt-2">Save and continue</button>
      <button type="button" className="btn w-full mt-2" onClick={onSignOut}>Sign out</button>
    </form>
  </main>;
}
