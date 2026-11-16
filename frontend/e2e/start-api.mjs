// Throwaway API for browser tests: fresh SQLite DB, first admin created by the real installer CLI.
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const backend = join(import.meta.dirname, "..", "..", "backend");
const py = process.env.VPNIX_PYTHON ?? (process.platform === "win32" ? join(backend, ".venv", "Scripts", "python.exe") : "python");
const db = join(tmpdir(), "vpnix-create-ui.db").replaceAll("\\", "/");
for (const f of [db, db + "-wal", db + "-shm"]) rmSync(f, { force: true });
const env = { ...process.env, VPNIX_DATABASE_URL: `sqlite:///${db}`, VPNIX_SECRET_KEY: randomBytes(32).toString("base64url"),
  VPNIX_COOKIE_SECURE: "false", VPNIX_BACKGROUND_JOBS: "false", VPNIX_UI_TEST_HELPER: "1", VPNIX_AUTH_RATE_PER_MINUTE: "500" };
// A throwaway release key and a signed fake bundle for the Updates page (never the real release key).
const feed = join(tmpdir(), "vpnix-create-ui-feed"); const dl = join(tmpdir(), "vpnix-create-ui-updates");
for (const d of [feed, dl]) rmSync(d, { recursive: true, force: true });
const mk = spawnSync(py, ["-c", `
import base64, hashlib, io, os, sys, tarfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
k = Ed25519PrivateKey.generate(); d = sys.argv[1]; os.makedirs(d); v = "9.9.9"
buf = io.BytesIO(); t = tarfile.open(fileobj=buf, mode="w:gz"); i = tarfile.TarInfo(f"vpnix-create-{v}/VERSION"); i.size = 6
t.addfile(i, io.BytesIO(b"9.9.9\\n")); t.close(); b = buf.getvalue()
open(f"{d}/vpnix-create-{v}.tar.gz", "wb").write(b)
open(f"{d}/vpnix-create-{v}.tar.gz.sig", "w").write(base64.b64encode(k.sign(f"vpnix-create-release:{v}:{hashlib.sha256(b).hexdigest()}".encode())).decode())
open(f"{d}/{v}.md", "w").write("- Faster dashboard\\n- Security fixes")
print(base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())`, feed], { encoding: "utf8" });
if (mk.status !== 0) { console.error(mk.stderr); process.exit(1); }
Object.assign(env, { VPNIX_UPDATE_FEED_DIR: feed, VPNIX_UPDATE_DIR: dl, VPNIX_TEST_RELEASE_PUBKEY: mk.stdout.trim() });
const run = (args) => spawnSync(py, ["-m", "vpnix_create.cli", ...args], { cwd: backend, env, encoding: "utf8" });
if (run(["migrate"]).status !== 0) process.exit(1);
const init = run(["init-admin", "--username", "admin"]);
const pw = /VPNIX_ADMIN_PASSWORD=(\S+)/.exec(init.stdout)?.[1];
if (!pw) { console.error(init.stderr); process.exit(1); }
writeFileSync(join(tmpdir(), "vpnix-create-ui-admin.txt"), pw, { mode: 0o600 });  // read by the tests only
const api = spawn(py, ["-m", "uvicorn", "vpnix_create.main:app", "--port", "8011"], { cwd: backend, env, stdio: "inherit" });
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { api.kill(); process.exit(0); });
