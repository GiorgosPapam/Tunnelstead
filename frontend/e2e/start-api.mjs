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
  VPNIX_COOKIE_SECURE: "false", VPNIX_BACKGROUND_JOBS: "false" };
const run = (args) => spawnSync(py, ["-m", "vpnix_create.cli", ...args], { cwd: backend, env, encoding: "utf8" });
if (run(["migrate"]).status !== 0) process.exit(1);
const init = run(["init-admin", "--username", "admin"]);
const pw = /VPNIX_ADMIN_PASSWORD=(\S+)/.exec(init.stdout)?.[1];
if (!pw) { console.error(init.stderr); process.exit(1); }
writeFileSync(join(tmpdir(), "vpnix-create-ui-admin.txt"), pw, { mode: 0o600 });  // read by the tests only
const api = spawn(py, ["-m", "uvicorn", "vpnix_create.main:app", "--port", "8011"], { cwd: backend, env, stdio: "inherit" });
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { api.kill(); process.exit(0); });
