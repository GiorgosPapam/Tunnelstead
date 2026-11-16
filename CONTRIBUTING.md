# Contributing

## Setup

```bash
cd backend && python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt ruff mypy
cd frontend && npm ci
```

## Before opening a pull request

```bash
ruff check . && mypy                                  # from the repository root
(cd backend && .venv/bin/python -m pytest -q)
(cd frontend && npm run build && npx playwright test)
shellcheck -S warning installer/*.sh
```

CI runs the same checks plus dependency audits, a secret scan and CodeQL.

## Rules

- Anything that changes the system goes through the privileged helper as a **new allowlisted method that
  validates every argument before doing anything**, with tests that feed it hostile input. The API never runs
  commands itself.
- Never touch resources VPNix Create did not create (other WireGuard/OpenVPN configs, nftables tables, Caddy sites).
- Every API route declares its permission; add an RBAC test for new routes.
- Database changes need an Alembic migration (`alembic revision --autogenerate`) and must keep upgrades working.
- Changes to the helper, firewall, VPN engines, backups or updates must also pass the real-system tests in
  `tests-e2e/` on a disposable Linux server (they run as root and create/remove real interfaces).
- Never log secrets. Never commit keys, `.env` files or databases.
