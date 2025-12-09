# Financial Literacy App

Modern FastAPI + Jinja portal for a firm (admin) and its clients to connect QuickBooks Online, pull balance-sheet data, and surface three financial literacy ratios:

- Working Capital = Current Assets – Current Liabilities
- Working Capital Ratio = Current Assets / Current Liabilities
- Debt-to-Equity Ratio = Total Liabilities / Total Shareholders’ Equity

## What’s inside
- FastAPI backend with OAuth flow for Intuit (QuickBooks Online).
- SQLite persistence (users, clients, firm profiles, client profiles, audit events, encrypted tokens).
- Fernet-encrypted access/refresh tokens at rest; bcrypt-hashed passwords.
- Separate dashboards for admin and client, dark glassmorphism UI.
- First-login onboarding wizards (admin: firm details; client: company contact/location).

## Prerequisites
- Python 3.12+
- A QuickBooks app (sandbox is fine) with OAuth2 keys.
- Fernet token encryption key.

## Environment
Create a `.env` in the repo root with:
```
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=choose_a_password
CLIENT_ID=your_intuit_client_id
CLIENT_SECRET=your_intuit_client_secret
REDIRECT_URI=http://localhost:8000/callback
TOKEN_ENCRYPTION_KEY=your_fernet_key   # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
SESSION_SECRET=auto                     # or set a fixed secret in prod
SESSION_COOKIE_SECURE=false             # true in prod with HTTPS
```

## Setup
```
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Run
```
uvicorn main:app --reload
# or
python runserver.py --reload
```
Visit `http://localhost:8000/login`.

## Roles and flows
- **Admin**
  - Logs in with `ADMIN_EMAIL`/`ADMIN_PASSWORD`.
  - First login → `/onboarding/admin` (3 steps) to capture firm info.
  - Can create client accounts, connect each client to QuickBooks, refresh metrics, delete clients, change password.
- **Client**
  - Receives portal credentials from admin.
  - First login → `/onboarding/client` (2 steps) to capture company contact/location.
  - Connects own QuickBooks company, refreshes metrics, updates profile, changes password.

## Key routes
- `/login` – sign in
- `/onboarding/admin`, `/onboarding/client` – first-time wizards
- `/admin/overview` – admin dashboard (clients, metrics, audit)
- `/app/overview` – client dashboard
- `/auth` → Intuit OAuth start, `/callback` → token exchange and redirect back
- `/metrics` – returns metrics for the selected client (requires auth)

## Data storage
- SQLite file at `data/app.db`.
- Tables: users, clients, firm_profiles, client_profiles, tokens (encrypted), audit_events.
- Session secret stored in `data/session_secret.key` when `SESSION_SECRET=auto`.

## Security notes
- Passwords hashed with bcrypt (passlib).
- Access/refresh tokens encrypted with Fernet (`TOKEN_ENCRYPTION_KEY`).
- Session cookies signed; set `SESSION_COOKIE_SECURE=true` behind HTTPS.
- OAuth state tracked per-session; tokens revoked on disconnect.
- Never commit `.env`, tokens, or encryption keys to source control.

## Resetting
Delete `data/` to reset users/clients/tokens (you’ll need to recreate the admin or rely on `ADMIN_*` envs). Rotate `SESSION_SECRET` to invalidate all sessions after a reset.

## Next steps
- Harden HTTPS/CSRF/ratelimiting for production.
- Add tests for balance-sheet parsing and metric accuracy across locales.
- Add CI for linting and type checks.
