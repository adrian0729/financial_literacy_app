# Financial Literacy App

A FastAPI + Jinja web portal for accounting firms and their clients to connect QuickBooks Online (QBO), surface core balance-sheet metrics, and generate a plain-language financial health overview for startup and small business owners.

This repo is meant for development and demos. It includes multi-step onboarding, admin/client role separation, encrypted token storage, and a clean white UI with green accents.

## Features

### Product
- Admin and client roles with separate dashboards.
- Guided onboarding flows (admin: 6 steps, client: 8 steps) that gate access to metrics.
- QuickBooks OAuth connection per client company.
- Metrics dashboard with ratios and health labels (Healthy/Watch/Action).
- Client account page to edit all onboarding fields later.
- AI-generated financial overview and recommendations (Gemini) in the client overview.

### Security
- bcrypt password hashing via passlib.
- Access/refresh tokens encrypted at rest (Fernet).
- Session cookies signed with a strong secret.
- OAuth state stored in session and validated on callback.

### Backend
- SQLite persistence for users, clients, profiles, tokens, and audit events.
- Token refresh before expiry for QBO requests.
- Clear separation between auth, onboarding, metrics, and profiles.

## Architecture at a glance

- **FastAPI** serves HTML templates (Jinja) and JSON endpoints.
- **QuickBooks Online** OAuth2 provides per-company access.
- **SQLite** stores users, clients, and encrypted tokens.
- **Templates** render the admin and client portals.
- **LLM summary** calls Gemini via REST using `GEMINI_API_KEY`.

## Project structure

```
.
├── main.py                # FastAPI routes, onboarding, dashboards, insights
├── database.py            # SQLite schema, models, token encryption
├── oauth.py               # Intuit OAuth helper functions
├── qb_api.py              # QBO API calls + metric parsing
├── runserver.py           # Dev launcher with optional DB reset
├── requirements.txt
└── templates/
    ├── login.html
    ├── onboarding_admin.html
    ├── onboarding_client.html
    ├── admin_dashboard.html
    └── client_dashboard.html
```

## Prerequisites

- Python 3.12+
- A QuickBooks app (sandbox is fine) with OAuth credentials
- A Fernet key for token encryption

## Environment variables

Create a `.env` file in the repo root:

```
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=choose_a_password
CLIENT_ID=your_intuit_client_id
CLIENT_SECRET=your_intuit_client_secret
REDIRECT_URI=http://localhost:8000/callback
ENVIRONMENT=sandbox
TOKEN_ENCRYPTION_KEY=your_fernet_key
SESSION_SECRET=auto
SESSION_COOKIE_SECURE=false
GEMINI_API_KEY=your_google_gemini_key
```

Notes:
- Generate a Fernet key:
  ```bash
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```
- `SESSION_SECRET=auto` generates and stores a secret in `data/session_secret.key` on first run.
- Use HTTPS + `SESSION_COOKIE_SECURE=true` in production.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Run the app

```bash
uvicorn main:app --reload
# or
python runserver.py --reload
```

Visit:
- Login page: `http://localhost:8000/login`

## Reset the app

### Option A: use the helper script
```bash
python runserver.py --restart --reload
```
This removes `data/` (database + session secret) and starts a fresh instance.

### Option B: manual reset
```bash
rm -rf data/
```

## Roles and onboarding

### Admin (accounting firm)
- Logs in with `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
- First login triggers **6-step onboarding**:
  1) Firm name + company type
  2) Contact first/last name
  3) Phone
  4) Address line + city
  5) State + postal code
  6) Client volume + website
- After onboarding, the admin dashboard is available.
- Admin can create client logins, connect QBO, refresh metrics, disconnect or delete client accounts, and update firm profile.

### Client (business owner)
- Gets credentials from the admin.
- First login triggers **8-step onboarding**:
  1) Primary contact + phone
  2) Industry
  3) Team size + revenue range
  4) E-commerce (yes/no)
  5) Funding sources
  6) Primary goal + optional notes
  7) Address line + city
  8) State + postal code
- Metrics and AI insights are gated until onboarding completes.
- The client can connect QBO, refresh metrics, and update account details.

## QuickBooks OAuth flow

1. Admin or client clicks **Connect QuickBooks**.
2. `/auth` builds an authorization URL and redirects to Intuit.
3. Intuit redirects back to `/callback` with `code`, `realmId`, and `state`.
4. The app exchanges the code for tokens and stores them encrypted.
5. The user is redirected back to their dashboard.

## Metrics and calculations

The `/metrics` endpoint returns:
- Current Assets
- Current Liabilities
- Total Liabilities
- Total Equity
- Working Capital
- Working Capital Ratio
- Debt-to-Equity Ratio

**Calculation approach**
- Primary: QBO BalanceSheet report totals (US label matching).
- Fallback: account aggregation by QBO account types and subtypes.

**Note:** Different countries may label totals differently. The current implementation is optimized for US-based balance sheets and will fall back if the report labels differ.

## AI-generated financial overview

Clients can generate a financial health summary from the Overview page.
- Endpoint: `/insights`
- Provider: Gemini API (`GEMINI_API_KEY`)
- Inputs: onboarding profile, QBO company info, and metrics
- Output: plain-language summary, strengths, risks, and next steps

**Important:** This sends company data to an LLM provider. Use only in development or with customer consent.

## API routes (summary)

### Auth & onboarding
- `GET /login`, `POST /login`
- `POST /logout`
- `GET/POST /onboarding/admin`
- `GET/POST /onboarding/client`

### Dashboards
- `GET /admin/overview`
- `GET /admin/clients`
- `GET /admin/metrics`
- `GET /admin/account`
- `GET /app/overview`
- `GET /app/metrics`
- `GET /app/account`

### QuickBooks
- `GET /auth`
- `GET /callback`
- `GET /metrics`
- `GET /company`
- `POST /disconnect`

### Admin actions
- `GET /clients`
- `POST /clients`
- `DELETE /clients/{client_key}`
- `POST /admin/profile`

### Client actions
- `POST /client/profile`
- `POST /profile/password`
- `GET /insights`

## Database schema (SQLite)

Tables:
- `users`: admin/client accounts
- `clients`: companies tied to admins
- `firm_profiles`: admin onboarding data
- `client_profiles`: client onboarding data
- `tokens`: encrypted QBO tokens per client
- `audit_events`: optional audit trail

Data location: `data/app.db`

## UI overview

**Admin portal**
- Overview: what the portal does and recommended actions
- Clients & Metrics: create clients, connect QBO, refresh ratios
- Account: firm profile + password change

**Client portal**
- Overview: status + AI financial overview
- Metrics: connect QBO + refresh ratios
- Account: edit onboarding fields + change password

## Troubleshooting

- **Login fails**: ensure `ADMIN_EMAIL` and `ADMIN_PASSWORD` match `.env`.
- **Missing token errors**: connect the client to QuickBooks via **Connect QuickBooks**.
- **401/3200 QBO errors**: tokens expired or revoked; reconnect the client.
- **GEMINI errors**: set `GEMINI_API_KEY` and verify network access.
- **Onboarding loop**: delete `data/` to reset onboarding status.

## Development notes

- `runserver.py --restart` wipes `data/` (DB + session secret).
- Keep `venv/` out of git (already ignored in `.gitignore`).
- Update dependencies in `requirements.txt` when adding packages.

## Production readiness checklist (high level)

- Enforce HTTPS end-to-end (Intuit requires HTTPS in prod).
- Use a managed database (Postgres) instead of SQLite.
- Add CSRF protection and rate limiting for auth endpoints.
- Configure MFA for admin users.
- Centralize logs and add monitoring/alerts.
- Provide privacy policy and support contact for Intuit review.

---

If you want a more detailed deployment guide or a production hardening plan, say the word.
