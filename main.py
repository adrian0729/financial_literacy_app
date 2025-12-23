import logging
import os
import secrets
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from starlette.middleware.sessions import SessionMiddleware

from database import (
    Client,
    User,
    DB_INITIALIZED_NEW,
    create_client_account,
    delete_client_account,
    delete_tokens,
    ensure_client_access,
    get_tokens,
    get_user_by_id,
    list_clients_for_user,
    update_user_credentials,
    record_audit_event,
    save_tokens,
    verify_user_credentials,
    get_firm_profile,
    upsert_firm_profile,
    get_client_profile,
    update_client_profile,
    set_user_onboarding_completed,
    set_client_onboarding_completed,
)
from oauth import exchange_code, get_auth_url, revoke_refresh_token
from qb_api import get_balance_sheet_metrics, get_company_info

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


def _load_session_secret(db_reset: bool) -> str:
    env_secret = os.getenv("SESSION_SECRET")
    if env_secret and env_secret.lower() not in {"", "auto"}:
        return env_secret

    secret_path = DATA_DIR / "session_secret.key"
    if db_reset and secret_path.exists():
        secret_path.unlink()

    if secret_path.exists():
        return secret_path.read_text().strip()

    secret = secrets.token_urlsafe(48)
    secret_path.write_text(secret)
    return secret


SESSION_SECRET_VALUE = _load_session_secret(DB_INITIALIZED_NEW)
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
LOGIN_PATH = "/login"

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_VALUE,
    max_age=60 * 60 * 8,
    session_cookie="sarner_session",
    same_site="lax",
    https_only=SESSION_COOKIE_SECURE,
)
templates = Jinja2Templates(directory="templates")


def require_user(request: Request) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    user = get_user_by_id(user_id)
    if not user:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired.")
    return user


def _sanitize_user(user: User) -> dict:
    return {"id": user.id, "email": user.email, "role": user.role, "onboarding_completed": getattr(user, "onboarding_completed", 0)}


def _default_firm_profile(user: User) -> dict:
    profile = get_firm_profile(user.id)
    if profile:
        return {
            "firm_name": profile.firm_name,
            "company_type": profile.company_type,
            "contact_first_name": profile.contact_first_name,
            "contact_last_name": profile.contact_last_name,
            "contact_phone": profile.contact_phone,
            "address_line": profile.address_line,
            "city": profile.city,
            "state": profile.state,
            "postal_code": profile.postal_code,
            "client_volume": profile.client_volume,
            "website": profile.website,
        }
    return {
        "firm_name": "Your firm",
        "company_type": "accounting",
        "contact_first_name": None,
        "contact_last_name": None,
        "contact_phone": None,
        "address_line": None,
        "city": None,
        "state": None,
        "postal_code": None,
        "client_volume": None,
        "website": None,
    }


def _serialize_clients(clients: List[Client]) -> List[dict]:
    return [
        {
            "id": client.id,
            "name": client.name,
            "client_key": client.client_key,
            "connected": client.connected,
            "realm_id": client.realm_id,
            "contact_name": client.contact_name,
            "contact_phone": client.contact_phone,
            "industry": client.industry,
            "onboarding_completed": getattr(client, "onboarding_completed", 0),
        }
        for client in clients
    ]


def _serialize_client(client: Client) -> dict:
    return {
        "id": client.id,
        "name": client.name,
        "client_key": client.client_key,
        "connected": client.connected,
        "realm_id": client.realm_id,
        "contact_name": client.contact_name,
        "contact_phone": client.contact_phone,
        "industry": client.industry,
        "onboarding_completed": getattr(client, "onboarding_completed", 0),
    }


class ClientCreatePayload(BaseModel):
    name: str
    email: EmailStr
    password: str


@app.get(LOGIN_PATH, response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post(LOGIN_PATH)
def login_action(request: Request, email: str = Form(...), password: str = Form(...)):
    user = verify_user_credentials(email, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    request.session["user_id"] = user.id
    if user.role == "admin" and getattr(user, "onboarding_completed", 0) == 0:
        return RedirectResponse("/onboarding/admin?step=1", status_code=status.HTTP_303_SEE_OTHER)
    if user.role == "client" and getattr(user, "onboarding_completed", 0) == 0:
        return RedirectResponse("/onboarding/client?step=1", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/admin/overview" if user.role == "admin" else "/app/overview", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/onboarding/admin", response_class=HTMLResponse)
def onboarding_admin(request: Request, step: int = 1, user: User = Depends(require_user)):
    if user.role != "admin":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    data = request.session.get("admin_onboarding") or {}
    profile = get_firm_profile(user.id)
    return templates.TemplateResponse(
        "onboarding_admin.html",
        {"request": request, "user": _sanitize_user(user), "step": step, "data": data, "profile": profile},
    )


@app.post("/onboarding/admin")
def onboarding_admin_submit(
    request: Request,
    step: int = Form(...),
    company_type: Optional[str] = Form(None),
    firm_name: Optional[str] = Form(None),
    contact_first_name: Optional[str] = Form(None),
    contact_last_name: Optional[str] = Form(None),
    contact_phone: Optional[str] = Form(None),
    address_line: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    postal_code: Optional[str] = Form(None),
    client_volume: Optional[str] = Form(None),
    website: Optional[str] = Form(None),
    user: User = Depends(require_user),
):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can complete onboarding.")
    data = request.session.get("admin_onboarding") or {}
    if company_type:
        data["company_type"] = company_type
    if firm_name:
        data["firm_name"] = firm_name
    if contact_first_name:
        data["contact_first_name"] = contact_first_name
    if contact_last_name:
        data["contact_last_name"] = contact_last_name
    if contact_phone:
        data["contact_phone"] = contact_phone
    if address_line:
        data["address_line"] = address_line
    if city:
        data["city"] = city
    if state:
        data["state"] = state
    if postal_code:
        data["postal_code"] = postal_code
    if client_volume:
        data["client_volume"] = client_volume
    if website:
        data["website"] = website
    request.session["admin_onboarding"] = data
    next_step = step + 1
    if next_step > 6:
        # finalize
        upsert_firm_profile(
            user_id=user.id,
            company_type=data.get("company_type", "accounting"),
            firm_name=data.get("firm_name", "My Firm"),
            contact_first_name=data.get("contact_first_name"),
            contact_last_name=data.get("contact_last_name"),
            contact_phone=data.get("contact_phone"),
            address_line=data.get("address_line"),
            city=data.get("city"),
            state=data.get("state"),
            postal_code=data.get("postal_code"),
            client_volume=data.get("client_volume"),
            website=data.get("website"),
        )
        set_user_onboarding_completed(user.id)
        request.session.pop("admin_onboarding", None)
        return RedirectResponse("/admin/overview", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(f"/onboarding/admin?step={next_step}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/onboarding/client", response_class=HTMLResponse)
def onboarding_client(request: Request, step: int = 1, user: User = Depends(require_user)):
    if user.role != "client":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    data = request.session.get("client_onboarding") or {}
    clients = list_clients_for_user(user)
    client_profile = get_client_profile(clients[0].id) if clients else None
    return templates.TemplateResponse(
        "onboarding_client.html",
        {"request": request, "user": _sanitize_user(user), "step": step, "data": data, "client_profile": client_profile},
    )


@app.post("/onboarding/client")
def onboarding_client_submit(
    request: Request,
    step: int = Form(...),
    contact_name: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    industry: Optional[str] = Form(None),
    employees: Optional[str] = Form(None),
    revenue: Optional[str] = Form(None),
    ecommerce: Optional[str] = Form(None),
    funding: Optional[str] = Form(None),
    intent: Optional[str] = Form(None),
    address_line: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    postal_code: Optional[str] = Form(None),
    user: User = Depends(require_user),
):
    if user.role != "client":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only clients can complete onboarding.")
    data = request.session.get("client_onboarding") or {}
    if contact_name:
        data["contact_name"] = contact_name
    if phone:
        data["phone"] = phone
    if industry:
        data["industry"] = industry
    if employees:
        data["employees"] = employees
    if revenue:
        data["revenue"] = revenue
    if ecommerce is not None:
        data["ecommerce"] = ecommerce
    if funding is not None:
        data["funding"] = funding
    if intent:
        data["intent"] = intent
    if address_line:
        data["address_line"] = address_line
    if city:
        data["city"] = city
    if state:
        data["state"] = state
    if postal_code:
        data["postal_code"] = postal_code
    request.session["client_onboarding"] = data
    next_step = step + 1
    if next_step > 8:
        clients = list_clients_for_user(user)
        if not clients:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Client record missing.")
        update_client_profile(
            clients[0].id,
            contact_name=data.get("contact_name"),
            phone=data.get("phone"),
            industry=data.get("industry"),
            employees=data.get("employees"),
            revenue=data.get("revenue"),
            ecommerce=1 if str(data.get("ecommerce", "")).lower() == "yes" else 0,
            funding=data.get("funding"),
            intent=data.get("intent"),
            address_line=data.get("address_line"),
            city=data.get("city"),
            state=data.get("state"),
            postal_code=data.get("postal_code"),
        )
        set_client_onboarding_completed(clients[0].id)
        set_user_onboarding_completed(user.id)
        request.session.pop("client_onboarding", None)
        return RedirectResponse("/app/overview", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(f"/onboarding/client?step={next_step}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", response_class=HTMLResponse)
def root_redirect(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)
    user = get_user_by_id(user_id)
    if not user:
        request.session.clear()
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)
    if user.role == "admin":
        if getattr(user, "onboarding_completed", 0) == 0:
            return RedirectResponse("/onboarding/admin?step=1", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse("/admin/overview", status_code=status.HTTP_303_SEE_OTHER)
    if getattr(user, "onboarding_completed", 0) == 0:
        return RedirectResponse("/onboarding/client?step=1", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/app/overview", status_code=status.HTTP_303_SEE_OTHER)


def _admin_dashboard_context(request: Request, user: User, section: Optional[str] = None) -> dict:
    clients = list_clients_for_user(user)
    default_client_key = request.query_params.get("client_key") or (clients[0].client_key if clients else "")
    firm_profile = _default_firm_profile(user)
    return {
        "request": request,
        "user": _sanitize_user(user),
        "clients": _serialize_clients(clients),
        "default_client_key": default_client_key,
        "firm_profile": firm_profile,
        "active_section": section or "",
    }


def _client_dashboard_context(request: Request, user: User, section: Optional[str] = None) -> dict:
    clients = list_clients_for_user(user)
    client = clients[0] if clients else None
    profile = get_client_profile(client.id) if client else None
    return {
        "request": request,
        "user": _sanitize_user(user),
        "client": client,
        "client_profile": profile,
        "active_section": section or "",
    }


@app.get("/admin/overview", response_class=HTMLResponse)
def admin_overview(request: Request, section: Optional[str] = None, user: User = Depends(require_user)):
    if user.role != "admin":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("admin_dashboard.html", _admin_dashboard_context(request, user, section))


@app.get("/admin/clients", response_class=HTMLResponse)
def admin_clients(request: Request, user: User = Depends(require_user)):
    if user.role != "admin":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("admin_dashboard.html", _admin_dashboard_context(request, user, "clients"))


@app.get("/admin/metrics", response_class=HTMLResponse)
def admin_metrics(request: Request, user: User = Depends(require_user)):
    if user.role != "admin":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("admin_dashboard.html", _admin_dashboard_context(request, user, "metrics"))


@app.get("/admin/activity", response_class=HTMLResponse)
def admin_activity(request: Request, user: User = Depends(require_user)):
    if user.role != "admin":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/admin/overview", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/account", response_class=HTMLResponse)
def admin_account(request: Request, user: User = Depends(require_user)):
    if user.role != "admin":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("admin_dashboard.html", _admin_dashboard_context(request, user, "account"))


@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings(request: Request, user: User = Depends(require_user)):
    if user.role != "admin":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("admin_dashboard.html", _admin_dashboard_context(request, user, "account"))


@app.get("/app/overview", response_class=HTMLResponse)
def app_overview(request: Request, section: Optional[str] = None, user: User = Depends(require_user)):
    if user.role != "client":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("client_dashboard.html", _client_dashboard_context(request, user, section))


@app.get("/app/metrics", response_class=HTMLResponse)
def app_metrics(request: Request, user: User = Depends(require_user)):
    if user.role != "client":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("client_dashboard.html", _client_dashboard_context(request, user, "metrics"))


@app.get("/app/activity", response_class=HTMLResponse)
def app_activity(request: Request, user: User = Depends(require_user)):
    if user.role != "client":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/app/overview", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/app/account", response_class=HTMLResponse)
def app_account(request: Request, user: User = Depends(require_user)):
    if user.role != "client":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("client_dashboard.html", _client_dashboard_context(request, user, "account"))


@app.get("/app/settings", response_class=HTMLResponse)
def app_settings(request: Request, user: User = Depends(require_user)):
    if user.role != "client":
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("client_dashboard.html", _client_dashboard_context(request, user, "settings"))


@app.get("/auth")
def auth(request: Request, client_key: Optional[str] = None, user: User = Depends(require_user)):
    clients = list_clients_for_user(user)
    target_key = client_key or (clients[0].client_key if clients else None)
    if not target_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No clients available to connect.")
    try:
        ensure_client_access(target_key, user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))

    state_token = secrets.token_urlsafe(32)
    oauth_states = request.session.get("oauth_states") or {}
    oauth_states[state_token] = {"client_key": target_key, "user_id": user.id}
    request.session["oauth_states"] = oauth_states

    return RedirectResponse(get_auth_url(target_key, state_token))


@app.get("/callback")
async def callback(request: Request):
    params = dict(request.query_params)
    state_param = params.get("state")
    oauth_states = request.session.get("oauth_states") or {}
    state_data = oauth_states.pop(state_param, None)
    request.session["oauth_states"] = oauth_states
    if not state_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state.")

    client_key = state_data["client_key"]
    token_record = exchange_code(params, client_key)
    save_tokens(token_record)
    record_audit_event(state_data.get("user_id"), client_key, "quickbooks_connect")
    request.session["last_connected_client"] = token_record.client_key
    user = get_user_by_id(state_data.get("user_id")) if state_data.get("user_id") else None
    if user and user.role == "admin":
        dest = f"/admin/overview?client_key={token_record.client_key}"
    elif user and user.role == "client":
        dest = f"/app/overview?client_key={token_record.client_key}"
    else:
        dest = f"/?client_key={token_record.client_key}"
    return RedirectResponse(dest, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/company")
def company(client_key: Optional[str] = None, user: User = Depends(require_user)):
    selected = _resolve_client_key(client_key, user)
    client = ensure_client_access(selected, user)
    if user.role == "client" and getattr(client, "onboarding_completed", 0) == 0:
        raise HTTPException(status_code=403, detail="Complete onboarding to view company data.")
    return get_company_info(selected)


@app.get("/metrics")
def metrics(client_key: Optional[str] = None, user: User = Depends(require_user)):
    selected = _resolve_client_key(client_key, user)
    client = ensure_client_access(selected, user)
    if user.role == "client" and getattr(client, "onboarding_completed", 0) == 0:
        raise HTTPException(status_code=403, detail="Complete onboarding to view metrics.")
    return get_balance_sheet_metrics(selected)


@app.get("/clients")
def clients(user: User = Depends(require_user)):
    return {"clients": _serialize_clients(list_clients_for_user(user))}


@app.post("/clients")
def create_client(payload: ClientCreatePayload, user: User = Depends(require_user)):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can create clients.")
    try:
        client = create_client_account(payload.name, payload.email, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {"client": {
        "id": client.id,
        "name": client.name,
        "client_key": client.client_key,
        "connected": client.connected,
        "realm_id": client.realm_id,
    }}


@app.delete("/clients/{client_key}")
def delete_client(client_key: str, user: User = Depends(require_user)):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can delete clients.")
    try:
        ensure_client_access(client_key, user)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found.")
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))

    removed = delete_client_account(client_key)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found.")
    delete_tokens(client_key)
    record_audit_event(user.id, client_key, "client_deleted")
    return {"status": "deleted"}


@app.post("/disconnect")
def disconnect(client_key: Optional[str] = None, user: User = Depends(require_user)):
    selected = _resolve_client_key(client_key, user)
    removed = _revoke_and_delete_tokens(selected)
    if removed:
        record_audit_event(user.id, selected, "quickbooks_disconnect")
    return {"status": "disconnected" if removed else "not_connected"}


@app.post("/admin/profile")
def update_admin_profile(
    firm_name: Optional[str] = Form(None),
    company_type: Optional[str] = Form(None),
    contact_first_name: Optional[str] = Form(None),
    contact_last_name: Optional[str] = Form(None),
    contact_phone: Optional[str] = Form(None),
    address_line: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    postal_code: Optional[str] = Form(None),
    client_volume: Optional[str] = Form(None),
    website: Optional[str] = Form(None),
    user: User = Depends(require_user),
):
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can update the firm profile.")
    existing = _default_firm_profile(user)
    upsert_firm_profile(
        user_id=user.id,
        firm_name=firm_name or existing.firm_name,
        company_type=company_type or existing.company_type,
        contact_first_name=contact_first_name or existing.contact_first_name,
        contact_last_name=contact_last_name or existing.contact_last_name,
        contact_phone=contact_phone or existing.contact_phone,
        address_line=address_line or existing.address_line,
        city=city or existing.city,
        state=state or existing.state,
        postal_code=postal_code or existing.postal_code,
        client_volume=client_volume or existing.client_volume,
        website=website or existing.website,
    )
    return {"status": "updated"}


@app.post("/client/profile")
def client_profile_update(
    contact_name: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    industry: Optional[str] = Form(None),
    employees: Optional[str] = Form(None),
    revenue: Optional[str] = Form(None),
    ecommerce: Optional[str] = Form(None),
    funding: Optional[List[str]] = Form(None),
    intent: Optional[str] = Form(None),
    intent_extra: Optional[str] = Form(None),
    address_line: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    postal_code: Optional[str] = Form(None),
    user: User = Depends(require_user),
):
    if user.role != "client":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only clients can update this profile.")
    clients = list_clients_for_user(user)
    if not clients:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Client record missing.")
    primary = clients[0]
    funding_str = ", ".join(funding) if funding else None
    ecommerce_val: Optional[int] = None
    if ecommerce:
        if ecommerce.lower() in {"yes", "true", "1"}:
            ecommerce_val = 1
        elif ecommerce.lower() in {"no", "false", "0"}:
            ecommerce_val = 0
    update_client_profile(
        primary.id,
        contact_name=contact_name,
        phone=phone,
        industry=industry,
        employees=employees,
        revenue=revenue,
        ecommerce=ecommerce_val,
        funding=funding_str,
        intent=intent,
        intent_extra=intent_extra,
        address_line=address_line,
        city=city,
        state=state,
        postal_code=postal_code,
    )
    record_audit_event(user.id, primary.client_key, "client_profile_update")
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/profile/password")
def update_password(
    password: str = Form(...),
    confirm_password: str = Form(...),
    user: User = Depends(require_user),
):
    if password != confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match.")
    try:
        update_user_credentials(user.id, password=password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    record_audit_event(user.id, None, "password_update")
    return {"status": "updated"}


def _resolve_client_key(client_key: Optional[str], user: User) -> str:
    if client_key:
        try:
            ensure_client_access(client_key, user)
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
        return client_key

    clients = list_clients_for_user(user)
    if not clients:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No QuickBooks clients configured.")
    return clients[0].client_key


def _revoke_and_delete_tokens(client_key: str) -> bool:
    record = get_tokens(client_key)
    if not record:
        delete_tokens(client_key)
        return False

    revoke_refresh_token(record.refresh_token)
    delete_tokens(client_key)
    return True
