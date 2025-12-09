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
    return {"id": user.id, "email": user.email, "role": user.role}


def _serialize_clients(clients: List[Client]) -> List[dict]:
    return [
        {
            "id": client.id,
            "name": client.name,
            "client_key": client.client_key,
            "connected": client.connected,
            "realm_id": client.realm_id,
        }
        for client in clients
    ]


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
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, client_key: Optional[str] = None):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)

    user = get_user_by_id(user_id)
    if not user:
        request.session.clear()
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)

    clients = list_clients_for_user(user)
    session_selected = request.session.pop("last_connected_client", None)
    default_key = client_key or session_selected or (clients[0].client_key if clients else "")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": _sanitize_user(user),
            "clients": _serialize_clients(clients),
            "default_client_key": default_key,
        },
    )


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
    return RedirectResponse(f"/?client_key={token_record.client_key}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/company")
def company(client_key: Optional[str] = None, user: User = Depends(require_user)):
    selected = _resolve_client_key(client_key, user)
    return get_company_info(selected)


@app.get("/metrics")
def metrics(client_key: Optional[str] = None, user: User = Depends(require_user)):
    selected = _resolve_client_key(client_key, user)
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
