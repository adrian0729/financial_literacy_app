import logging
import os
import time
from typing import Dict

from dotenv import load_dotenv
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes

from database import TokenRecord

load_dotenv()

logger = logging.getLogger(__name__)

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "")
ENVIRONMENT = os.getenv("ENVIRONMENT", "sandbox")

if not (
    REDIRECT_URI.startswith("https://") or REDIRECT_URI.startswith("http://localhost")
):
    logger.warning(
        "REDIRECT_URI is not HTTPS. Intuit requires HTTPS in production environments."
    )


def _build_auth_client() -> AuthClient:
    return AuthClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        environment=ENVIRONMENT,
    )


def get_auth_url(client_key: str, state_token: str) -> str:
    client_key = client_key.strip()
    if not client_key:
        raise ValueError("Client identifier is required.")
    auth_client = _build_auth_client()
    return auth_client.get_authorization_url(
        scopes=[Scopes.ACCOUNTING],
        state_token=state_token,
    )


def exchange_code(params: Dict[str, str], client_key: str) -> TokenRecord:
    auth_code = params.get("code")
    realm_id = params.get("realmId")

    if not auth_code or not realm_id:
        raise ValueError("Callback is missing auth code or realm ID.")

    auth_client = _build_auth_client()
    auth_client.get_bearer_token(auth_code, realm_id=realm_id)
    expires_in = auth_client.expires_in or 3600
    expires_at = int(time.time()) + int(expires_in)

    return TokenRecord(
        client_key=client_key,
        realm_id=realm_id,
        access_token=auth_client.access_token,
        refresh_token=auth_client.refresh_token,
        expires_at=expires_at,
    )


def revoke_refresh_token(refresh_token: str) -> None:
    if not refresh_token:
        return
    auth_client = _build_auth_client()
    try:
        auth_client.revoke(token=refresh_token)
    except Exception as exc:
        logger.warning("Failed to revoke refresh token: %s", exc)
