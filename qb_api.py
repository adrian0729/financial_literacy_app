import logging
import os
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from fastapi import HTTPException
from intuitlib.client import AuthClient
from quickbooks import QuickBooks
from quickbooks.objects.company_info import CompanyInfo

from database import TokenRecord, get_tokens, save_tokens

logger = logging.getLogger(__name__)

# US-specific balance sheet labels we can reliably target.
BALANCE_SHEET_LABELS: Dict[str, List[str]] = {
    "current_assets": ["Total Current Assets"],
    "current_liabilities": ["Total Current Liabilities"],
    "total_liabilities": ["Total Liabilities"],
    "total_equity": ["Total for Equity", "Total Equity", "Total Shareholders' Equity"],
}

# Account subtype/type groupings (lowercase) we treat as current assets / liabilities.
CURRENT_ASSET_SUBTYPES: Set[str] = {
    "accountsreceivable",
    "allowanceforbaddebts",
    "inventory",
    "othercurrentassets",
    "prepaidexpenses",
    "undepositedfunds",
    "cashonhand",
    "checking",
    "savings",
    "moneymarket",
    "trustaccounts",
    "currentassets",
    "shortterminvestments",
}
CURRENT_ASSET_TYPES: Set[str] = {
    "accounts receivable",
    "other current asset",
    "current asset",
    "inventory",
    "bank",
    "cash",
}
CURRENT_LIABILITY_SUBTYPES: Set[str] = {
    "accountspayable",
    "currenttaxliability",
    "payrollliabilities",
    "salestaxpayable",
    "othercurrentliabilities",
    "creditcard",
    "shorttermdebt",
    "lineofcredit",
    "currentportionnotespayable",
    "currentportionlongtermdebt",
    "incometaxpayable",
    "interestpayable",
}
CURRENT_LIABILITY_TYPES: Set[str] = {
    "accounts payable",
    "other current liability",
    "current liability",
    "credit card",
}


def get_company_info(client_key: str) -> List[Any]:
    client, _ = _build_quickbooks_client(client_key)

    try:
        company_info: List[Any] = CompanyInfo.all(qb=client)
        logger.info("Company info retrieved for client %s", client_key)
    except Exception as exc:
        logger.exception("QuickBooks company info failed for client %s", client_key)
        raise HTTPException(status_code=502, detail=f"QuickBooks request failed: {exc}") from exc

    return [info.to_dict() if hasattr(info, "to_dict") else info for info in company_info]


def get_balance_sheet_metrics(client_key: str) -> Dict[str, Optional[float]]:
    client, _ = _build_quickbooks_client(client_key)

    current_assets = current_liabilities = total_liabilities = total_equity = None
    try:
        report_totals = _fetch_balance_sheet_values(client_key, client)
        current_assets = report_totals["current_assets"]
        current_liabilities = report_totals["current_liabilities"]
        total_liabilities = report_totals["total_liabilities"]
        total_equity = report_totals["total_equity"]
    except HTTPException as exc:
        logger.warning("Balance Sheet parsing failed for %s: %s. Falling back to account aggregation.", client_key, exc.detail)
        accounts = _fetch_all_accounts(client_key, client)
        if not accounts:
            raise HTTPException(status_code=502, detail="No accounts were returned from QuickBooks.")
        metrics = _aggregate_account_metrics(accounts, client_key)
        current_assets = metrics["current_assets"]
        current_liabilities = metrics["current_liabilities"]
        total_liabilities = metrics["total_liabilities"]
        total_equity = metrics["total_equity"]

    if any(value is None for value in [current_assets, current_liabilities, total_liabilities, total_equity]):
        raise HTTPException(status_code=502, detail="Unable to determine balance sheet totals.")

    working_capital = current_assets - current_liabilities
    working_capital_ratio = current_assets / current_liabilities if current_liabilities != 0 else None
    debt_to_equity_ratio = total_liabilities / total_equity if total_equity != 0 else None

    return {
        "currentAssets": _decimal_to_number(current_assets),
        "currentLiabilities": _decimal_to_number(current_liabilities),
        "totalLiabilities": _decimal_to_number(total_liabilities),
        "totalEquity": _decimal_to_number(total_equity),
        "workingCapital": _decimal_to_number(working_capital),
        "workingCapitalRatio": _decimal_to_number(working_capital_ratio) if working_capital_ratio is not None else None,
        "debtToEquityRatio": _decimal_to_number(debt_to_equity_ratio) if debt_to_equity_ratio is not None else None,
    }


def _build_quickbooks_client(client_key: str) -> Tuple[QuickBooks, TokenRecord]:
    record = _get_token_record(client_key)

    auth_client = AuthClient(
        client_id=os.getenv("CLIENT_ID"),
        client_secret=os.getenv("CLIENT_SECRET"),
        redirect_uri=os.getenv("REDIRECT_URI"),
        environment=os.getenv("ENVIRONMENT"),
    )
    auth_client.access_token = record.access_token
    auth_client.refresh_token = record.refresh_token
    auth_client.realm_id = record.realm_id

    record = _ensure_fresh_tokens(client_key, auth_client, record)
    auth_client.access_token = record.access_token
    auth_client.refresh_token = record.refresh_token
    auth_client.realm_id = record.realm_id

    try:
        qb_client = QuickBooks(auth_client=auth_client, company_id=record.realm_id)
    except Exception as exc:
        logger.exception("Unable to initialize QuickBooks client for %s", client_key)
        raise HTTPException(status_code=502, detail=f"Unable to initialize QuickBooks client: {exc}") from exc

    return qb_client, record


def _get_token_record(client_key: str) -> TokenRecord:
    record = get_tokens(client_key)
    if record is None:
        logger.warning("No QuickBooks tokens found for client %s", client_key)
        raise HTTPException(
            status_code=400,
            detail=f"No QuickBooks connection found for client '{client_key}'. Connect via /auth.",
        )
    return record


def _ensure_fresh_tokens(client_key: str, auth_client: AuthClient, record: TokenRecord) -> TokenRecord:
    if record.expires_at > int(time.time()) + 60:
        return record

    logger.info("Refreshing QuickBooks tokens for client %s", client_key)
    try:
        auth_client.refresh(refresh_token=record.refresh_token)
    except Exception as exc:
        logger.exception("Token refresh failed for client %s", client_key)
        raise HTTPException(
            status_code=401,
            detail="QuickBooks authorization expired. Reconnect via /auth to continue.",
        ) from exc

    expires_in = auth_client.expires_in or 3600
    refreshed = TokenRecord(
        client_key=client_key,
        realm_id=record.realm_id,
        access_token=auth_client.access_token,
        refresh_token=auth_client.refresh_token,
        expires_at=int(time.time()) + int(expires_in),
    )
    save_tokens(refreshed)
    return refreshed


def _fetch_all_accounts(client_key: str, client: QuickBooks) -> List[Dict[str, Any]]:
    start_pos = 1
    page_size = 500
    accounts: List[Dict[str, Any]] = []
    while True:
        query = (
            "select Id, Name, AccountType, AccountSubType, Classification, CurrentBalance "
            "from Account where Active = true "
            f"startposition {start_pos} maxresults {page_size}"
        )
        try:
            response = client.query(query)
        except Exception as exc:
            logger.exception("Account query failed for client %s", client_key)
            raise HTTPException(status_code=502, detail=f"Unable to query accounts: {exc}") from exc

        batch = response.get("QueryResponse", {}).get("Account", [])
        accounts.extend(batch)
        if len(batch) < page_size:
            break
        start_pos += page_size
    logger.info("Fetched %s accounts for client %s", len(accounts), client_key)
    return accounts


def _aggregate_account_metrics(accounts: List[Dict[str, Any]], client_key: str) -> Dict[str, Decimal]:
    metrics = {
        "total_assets": Decimal("0"),
        "current_assets": Decimal("0"),
        "current_liabilities": Decimal("0"),
        "total_liabilities": Decimal("0"),
        "total_equity": Decimal("0"),
    }
    found_current_assets = False
    found_current_liabilities = False

    for account in accounts:
        classification = (account.get("Classification") or "").strip().lower()
        if classification not in {
            "asset",
            "liability",
            "equity",
            "revenue",
            "income",
            "otherincome",
            "expense",
            "otherexpense",
            "costofgoodssold",
        }:
            continue

        amount = _account_balance_amount(account)
        if amount is None:
            continue

        if classification == "asset":
            metrics["total_assets"] += abs(amount)
            if _is_current_asset(account):
                metrics["current_assets"] += abs(amount)
                found_current_assets = True
        elif classification == "liability":
            metrics["total_liabilities"] += abs(amount)
            if _is_current_liability(account):
                metrics["current_liabilities"] += abs(amount)
                found_current_liabilities = True

    if not found_current_assets or not found_current_liabilities:
        missing = []
        if not found_current_assets:
            missing.append("current assets")
        if not found_current_liabilities:
            missing.append("current liabilities")
        readable = ", ".join(missing)
        logger.error("Unable to determine %s for client %s from accounts", readable, client_key)
        raise HTTPException(
            status_code=502,
            detail=f"Unable to determine {readable} from QuickBooks accounts. Review account types.",
        )

    metrics["total_equity"] = metrics["total_assets"] - metrics["total_liabilities"]
    return metrics


def _is_current_asset(account: Dict[str, Any]) -> bool:
    subtype = (account.get("AccountSubType") or "").strip().lower()
    account_type = (account.get("AccountType") or "").strip().lower()
    if subtype in CURRENT_ASSET_SUBTYPES or account_type in CURRENT_ASSET_TYPES:
        return True
    if "current asset" in account_type:
        return True
    if any(keyword in subtype for keyword in ("current", "cash", "inventory", "receivable", "depositor", "bank")):
        return True
    return False


def _is_current_liability(account: Dict[str, Any]) -> bool:
    subtype = (account.get("AccountSubType") or "").strip().lower()
    account_type = (account.get("AccountType") or "").strip().lower()
    if subtype in CURRENT_LIABILITY_SUBTYPES or account_type in CURRENT_LIABILITY_TYPES:
        return True
    if "current liability" in account_type:
        return True
    if any(keyword in subtype for keyword in ("creditor", "payable", "current", "tax", "vat", "gst")):
        return True
    return False


def _parse_decimal_value(value: Any) -> Decimal:
    if value is None:
        return Decimal("0")
    if isinstance(value, (int, float, Decimal)):
        return Decimal(str(value))
    text = str(value).strip()
    if not text:
        return Decimal("0")
    negative = False
    if text.startswith("(") and text.endswith(")"):
        negative = True
        text = text[1:-1]
    cleaned = (
        text.replace(",", "")
        .replace("$", "")
        .replace("£", "")
        .replace("€", "")
        .replace("HK$", "")
        .strip()
    )
    if cleaned in {"", "-", "--"}:
        return Decimal("0")
    amount = Decimal(cleaned)
    return -amount if negative else amount


def _account_balance_amount(account: Dict[str, Any]) -> Optional[Decimal]:
    try:
        amount = _parse_decimal_value(account.get("CurrentBalance"))
    except InvalidOperation:
        logger.warning("Skipping account %s due to invalid balance '%s'", account.get("Id"), account.get("CurrentBalance"))
        return None
    return amount


def _decimal_to_number(value: Optional[Decimal]) -> Optional[float]:
    if value is None:
        return None
    return float(value)


def _fetch_balance_sheet_values(client_key: str, client: QuickBooks) -> Dict[str, Decimal]:
    try:
        report = client.get_report("BalanceSheet", qs={"summarize_column_by": "Total"})
        logger.info("Balance sheet report fetched for client %s", client_key)
    except Exception as exc:
        logger.exception("Unable to load balance sheet report for client %s", client_key)
        raise HTTPException(status_code=502, detail=f"Unable to load balance sheet: {exc}") from exc

    rows = report.get("Rows", {}).get("Row", [])
    values: Dict[str, Decimal] = {}
    for key, label_options in BALANCE_SHEET_LABELS.items():
        value = _find_report_value(rows, label_options)
        if value is None:
            raise HTTPException(status_code=502, detail=f"Balance sheet total '{label_options[0]}' not found.")
        values[key] = value
    return values


def _find_report_value(rows: Iterable[Dict[str, Any]], labels: List[str]) -> Optional[Decimal]:
    if not rows:
        return None
    targets = {label.lower() for label in labels}
    for row in rows:
        value = _extract_value_from_row(row, targets)
        if value is not None:
            return value
    return None


def _extract_value_from_row(row: Dict[str, Any], targets: Set[str]) -> Optional[Decimal]:
    label_value = _value_from_coldata(row.get("ColData"), targets)
    if label_value is not None:
        return label_value
    summary = row.get("Summary")
    if summary:
        summary_value = _value_from_coldata(summary.get("ColData"), targets)
        if summary_value is not None:
            return summary_value
    nested_rows = row.get("Rows", {}).get("Row")
    if nested_rows:
        return _find_report_value(nested_rows, list(targets))
    return None


def _value_from_coldata(coldata: Optional[List[Dict[str, Any]]], targets: Set[str]) -> Optional[Decimal]:
    if not coldata or len(coldata) < 2:
        return None
    label = (coldata[0].get("value") or "").strip().lower()
    if label not in targets:
        return None
    raw_value = coldata[1].get("value") or "0"
    return _parse_decimal_value(raw_value)
