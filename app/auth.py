"""
Authentication and security module.
Supports:
1. Web Session Cookie authentication (username + password, rate limiting, lockout).
2. X-API-Key header authentication (for automated scripts/curl).
"""

import hmac
import hashlib
import base64
import json
import time
import secrets
import logging
from typing import Optional, Tuple
from fastapi import Request, HTTPException, status, Security
from fastapi.security import APIKeyHeader

from .config import (
    API_KEY,
    ADMIN_USERNAME,
    ADMIN_PASSWORD,
    SESSION_SECRET_KEY,
    SESSION_COOKIE_NAME,
    SESSION_LIFETIME_HOURS,
    MAX_FAILED_LOGIN_ATTEMPTS,
    ACCOUNT_LOCKOUT_MINUTES,
    IP_RATE_LIMIT_ATTEMPTS,
    IP_RATE_LIMIT_MINUTES,
)

logger = logging.getLogger("limits.auth")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── In-Memory Security Tracking (Rate limiting & Account Lockout) ──────────
# { ip: [timestamp, timestamp, ...] }
_ip_attempts = {}
# { "failed_attempts": int, "locked_until": float }
_account_state = {
    "failed_attempts": 0,
    "locked_until": 0.0,
}


def _clean_old_ip_attempts(now: float) -> None:
    cutoff = now - (IP_RATE_LIMIT_MINUTES * 60)
    for ip in list(_ip_attempts.keys()):
        _ip_attempts[ip] = [ts for ts in _ip_attempts[ip] if ts > cutoff]
        if not _ip_attempts[ip]:
            del _ip_attempts[ip]


def is_ip_rate_limited(ip: str) -> bool:
    now = time.time()
    _clean_old_ip_attempts(now)
    attempts = _ip_attempts.get(ip, [])
    return len(attempts) >= IP_RATE_LIMIT_ATTEMPTS


def record_ip_attempt(ip: str) -> None:
    now = time.time()
    _clean_old_ip_attempts(now)
    if ip not in _ip_attempts:
        _ip_attempts[ip] = []
    _ip_attempts[ip].append(now)


def is_account_locked() -> Tuple[bool, int]:
    now = time.time()
    locked_until = _account_state.get("locked_until", 0.0)
    if locked_until > now:
        remaining_minutes = max(1, int((locked_until - now) / 60))
        return True, remaining_minutes
    return False, 0


def record_failed_login(ip: str) -> None:
    record_ip_attempt(ip)
    now = time.time()
    _account_state["failed_attempts"] += 1
    if _account_state["failed_attempts"] >= MAX_FAILED_LOGIN_ATTEMPTS:
        _account_state["locked_until"] = now + (ACCOUNT_LOCKOUT_MINUTES * 60)
        logger.warning(
            "Admin account locked for %d minutes due to %d failed attempts from IP %s",
            ACCOUNT_LOCKOUT_MINUTES,
            _account_state["failed_attempts"],
            ip,
        )


def record_successful_login() -> None:
    _account_state["failed_attempts"] = 0
    _account_state["locked_until"] = 0.0


# ── Session Token Cryptography (Signed JSON with HMAC-SHA256) ─────────────
def create_session_token(username: str) -> str:
    """Create a tamper-proof signed session token."""
    now = int(time.time())
    exp = now + (SESSION_LIFETIME_HOURS * 3600)
    payload = {
        "sub": username,
        "iat": now,
        "exp": exp,
        "nonce": secrets.token_hex(8),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    signature = hmac.new(
        SESSION_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{payload_b64}.{sig_b64}"


def verify_session_token(token: str) -> Optional[dict]:
    """Verify session token signature and expiration in constant time."""
    if not token or "." not in token:
        return None
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        expected_sig = hmac.new(
            SESSION_SECRET_KEY.encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        # Add padding back if necessary
        pad = len(sig_b64) % 4
        sig_raw = base64.urlsafe_b64decode(sig_b64 + ("=" * (4 - pad) if pad else ""))
        if not hmac.compare_digest(expected_sig, sig_raw):
            return None

        pad_p = len(payload_b64) % 4
        payload_json = base64.urlsafe_b64decode(payload_b64 + ("=" * (4 - pad_p) if pad_p else "")).decode("utf-8")
        payload = json.loads(payload_json)

        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception as e:
        logger.debug("Failed to verify session token: %s", e)
        return None


# ── Password Verification (Constant Time) ─────────────────────────────────
def verify_credentials(username: str, password: str, client_ip: str) -> Tuple[bool, str]:
    """
    Authenticate username and password with:
    - IP Rate Limiting
    - Account Lockout
    - Constant-time string comparison against .env credentials
    """
    if is_ip_rate_limited(client_ip):
        return False, f"Příliš mnoho neúspěšných pokusů. Počkejte prosím {IP_RATE_LIMIT_MINUTES} minut."

    locked, rem_min = is_account_locked()
    if locked:
        return False, f"Účet je dočasně uzamčen. Zkuste to prosím za {rem_min} min."

    # Do not allow login if password is not configured in environment
    if not ADMIN_PASSWORD:
        logger.error("ADMIN_PASSWORD is not set in environment. Login disabled.")
        return False, "Přihlášení není nakonfigurováno na serveru (chybí ADMIN_PASSWORD)."

    # Constant time comparisons to avoid timing attacks
    user_ok = secrets.compare_digest(username.strip(), ADMIN_USERNAME)
    pass_ok = secrets.compare_digest(password, ADMIN_PASSWORD)

    if user_ok and pass_ok:
        record_successful_login()
        return True, ""
    else:
        record_failed_login(client_ip)
        return False, "Neplatné uživatelské jméno nebo heslo."


# ── Dependency: Auth Check (Session Cookie or X-API-Key) ───────────────────
def get_client_ip(request: Request) -> str:
    """Extract client IP respecting X-Forwarded-For if set by Traefik."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


async def verify_auth(
    request: Request,
    api_key: Optional[str] = Security(api_key_header),
) -> str:
    """
    Unified authentication dependency.
    Accepts either:
    1. Valid session cookie (from web login)
    2. Valid X-API-Key header (from automation/curl)
    """
    # 1. Check Session Cookie
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        payload = verify_session_token(cookie_token)
        if payload and payload.get("sub"):
            return payload["sub"]

    # 2. Check X-API-Key Header
    if api_key:
        if secrets.compare_digest(api_key, API_KEY):
            return "api-user"
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid API key",
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Přihlaste se prosím nebo zadejte platný API klíč.",
    )
