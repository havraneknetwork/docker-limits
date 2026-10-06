"""
Configuration module for Docker Limits Manager.
Loads configuration from environment variables (.env).
"""

import os
import secrets
import logging

logger = logging.getLogger("limits")

# ── API Key Configuration ───────────────────────────────────────────────
def get_api_key() -> str:
    """Resolve API key from LIMITS_API_KEY env or secret file."""
    key = os.environ.get("LIMITS_API_KEY")
    if key and key.strip():
        logger.info("API key loaded from environment variable")
        return key.strip()

    secret_file = os.environ.get("LIMITS_API_KEY_FILE", "/run/secrets/api_key")
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r") as f:
                file_key = f.read().strip()
            if file_key:
                logger.info("API key loaded from secret file: %s", secret_file)
                return file_key
        except OSError as e:
            logger.warning("Failed to read secret file %s: %s", secret_file, e)

    ephemeral = secrets.token_urlsafe(32)
    logger.warning("No API key configured. Generated ephemeral key: %s", ephemeral)
    return ephemeral

API_KEY = get_api_key()

# ── Admin User Authentication (Username + Password) ──────────────────────
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# ── Session & Security Settings ──────────────────────────────────────────
def get_session_secret_key() -> str:
    """Resolve session secret key from env, secret file, or generate secure ephemeral."""
    secret = os.environ.get("SESSION_SECRET_KEY")
    if secret and secret.strip():
        return secret.strip()

    secret_file = os.environ.get("SESSION_SECRET_KEY_FILE", "/run/secrets/session_secret")
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r") as f:
                file_secret = f.read().strip()
            if file_secret:
                return file_secret
        except OSError as e:
            logger.warning("Failed to read session secret file %s: %s", secret_file, e)

    ephemeral = secrets.token_hex(32)
    logger.warning("No SESSION_SECRET_KEY configured. Generated ephemeral secret.")
    return ephemeral

SESSION_SECRET_KEY = get_session_secret_key()
SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "limits_session")
SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", "72"))  # 3 days

# Allowed Host Root for docker-compose files sync
ALLOWED_HOST_ROOT = os.environ.get("ALLOWED_HOST_ROOT", "/").strip()

# Brute-force & Account Lockout
MAX_FAILED_LOGIN_ATTEMPTS = int(os.environ.get("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
ACCOUNT_LOCKOUT_MINUTES = int(os.environ.get("ACCOUNT_LOCKOUT_MINUTES", "15"))
IP_RATE_LIMIT_ATTEMPTS = int(os.environ.get("IP_RATE_LIMIT_ATTEMPTS", "10"))
IP_RATE_LIMIT_MINUTES = int(os.environ.get("IP_RATE_LIMIT_MINUTES", "15"))

# Manageable container label key
MANAGEABLE_LABEL = os.environ.get("MANAGEABLE_LABEL", "app.manageable")
MANAGEABLE_LABEL_VALUE = "true"

# Minimum memory in MB (Docker requires at least 6MB)
MIN_MEMORY_MB = 6

# Maximum CPU cores (sanity limit)
MAX_CPU_CORES = 128.0

# Application port
APP_PORT = int(os.environ.get("LIMITS_PORT", "8000"))
