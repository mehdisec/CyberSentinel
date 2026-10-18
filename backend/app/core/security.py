"""Security primitives, authentication verification, and alert dispatchers."""
import ipaddress
import logging
import time
from typing import Optional, List, Dict
import requests
from fastapi import Request, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from backend.app.core.config import settings

logger = logging.getLogger("cybersentinel.security")
bearer_scheme = HTTPBearer(auto_error=False)

# In-memory rate limiting tracker: action_type -> {ip: [timestamps]}
_ACTION_RATE_LIMITS: Dict[str, Dict[str, List[float]]] = {}


def get_client_ip(request: Request) -> str:
    """Extract real client IP considering reverse proxy headers safely."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # First IP in comma-separated list is client
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"


def is_ip_whitelisted(ip_str: str, custom_whitelist: Optional[List[str]] = None) -> bool:
    """
    Check if an IP is in the local/administrative whitelist.
    Prevents self-lockout of operator, loopback, or private infrastructure.
    """
    try:
        target_ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    whitelist = custom_whitelist if custom_whitelist is not None else settings.whitelist
    for item in whitelist:
        try:
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
                if target_ip in net:
                    return True
            else:
                allowed_ip = ipaddress.ip_address(item)
                if target_ip == allowed_ip:
                    return True
        except ValueError:
            continue
    return False


def verify_auth_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)
) -> bool:
    """
    FastAPI dependency for dashboard authentication.
    If auth_enabled is False, passes transparently.
    Otherwise checks Bearer token or 'token' query param against configured secret.
    """
    if not settings.auth_enabled:
        return True

    expected = settings.admin_token
    token = None

    if credentials:
        token = credentials.credentials
    elif "token" in request.query_params:
        token = request.query_params.get("token")
    elif "x-api-key" in request.headers:
        token = request.headers.get("x-api-key")

    if not token or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


def check_rate_limit(client_ip: str, action: str = "critical_action", limit: int = 30, window: int = 60) -> bool:
    """
    Simple sliding-window rate limiter for sensitive actions (e.g. kill session, ban IP).
    Returns True if allowed, False if exceeded.
    """
    now = time.time()
    if action not in _ACTION_RATE_LIMITS:
        _ACTION_RATE_LIMITS[action] = {}

    client_history = _ACTION_RATE_LIMITS[action].setdefault(client_ip, [])
    # Prune old timestamps
    _ACTION_RATE_LIMITS[action][client_ip] = [ts for ts in client_history if now - ts < window]

    if len(_ACTION_RATE_LIMITS[action][client_ip]) >= limit:
        return False

    _ACTION_RATE_LIMITS[action][client_ip].append(now)
    return True


def dispatch_alert(title: str, message: str, severity: str = "warning") -> bool:
    """
    Dispatch security alert notification to configured webhooks (Discord / Telegram / Generic).
    Runs synchronously or in executor.
    """
    notifications = settings.get("notifications", {})
    if not notifications.get("enabled", False):
        return False

    success = False

    # 1. Discord Webhook
    discord_url = notifications.get("discord_webhook_url")
    if discord_url:
        color = 0xef4444 if severity == "critical" else (0xf59e0b if severity == "warning" else 0x3b82f6)
        payload = {
            "embeds": [
                {
                    "title": f"🛡️ CyberSentinel Alert: {title}",
                    "description": message,
                    "color": color,
                    "footer": {"text": "Aegis Linux Cybersecurity Daemon"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            ]
        }
        try:
            r = requests.post(discord_url, json=payload, timeout=4)
            if r.status_code in (200, 204):
                success = True
        except Exception as e:
            logger.error(f"Failed to deliver Discord alert: {e}")

    # 2. Telegram Bot
    tg_token = notifications.get("telegram_bot_token")
    tg_chat_id = notifications.get("telegram_chat_id")
    if tg_token and tg_chat_id:
        tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
        text = f"🛡️ *CyberSentinel Alert: {title}*\n\n{message}\n\n*Severity:* `{severity.upper()}`"
        try:
            r = requests.post(tg_url, json={"chat_id": tg_chat_id, "text": text, "parse_mode": "Markdown"}, timeout=4)
            if r.status_code == 200:
                success = True
        except Exception as e:
            logger.error(f"Failed to deliver Telegram alert: {e}")

    # 3. Generic Webhook
    generic_url = notifications.get("generic_webhook_url")
    if generic_url:
        generic_payload = {
            "alert": title,
            "message": message,
            "severity": severity,
            "timestamp": time.time(),
        }
        try:
            r = requests.post(generic_url, json=generic_payload, timeout=4)
            if r.status_code < 400:
                success = True
        except Exception as e:
            logger.error(f"Failed to deliver Generic webhook alert: {e}")

    return success
