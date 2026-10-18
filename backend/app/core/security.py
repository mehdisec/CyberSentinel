"""Security primitives, authentication verification, brute-force protection, and alert dispatchers."""
import ipaddress
import logging
import time
import secrets
import hashlib
import hmac
from typing import Optional, List, Dict
import requests
from fastapi import Request, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from backend.app.core.config import settings

logger = logging.getLogger("cybersentinel.security")
bearer_scheme = HTTPBearer(auto_error=False)

# In-memory rate limiting tracker: action_type -> {ip: [timestamps]}
_ACTION_RATE_LIMITS: Dict[str, Dict[str, List[float]]] = {}

# Active authenticated sessions: token -> {"username": str, "created_at": float, "expires_at": float}
_ACTIVE_SESSIONS: Dict[str, Dict[str, float]] = {}
SESSION_EXPIRATION_SECONDS = 7 * 86400  # 7 days


# ==========================================
# Password Cryptography & Verification
# ==========================================
def hash_password(password: str, salt: Optional[str] = None) -> tuple:
    """Generate PBKDF2-HMAC-SHA256 password hash and salt (100,000 iterations)."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return hashed, salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Constant-time verification of password against stored hash."""
    if not hashed or not salt:
        return False
    check, _ = hash_password(password, salt)
    return hmac.compare_digest(check, hashed)


# ==========================================
# Session Management
# ==========================================
def create_session(username: str) -> str:
    """Issues a cryptographically secure session token."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    _ACTIVE_SESSIONS[token] = {
        "username": username,
        "created_at": now,
        "expires_at": now + SESSION_EXPIRATION_SECONDS,
    }
    return token


def revoke_session(token: str) -> bool:
    """Invalidates an active session token."""
    return _ACTIVE_SESSIONS.pop(token, None) is not None


def is_valid_session(token: str) -> bool:
    """Checks if a session token is active and not expired."""
    session = _ACTIVE_SESSIONS.get(token)
    if not session:
        return False
    if session["expires_at"] < time.time():
        _ACTIVE_SESSIONS.pop(token, None)
        return False
    return True


# ==========================================
# Brute-Force Login Rate Limiter
# ==========================================
class LoginRateLimiter:
    """
    Stateful sliding-window rate limiter protecting login windows from brute-force attacks.
    Locks out offensive IPs for progressive durations after repeated failed attempts.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300, initial_lockout: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.initial_lockout = initial_lockout
        self._lockouts: Dict[str, Dict[str, float]] = {}  # ip -> {"locked_until": float, "count": int}
        self._attempts: Dict[str, List[float]] = {}       # ip -> [timestamps]

    def is_locked(self, ip: str) -> tuple:
        """Returns (is_locked, remaining_seconds)."""
        now = time.time()
        record = self._lockouts.get(ip)
        if record and record["locked_until"] > now:
            remaining = int(record["locked_until"] - now)
            return True, max(1, remaining)
        return False, 0

    def record_failure(self, ip: str, username: str = "admin") -> tuple:
        """
        Records a failed authentication attempt.
        Returns (is_locked, remaining_lockout_seconds, remaining_attempts_before_lockout).
        """
        now = time.time()
        is_locked, remaining = self.is_locked(ip)
        if is_locked:
            return True, remaining, 0

        attempts = self._attempts.setdefault(ip, [])
        # Prune old attempts outside the window
        self._attempts[ip] = [ts for ts in attempts if now - ts < self.window_seconds]
        self._attempts[ip].append(now)

        current_count = len(self._attempts[ip])
        if current_count >= self.max_attempts:
            # Trigger lockout with progressive multiplier
            prev_lockouts = int(self._lockouts.get(ip, {}).get("count", 0))
            lockout_duration = self.initial_lockout * (2 ** min(prev_lockouts, 3))
            locked_until = now + lockout_duration
            self._lockouts[ip] = {"locked_until": locked_until, "count": prev_lockouts + 1}
            self._attempts[ip] = []  # Reset attempts window upon lockout
            logger.warning(
                f"[BRUTE-FORCE] Client IP {ip} triggered login lockout for {lockout_duration}s "
                f"after {current_count} failed attempts on user '{username}'"
            )
            return True, lockout_duration, 0

        remaining_attempts = self.max_attempts - current_count
        logger.warning(
            f"[AUTH] Failed login attempt from {ip} on user '{username}'. "
            f"{remaining_attempts} attempt(s) remaining before temporary lockout."
        )
        return False, 0, remaining_attempts

    def record_success(self, ip: str):
        """Clears failed attempts and lockouts upon successful authentication."""
        self._attempts.pop(ip, None)
        self._lockouts.pop(ip, None)

    def get_status(self, ip: str) -> dict:
        """Returns current lockout status and remaining attempts for client IP."""
        is_locked, remaining = self.is_locked(ip)
        now = time.time()
        attempts = [ts for ts in self._attempts.get(ip, []) if now - ts < self.window_seconds]
        return {
            "locked": is_locked,
            "retry_after": remaining,
            "failed_attempts": len(attempts),
            "max_attempts": self.max_attempts,
            "remaining_attempts": max(0, self.max_attempts - len(attempts)) if not is_locked else 0,
        }


# Global login brute force rate limiter singleton (5 failures in 5 min -> 5 min lockout)
login_limiter = LoginRateLimiter(max_attempts=5, window_seconds=300, initial_lockout=300)


# ==========================================
# Network & IP Utilities
# ==========================================
def get_client_ip(request: Request) -> str:
    """Extract real client IP considering reverse proxy headers safely."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
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


# ==========================================
# FastAPI Auth Dependency
# ==========================================
def verify_auth_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)
) -> bool:
    """
    FastAPI dependency for dashboard authentication.
    If auth_enabled is False, passes transparently.
    Otherwise checks Bearer session token, query param 'token', or 'x-api-key'.
    """
    if not settings.auth_enabled:
        return True

    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif "token" in request.query_params:
        token = request.query_params.get("token")
    elif "x-api-key" in request.headers:
        token = request.headers.get("x-api-key")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate against active session tokens or static admin_token
    if is_valid_session(token) or (settings.admin_token and token == settings.admin_token):
        return True

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired session token",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ==========================================
# Action Rate Limiter (Sensitive Actions)
# ==========================================
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


# ==========================================
# Security Alert Dispatcher
# ==========================================
def dispatch_alert(title: str, message: str, severity: str = "warning") -> bool:
    """
    Dispatch security alert notification to configured webhooks (Discord / Telegram / Generic).
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
                    "footer": {"text": "CyberSentinel Linux Defense Daemon"},
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
