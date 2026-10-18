"""REST API Endpoints for CyberSentinel Security Daemon."""
import os
import logging
import platform
from typing import Optional, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, Request, HTTPException, status

from backend.app.core.config import settings
from backend.app.core.security import (
    verify_auth_token,
    get_client_ip,
    check_rate_limit,
    dispatch_alert,
    login_limiter,
    verify_password,
    create_session,
    revoke_session,
)
from backend.app.modules.network import (
    bandwidth_tracker,
    get_active_sockets,
    get_top_ip_negotiations,
)
from backend.app.modules.fail2ban import (
    get_fail2ban_status,
    unban_ip_fail2ban,
    ban_ip_fail2ban,
    get_fail2ban_logs,
)
from backend.app.modules.firewall import firewall_manager
from backend.app.modules.access import get_active_sessions, kill_session, get_failed_logins, get_sudo_history
from backend.app.modules.persistence import fim_monitor, get_persistence_artifacts, verify_listening_ports
from backend.app.modules.logs import query_logs
from backend.app.modules.telemetry import get_full_overview

logger = logging.getLogger("cybersentinel.api")

# Protected API Router (enforces verify_auth_token when auth_enabled is True)
router = APIRouter(prefix="/api", dependencies=[Depends(verify_auth_token)])

# Public Authentication Router (login, logout, status, password-change)
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


# ==========================================
# Authentication & Pydantic Request Models
# ==========================================
class LoginRequest(BaseModel):
    username: str = Field(..., description="Administrator username")
    password: str = Field(..., description="Administrator password")


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., description="Current administrator password")
    new_password: str = Field(..., min_length=6, description="New administrator password (min 6 chars)")


# ==========================================
# Authentication Endpoints
# ==========================================
@auth_router.get("/status")
def get_auth_status(request: Request):
    """Returns current authentication requirements and brute-force lockout status for client IP."""
    client_ip = get_client_ip(request)
    limiter_status = login_limiter.get_status(client_ip)
    return {
        "auth_enabled": settings.auth_enabled,
        "must_change_password": settings.must_change_password,
        "username": settings.admin_username,
        "client_ip": client_ip,
        "locked": limiter_status["locked"],
        "retry_after": limiter_status["retry_after"],
        "remaining_attempts": limiter_status["remaining_attempts"],
    }


@auth_router.post("/login")
def auth_login(req: LoginRequest, request: Request):
    """
    Operator login endpoint protected by anti-brute-force rate limiting.
    Locks out repeated attackers with progressive cooldowns.
    """
    client_ip = get_client_ip(request)

    # 1. Check if IP is currently in brute-force lockout
    is_locked, remaining_seconds = login_limiter.is_locked(client_ip)
    if is_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. IP temporarily locked out for {remaining_seconds}s.",
            headers={"Retry-After": str(remaining_seconds)},
        )

    # 2. Verify credentials
    user_ok = req.username == settings.admin_username
    pass_ok = verify_password(req.password, settings.admin_password_hash, settings.admin_password_salt)

    if not (user_ok and pass_ok):
        is_locked_now, lockout_duration, remaining_attempts = login_limiter.record_failure(client_ip, req.username)
        if is_locked_now:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Exceeded maximum failed attempts. IP temporarily locked out for {lockout_duration}s.",
                headers={"Retry-After": str(lockout_duration)},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid username or password. {remaining_attempts} attempt(s) remaining before temporary lockout.",
        )

    # 3. Successful authentication: clear failure counters & issue session
    login_limiter.record_success(client_ip)
    token = create_session(settings.admin_username)
    logger.info(f"[AUTH] User '{settings.admin_username}' logged in successfully from {client_ip}")

    return {
        "success": True,
        "token": token,
        "username": settings.admin_username,
        "must_change_password": settings.must_change_password,
    }


@auth_router.post("/change-password")
def auth_change_password(req: ChangePasswordRequest, request: Request):
    """
    Mandatory password change upon initial login or manual operator update.
    Validates current password and updates hash with fresh salt.
    """
    client_ip = get_client_ip(request)

    # Check lockout
    is_locked, remaining_seconds = login_limiter.is_locked(client_ip)
    if is_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"IP temporarily locked out. Try again in {remaining_seconds}s.",
        )

    # Verify current password
    if not verify_password(req.current_password, settings.admin_password_hash, settings.admin_password_salt):
        login_limiter.record_failure(client_ip, "password-change")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    # Validate new password
    if len(req.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 6 characters long.",
        )
    if req.new_password.lower() == "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be 'admin'. Please choose a stronger password.",
        )
    if req.new_password == req.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be the same as the current password.",
        )

    # Apply new password
    settings.set_admin_password(req.new_password)
    login_limiter.record_success(client_ip)
    new_token = create_session(settings.admin_username)

    logger.info(f"[AUTH] Administrator password updated successfully by operator from {client_ip}")

    return {
        "success": True,
        "token": new_token,
        "message": "Administrator password successfully updated. SOC panel secured.",
    }


@auth_router.post("/logout")
def auth_logout(request: Request):
    """Invalidates active session token."""
    token = None
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif "token" in request.query_params:
        token = request.query_params.get("token")

    if token:
        revoke_session(token)
    return {"success": True}
class BlockIPRequest(BaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to drop")
    duration: int = Field(0, description="Duration in seconds (0 = permanent, 3600 = 1h, 86400 = 24h)")
    reason: str = Field("Manual SOC Operator Block", description="Audit reason for ban")
    force: bool = Field(False, description="Override whitelist safety check if True")


class UnblockIPRequest(BaseModel):
    ip: str = Field(..., description="IP address to remove from drop list")


class Fail2BanUnbanRequest(BaseModel):
    ip: str = Field(..., description="IP address to unban from Fail2Ban")
    jail: Optional[str] = Field(None, description="Specific jail name or None to unban from all jails")


class Fail2BanBanRequest(BaseModel):
    ip: str = Field(..., description="IP address to ban in Fail2Ban")
    jail: str = Field("sshd-aggressive", description="Target jail name (e.g. sshd, sshd-aggressive, sshd-banned)")


class KillSessionRequest(BaseModel):
    session_id: str = Field(..., description="Session ID from loginctl or TTY")
    tty: Optional[str] = Field(None, description="TTY name e.g. pts/0")


class FimUpdateBaselineRequest(BaseModel):
    reason: str = Field("Admin approved baseline update", description="Reason for baseline update")


class WhitelistItemRequest(BaseModel):
    ip_or_cidr: str = Field(..., description="IP or CIDR network to add/remove")


class SettingsUpdateRequest(BaseModel):
    auth_enabled: Optional[bool] = None
    admin_token: Optional[str] = None
    failed_logins_threshold_1h: Optional[int] = None
    bandwidth_spike_mbps: Optional[int] = None
    threat_score_high: Optional[int] = None
    notifications_enabled: Optional[bool] = None
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    generic_webhook_url: Optional[str] = None
    test_webhook: Optional[bool] = False


# ==========================================
# 1. Dashboard Overview
# ==========================================
@router.get("/overview")
def get_overview():
    """Consolidated SOC summary: threat level score, sparklines, stats."""
    return get_full_overview()


# ==========================================
# 2. Network & Connections
# ==========================================
@router.get("/network/bandwidth")
def get_bandwidth():
    """Real-time RX/TX bandwidth metrics and historical sparklines."""
    return bandwidth_tracker.get_bandwidth()


@router.get("/network/sockets")
def get_sockets(
    proto: Optional[str] = None,
    state: Optional[str] = None,
    direction: Optional[str] = None,
    search: Optional[str] = None,
):
    """Filterable real-time active sockets table."""
    return get_active_sockets(
        filter_proto=proto,
        filter_state=state,
        filter_direction=direction,
        search=search,
    )


# ==========================================
# Fail2Ban Jails & Defense Matrix
# ==========================================
@router.get("/fail2ban/status")
def get_fail2ban_status_endpoint():
    """Current Fail2Ban server status, active jails, ban counts, and sample banned IPs."""
    return get_fail2ban_status()


@router.post("/fail2ban/unban")
def unban_fail2ban_endpoint(req: Fail2BanUnbanRequest, request: Request):
    """Unban an IP from one or all active Fail2Ban jails."""
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip, "f2b_unban", limit=30, window=60):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")
    res = unban_ip_fail2ban(req.ip, req.jail)
    if not res.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.get("error", "Failed to unban"))
    dispatch_alert(
        title="Fail2Ban IP Unbanned",
        message=f"IP `{req.ip}` unbanned from Fail2Ban ({req.jail or 'all jails'}) by operator@{client_ip}",
        severity="INFO"
    )
    return res


@router.post("/fail2ban/ban")
def ban_fail2ban_endpoint(req: Fail2BanBanRequest, request: Request):
    """Ban an IP in a specific Fail2Ban jail."""
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip, "f2b_ban", limit=30, window=60):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")
    if req.ip == client_ip:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refusing to ban current client IP in Fail2Ban!")
    res = ban_ip_fail2ban(req.ip, req.jail)
    if not res.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.get("error", "Failed to ban"))
    dispatch_alert(
        title="Fail2Ban IP Banned",
        message=f"IP `{req.ip}` manually banned in jail `{req.jail}` by operator@{client_ip}",
        severity="WARNING"
    )
    return res


@router.get("/fail2ban/logs")
def get_fail2ban_logs_endpoint(limit: int = 100):
    """Recent Fail2Ban action events (Ban, Unban, Found) from /var/log/fail2ban.log."""
    return {"logs": get_fail2ban_logs(limit=min(500, max(1, limit)))}


@router.get("/network/top-negotiations")
def get_top_negotiations_endpoint(limit: int = 25):
    """Top remote IPs negotiating network handshakes and active socket flows."""
    return {"negotiations": get_top_ip_negotiations(limit=min(100, max(1, limit)))}


@router.post("/network/block")
def block_ip_endpoint(req: BlockIPRequest, request: Request):
    """Instant IP blocking integration at kernel level."""
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip, "block_ip", limit=30, window=60):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded for firewall actions.")

    # Prevent operator locking themselves out
    if req.ip == client_ip and not req.force:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Refusing to ban {req.ip}: this matches your current client IP! Pass force=True if strictly intended.",
        )

    res = firewall_manager.block_ip(
        ip_str=req.ip,
        duration_seconds=req.duration,
        reason=req.reason,
        actor=f"operator@{client_ip}",
        force=req.force,
    )
    if not res.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.get("error"))

    dispatch_alert(
        title="Firewall Ban Applied",
        message=f"IP `{req.ip}` banned by operator for {req.duration}s. Reason: {req.reason}",
        severity="warning",
    )
    return res


# ==========================================
# 3. Identity & Access (SSH & Users)
# ==========================================
@router.get("/access/sessions")
def get_sessions():
    """Active interactive sessions with user, TTY, remote IP, and command."""
    return {"sessions": get_active_sessions()}


@router.post("/access/kill-session")
def kill_session_endpoint(req: KillSessionRequest, request: Request):
    """Safely terminates an active login session via loginctl or pkill."""
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip, "kill_session", limit=20, window=60):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded for kill session actions.")

    res = kill_session(session_id=req.session_id, tty=req.tty)
    if not res.get("success"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to terminate session {req.session_id} (methods tried: {res.get('methods_tried')})",
        )

    dispatch_alert(
        title="Active Session Terminated",
        message=f"Session ID `{req.session_id}` (TTY: `{req.tty}`) terminated by operator@{client_ip}",
        severity="critical",
    )
    return res


@router.get("/access/failed-logins")
def get_failed_logins_endpoint(limit: int = 100):
    """Failed login tracker with brute-force attempts and GeoIP."""
    return get_failed_logins(max_entries=limit)


@router.get("/access/sudo-history")
def get_sudo_history_endpoint(limit: int = 100):
    """Sudo command execution audit history."""
    return {"history": get_sudo_history(max_entries=limit)}


# ==========================================
# 4. Security Logs & Audit
# ==========================================
@router.get("/logs")
def get_logs(
    limit: int = 100,
    search: Optional[str] = None,
    regex: Optional[str] = None,
    facility: Optional[str] = None,
    severity: Optional[str] = None,
):
    """Filterable log stream with regex, facility, and severity filters."""
    return query_logs(
        limit=min(500, max(1, limit)),
        search=search,
        regex_pattern=regex,
        facility=facility,
        severity=severity,
    )


# ==========================================
# 5. System & Persistence Audit
# ==========================================
@router.get("/persistence/fim")
def get_fim_status():
    """File Integrity Monitor (FIM) baseline verification."""
    return fim_monitor.verify_integrity()


@router.post("/persistence/fim/update-baseline")
def update_fim_baseline(req: FimUpdateBaselineRequest):
    """Updates the trusted FIM baseline with current filesystem state."""
    new_baseline = fim_monitor.create_baseline(reason=req.reason)
    return {"success": True, "files_indexed": len(new_baseline.get("files", {}))}


@router.get("/persistence/artifacts")
def get_persistence():
    """Cron jobs, systemd timers, and custom service persistence scanner."""
    return get_persistence_artifacts()


@router.get("/persistence/ports")
def get_listening_ports():
    """Cross-references listening ports with binaries, flagging deleted executables or rogue paths."""
    return {"ports": verify_listening_ports()}


# ==========================================
# 6. Firewall & Blocklist Management
# ==========================================
@router.get("/firewall/rules")
def get_firewall_rules():
    """Lists currently banned IPs from CyberSentinel set and underlying system firewall."""
    return firewall_manager.list_bans()


@router.post("/firewall/ban")
def ban_ip_rule(req: BlockIPRequest, request: Request):
    """Manual ban form with expiration timers."""
    return block_ip_endpoint(req, request)


@router.post("/firewall/unban")
def unban_ip_rule(req: UnblockIPRequest):
    """Removes an active block rule from the firewall."""
    res = firewall_manager.unblock_ip(req.ip)
    if not res.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=res.get("error"))
    return res


@router.get("/firewall/whitelist")
def get_whitelist():
    """Lists whitelisted IPs/CIDRs."""
    return {"whitelist": firewall_manager.get_whitelist()}


@router.post("/firewall/whitelist/add")
def add_whitelist(req: WhitelistItemRequest):
    """Adds an IP or CIDR to the whitelist."""
    return firewall_manager.add_to_whitelist(req.ip_or_cidr)


@router.post("/firewall/whitelist/remove")
def remove_whitelist(req: WhitelistItemRequest):
    """Removes an IP or CIDR from the whitelist."""
    return firewall_manager.remove_from_whitelist(req.ip_or_cidr)


# ==========================================
# 7. Settings & Agent Config
# ==========================================
@router.get("/settings")
def get_settings():
    """Returns runtime settings (redacting secret keys)."""
    cfg = settings.data
    notifications = cfg.get("notifications", {})
    return {
        "server": {
            "host": settings.host,
            "port": settings.port,
            "auth_enabled": settings.auth_enabled,
            "admin_username": settings.admin_username,
            "must_change_password": settings.must_change_password,
            "admin_token_set": bool(settings.admin_token),
        },
        "alerts": cfg.get("alerts", {}),
        "notifications": {
            "enabled": notifications.get("enabled", False),
            "discord_webhook_url": notifications.get("discord_webhook_url", ""),
            "telegram_bot_token": "***" if notifications.get("telegram_bot_token") else "",
            "telegram_chat_id": notifications.get("telegram_chat_id", ""),
            "generic_webhook_url": notifications.get("generic_webhook_url", ""),
        },
        "firewall_backend": firewall_manager.backend,
        "fim_monitored_paths": settings.fim_paths,
    }


@router.post("/settings")
def update_settings(req: SettingsUpdateRequest):
    """Updates runtime configuration and sends test alert if requested."""
    updates: dict = {}
    if req.auth_enabled is not None:
        updates.setdefault("server", {})["auth_enabled"] = req.auth_enabled
    if req.admin_token:
        updates.setdefault("server", {})["admin_token"] = req.admin_token

    alerts_updates = {}
    if req.failed_logins_threshold_1h is not None:
        alerts_updates["failed_logins_threshold_1h"] = req.failed_logins_threshold_1h
    if req.bandwidth_spike_mbps is not None:
        alerts_updates["bandwidth_spike_mbps"] = req.bandwidth_spike_mbps
    if req.threat_score_high is not None:
        alerts_updates["threat_score_high"] = req.threat_score_high
    if alerts_updates:
        updates["alerts"] = alerts_updates

    notif_updates = {}
    if req.notifications_enabled is not None:
        notif_updates["enabled"] = req.notifications_enabled
    if req.discord_webhook_url is not None:
        notif_updates["discord_webhook_url"] = req.discord_webhook_url
    if req.telegram_bot_token and req.telegram_bot_token != "***":
        notif_updates["telegram_bot_token"] = req.telegram_bot_token
    if req.telegram_chat_id is not None:
        notif_updates["telegram_chat_id"] = req.telegram_chat_id
    if req.generic_webhook_url is not None:
        notif_updates["generic_webhook_url"] = req.generic_webhook_url
    if notif_updates:
        updates["notifications"] = notif_updates

    settings.update(updates)

    test_sent = False
    if req.test_webhook:
        test_sent = dispatch_alert(
            title="Test Webhook Notification",
            message="CyberSentinel security alert integration is active and operating normally.",
            severity="info",
        )

    return {"success": True, "test_sent": test_sent}


# ==========================================
# 8. Host System Diagnostics
# ==========================================
@router.get("/system/info")
def get_system_info():
    """Host operating system, kernel, CPU model, and daemon runtime."""
    uname = platform.uname()
    distro = "Linux"
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        distro = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass

    return {
        "hostname": uname.node,
        "os_distro": distro,
        "kernel": uname.release,
        "arch": uname.machine,
        "python_version": platform.python_version(),
        "firewall_backend": firewall_manager.backend,
    }
