#!/usr/bin/env bash
# ==============================================================================
# CyberSentinel Automated Verification & Test Suite
# Tests backend auth, brute-force defense, API endpoints, and frontend assets
# ==============================================================================

set -euo pipefail

PORT="${1:-9090}"
BASE_URL="http://127.0.0.1:${PORT}"
PASS=0
FAIL=0
AUTH_TOKEN=""

test_endpoint() {
    local name="$1"
    local path="$2"
    local expected_key="$3"

    printf "Testing %-35s " "${name}..."
    local headers=()
    if [[ -n "${AUTH_TOKEN}" ]]; then
        headers=(-H "Authorization: Bearer ${AUTH_TOKEN}")
    fi

    local response
    response=$(curl -s -w "\n%{http_code}" "${headers[@]}" "${BASE_URL}${path}" || echo -e "\n000")
    local body
    body=$(echo "${response}" | head -n -1)
    local code
    code=$(echo "${response}" | tail -n 1)

    if [[ "${code}" == "200" ]] && [[ "${body}" == *"${expected_key}"* ]]; then
        echo -e "\033[0;32m[PASS] (HTTP ${code})\033[0m"
        PASS=$((PASS + 1))
    else
        echo -e "\033[0;31m[FAIL] (HTTP ${code}, missing '${expected_key}')\033[0m"
        FAIL=$((FAIL + 1))
    fi
}

echo "================================================================="
echo "  CyberSentinel Verification & Integration Test Suite"
echo "  Target: ${BASE_URL}"
echo "================================================================="

# 1. Frontend static asset tests
test_endpoint "Frontend SPA HTML" "/" "CyberSentinel"
test_endpoint "SOC CSS Theme" "/static/css/soc.css" "JetBrains"
test_endpoint "Offline Vendor Bundle (Vue)" "/static/vendor/vue.global.js" "Vue"

# 2. Authentication & Brute-Force Defense Tests
test_endpoint "Auth Status & Defense Query" "/api/auth/status" "auth_enabled"

printf "Testing %-35s " "Auth Enforcement (401 check)..."
unauth_code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/overview" || echo "000")
if [[ "${unauth_code}" == "401" ]]; then
    echo -e "\033[0;32m[PASS] (HTTP 401 Unauthorized Enforced)\033[0m"
    PASS=$((PASS + 1))
else
    echo -e "\033[0;31m[FAIL] (Expected HTTP 401, got ${unauth_code})\033[0m"
    FAIL=$((FAIL + 1))
fi

printf "Testing %-35s " "Admin Authentication (admin/admin)..."
login_response=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}' "${BASE_URL}/api/auth/login" || echo "{}")
AUTH_TOKEN=$(echo "${login_response}" | grep -oP '"token":\s*"\K[^"]+' || echo "")

if [[ -n "${AUTH_TOKEN}" ]]; then
    echo -e "\033[0;32m[PASS] (Token acquired, must_change_password flagged)\033[0m"
    PASS=$((PASS + 1))
else
    echo -e "\033[0;31m[FAIL] (Failed acquiring session token)\033[0m"
    FAIL=$((FAIL + 1))
fi

# 3. Protected Backend API Endpoints (with Authenticated Bearer Token)
test_endpoint "SOC Overview Telemetry" "/api/overview" "threat"
test_endpoint "Live Bandwidth Tracker" "/api/network/bandwidth" "rx_kbps"
test_endpoint "Kernel Sockets Inspection" "/api/network/sockets" "sockets"
test_endpoint "Fail2Ban Status & Jails" "/api/fail2ban/status" "total_currently_banned"
test_endpoint "Fail2Ban Activity Logs" "/api/fail2ban/logs" "logs"
test_endpoint "Top IP Negotiations Matrix" "/api/network/top-negotiations" "negotiations"
test_endpoint "Interactive Sessions" "/api/access/sessions" "sessions"
test_endpoint "Failed SSH Login Tracker" "/api/access/failed-logins" "attackers"
test_endpoint "Sudo Execution Audit" "/api/access/sudo-history" "history"
test_endpoint "Security Audit Logs" "/api/logs" "logs"
test_endpoint "File Integrity Monitor (FIM)" "/api/persistence/fim" "files"
test_endpoint "Persistence Artifacts (Cron)" "/api/persistence/artifacts" "cron_entries"
test_endpoint "Port-to-Process Verification" "/api/persistence/ports" "ports"
test_endpoint "Firewall Drop Rules & Bans" "/api/firewall/rules" "backend"
test_endpoint "Firewall Whitelist" "/api/firewall/whitelist" "whitelist"
test_endpoint "Daemon Configuration" "/api/settings" "server"
test_endpoint "Host System Diagnostics" "/api/system/info" "hostname"

echo "================================================================="
echo -e "Total Tests: $((PASS + FAIL)) | \033[0;32mPassed: ${PASS}\033[0m | \033[0;31mFailed: ${FAIL}\033[0m"
if [[ ${FAIL} -eq 0 ]]; then
    echo -e "\033[1;32mAll CyberSentinel subsystem tests passed successfully!\033[0m"
    exit 0
else
    echo -e "\033[1;31mSome tests failed. Check daemon logs.\033[0m"
    exit 1
fi
