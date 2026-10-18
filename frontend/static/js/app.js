// app.js - CyberSentinel Main Reactive Application & Security Guard
const { createApp, ref, reactive, computed, onMounted, nextTick } = Vue;

const app = createApp({
  components: {
    OverviewView,
    NetworkView,
    AccessView,
    LogsView,
    PersistenceView,
    FirewallView,
    SettingsView,
  },
  setup() {
    const currentView = ref('overview');
    const wsConnected = ref(false);
    const telemetry = ref({});
    const overviewData = ref({});
    const toasts = ref([]);

    // ==========================================
    // Theme Manager (Dark SOC / Clean Light Mode)
    // ==========================================
    const isDark = ref(localStorage.getItem('cybersentinel_theme') !== 'light');

    const applyTheme = () => {
      if (isDark.value) {
        document.documentElement.classList.add('dark');
        document.documentElement.classList.remove('light');
        localStorage.setItem('cybersentinel_theme', 'dark');
      } else {
        document.documentElement.classList.remove('dark');
        document.documentElement.classList.add('light');
        localStorage.setItem('cybersentinel_theme', 'light');
      }
      nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    };

    const toggleTheme = () => {
      isDark.value = !isDark.value;
      applyTheme();
      showToast(`Switched to ${isDark.value ? 'Dark SOC' : 'Light'} Mode`, 'info');
    };

    // ==========================================
    // Authentication & Brute-Force State
    // ==========================================
    const authEnabled = ref(true);
    const isAuthenticated = ref(false);
    const mustChangePassword = ref(false);
    const currentUsername = ref('admin');
    const authLoading = ref(true);
    const showPassword = ref(false);

    const loginForm = reactive({
      username: 'admin',
      password: '',
    });

    const loginState = reactive({
      loading: false,
      error: '',
      isLocked: false,
      retryAfter: 0,
      timerInterval: null,
    });

    const pwdForm = reactive({
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
      error: '',
      loading: false,
    });

    const startLockoutTimer = (seconds) => {
      if (loginState.timerInterval) clearInterval(loginState.timerInterval);
      loginState.retryAfter = Math.max(1, seconds);
      loginState.isLocked = true;
      loginState.timerInterval = setInterval(() => {
        loginState.retryAfter -= 1;
        if (loginState.retryAfter <= 0) {
          clearInterval(loginState.timerInterval);
          loginState.timerInterval = null;
          loginState.isLocked = false;
          loginState.error = '';
          checkAuthStatus();
        }
      }, 1000);
    };

    const formatCountdown = (seconds) => {
      const m = Math.floor(seconds / 60);
      const s = seconds % 60;
      return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    const checkAuthStatus = async () => {
      try {
        const res = await fetch('/api/auth/status');
        if (res.ok) {
          const status = await res.json();
          authEnabled.value = status.auth_enabled;
          currentUsername.value = status.username || 'admin';

          if (status.locked && status.retry_after > 0) {
            startLockoutTimer(status.retry_after);
          }

          if (!authEnabled.value) {
            isAuthenticated.value = true;
            mustChangePassword.value = false;
            authLoading.value = false;
            fetchOverview();
            connectWebSocket();
            return;
          }

          const token = localStorage.getItem('cybersentinel_token');
          if (token) {
            // Verify token validity by requesting overview
            const testRes = await fetch('/api/overview');
            if (testRes.ok) {
              overviewData.value = await testRes.json();
              isAuthenticated.value = true;
              mustChangePassword.value = status.must_change_password;
              connectWebSocket();
            } else {
              localStorage.removeItem('cybersentinel_token');
              isAuthenticated.value = false;
            }
          } else {
            isAuthenticated.value = false;
          }
        }
      } catch (e) {
        console.error('Failed to query auth status:', e);
      } finally {
        authLoading.value = false;
        nextTick(() => {
          if (window.lucide) window.lucide.createIcons();
        });
      }
    };

    const submitLogin = async () => {
      if (loginState.isLocked) return;
      loginState.loading = true;
      loginState.error = '';

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: loginForm.username.trim(),
            password: loginForm.password,
          }),
        });

        const data = await res.json();

        if (res.status === 429) {
          // Locked out by anti-brute-force defense
          loginState.error = data.detail || 'IP temporarily locked out due to repeated failed logins.';
          if (data.retry_after) {
            startLockoutTimer(data.retry_after);
          }
        } else if (!res.ok) {
          loginState.error = data.detail || 'Invalid username or password.';
        } else {
          // Successful login
          localStorage.setItem('cybersentinel_token', data.token);
          isAuthenticated.value = true;
          mustChangePassword.value = Boolean(data.must_change_password);
          currentUsername.value = data.username || 'admin';
          loginForm.password = '';
          loginState.error = '';

          if (data.must_change_password) {
            pwdForm.currentPassword = 'admin'; // prefill default for convenience
          }

          showToast('Authenticated successfully.', 'success');
          fetchOverview();
          connectWebSocket();
        }
      } catch (e) {
        loginState.error = 'Unable to connect to CyberSentinel daemon.';
      } finally {
        loginState.loading = false;
        nextTick(() => {
          if (window.lucide) window.lucide.createIcons();
        });
      }
    };

    const submitPasswordChange = async () => {
      pwdForm.error = '';
      if (!pwdForm.currentPassword) {
        pwdForm.error = 'Please enter your current password.';
        return;
      }
      if (!pwdForm.newPassword || pwdForm.newPassword.length < 6) {
        pwdForm.error = 'New password must be at least 6 characters.';
        return;
      }
      if (pwdForm.newPassword.toLowerCase() === 'admin') {
        pwdForm.error = 'New password cannot be "admin". Please choose a secure password.';
        return;
      }
      if (pwdForm.newPassword !== pwdForm.confirmPassword) {
        pwdForm.error = 'New password and confirmation do not match.';
        return;
      }

      pwdForm.loading = true;
      try {
        const res = await fetch('/api/auth/change-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            current_password: pwdForm.currentPassword,
            new_password: pwdForm.newPassword,
          }),
        });

        const data = await res.json();
        if (!res.ok) {
          pwdForm.error = data.detail || 'Failed to update administrator password.';
        } else {
          if (data.token) {
            localStorage.setItem('cybersentinel_token', data.token);
          }
          mustChangePassword.value = false;
          pwdForm.currentPassword = '';
          pwdForm.newPassword = '';
          pwdForm.confirmPassword = '';
          showToast('Administrator password updated! CyberSentinel secured.', 'success');
          fetchOverview();
        }
      } catch (e) {
        pwdForm.error = 'Error connecting to security daemon.';
      } finally {
        pwdForm.loading = false;
        nextTick(() => {
          if (window.lucide) window.lucide.createIcons();
        });
      }
    };

    const logout = async () => {
      try {
        await fetch('/api/auth/logout', { method: 'POST' });
      } catch (e) {}
      localStorage.removeItem('cybersentinel_token');
      isAuthenticated.value = false;
      if (ws) {
        ws.close();
        ws = null;
      }
      wsConnected.value = false;
      showToast('Signed out of CyberSentinel.', 'info');
      checkAuthStatus();
    };

    window.addEventListener('cybersentinel:unauthorized', () => {
      if (isAuthenticated.value) {
        logout();
      }
    });

    // ==========================================
    // Modal States
    // ==========================================
    const blockModal = reactive({
      open: false,
      ip: '',
      duration: 86400, // 24 hours
      reason: 'Hostile network anomaly',
      force: false,
      loading: false,
    });

    const killModal = reactive({
      open: false,
      session: null,
      loading: false,
    });

    const unblockModal = reactive({
      open: false,
      ip: '',
      loading: false,
    });

    const fimModal = reactive({
      open: false,
      reason: 'Admin approved baseline modification',
      loading: false,
    });

    // ==========================================
    // Toast Manager
    // ==========================================
    const showToast = (message, type = 'info') => {
      const id = Date.now() + Math.random();
      toasts.value.push({ id, message, type });
      setTimeout(() => {
        toasts.value = toasts.value.filter(t => t.id !== id);
      }, 4500);
    };

    const removeToast = (id) => {
      toasts.value = toasts.value.filter(t => t.id !== id);
    };

    // Navigation
    const navigate = (viewName) => {
      currentView.value = viewName;
      nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    };

    // REST Overview Fetcher
    const fetchOverview = async () => {
      if (!isAuthenticated.value && authEnabled.value) return;
      try {
        const res = await fetch('/api/overview');
        if (res.ok) {
          overviewData.value = await res.json();
        }
      } catch (e) {
        console.error('Failed fetching overview:', e);
      }
    };

    // ==========================================
    // WebSocket Live Telemetry Connection
    // ==========================================
    let ws = null;
    let reconnectTimer = null;

    const connectWebSocket = () => {
      if (!isAuthenticated.value && authEnabled.value) return;
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const token = localStorage.getItem('cybersentinel_token');
      const tokenParam = token ? `?token=${encodeURIComponent(token)}` : '';
      const wsUrl = `${protocol}//${window.location.host}/ws/live${tokenParam}`;

      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          wsConnected.value = true;
          if (reconnectTimer) clearTimeout(reconnectTimer);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'telemetry_pulse') {
              telemetry.value = data;
            }
          } catch (e) {
            console.error('Error parsing WS message:', e);
          }
        };

        ws.onclose = () => {
          wsConnected.value = false;
          if (isAuthenticated.value) {
            reconnectTimer = setTimeout(connectWebSocket, 3000);
          }
        };

        ws.onerror = () => {
          wsConnected.value = false;
        };
      } catch (e) {
        console.error('WebSocket connection failed:', e);
        if (isAuthenticated.value) {
          reconnectTimer = setTimeout(connectWebSocket, 3000);
        }
      }
    };

    // Modal Actions
    const triggerBlockModal = (ip, defaultReason = 'Manual Operator Drop') => {
      blockModal.ip = ip;
      blockModal.reason = defaultReason;
      blockModal.duration = 86400;
      blockModal.force = false;
      blockModal.open = true;
      nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    };

    const confirmBlockIP = async () => {
      blockModal.loading = true;
      try {
        const res = await fetch('/api/firewall/ban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip: blockModal.ip,
            duration: blockModal.duration,
            reason: blockModal.reason,
            force: blockModal.force,
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`Successfully dropped ${blockModal.ip} at kernel level!`, 'success');
          blockModal.open = false;
          fetchOverview();
        } else {
          showToast(data.detail || data.error || 'Failed to ban IP', 'error');
        }
      } catch (e) {
        showToast('Error communicating with firewall daemon', 'error');
      } finally {
        blockModal.loading = false;
      }
    };

    const triggerKillModal = (session) => {
      killModal.session = session;
      killModal.open = true;
      nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    };

    const confirmKillSession = async () => {
      if (!killModal.session) return;
      killModal.loading = true;
      try {
        const res = await fetch('/api/access/kill-session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: String(killModal.session.session_id || killModal.session.session || ''),
            tty: killModal.session.tty,
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`Terminated session for user ${killModal.session.user}`, 'success');
          killModal.open = false;
          fetchOverview();
        } else {
          showToast(data.detail || 'Failed to terminate session', 'error');
        }
      } catch (e) {
        showToast('Error sending kill command', 'error');
      } finally {
        killModal.loading = false;
      }
    };

    const triggerUnblockModal = (ip) => {
      unblockModal.ip = ip;
      unblockModal.open = true;
      nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    };

    const confirmUnblockIP = async () => {
      if (!unblockModal.ip) return;
      unblockModal.loading = true;
      try {
        const res = await fetch('/api/firewall/unban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: unblockModal.ip })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`Unblocked ${unblockModal.ip}`, 'success');
          unblockModal.open = false;
          fetchOverview();
        } else {
          showToast(data.detail || 'Failed to unblock IP', 'error');
        }
      } catch (e) {
        showToast('Error communicating with firewall daemon', 'error');
      } finally {
        unblockModal.loading = false;
      }
    };

    const triggerFimModal = () => {
      fimModal.reason = 'Admin approved baseline modification';
      fimModal.open = true;
      nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    };

    const confirmUpdateFim = async () => {
      fimModal.loading = true;
      try {
        const res = await fetch('/api/persistence/fim/update-baseline', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: fimModal.reason })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`SHA-256 FIM baseline refreshed (${data.hashed_files} files)`, 'success');
          fimModal.open = false;
        } else {
          showToast(data.detail || 'Failed to update FIM baseline', 'error');
        }
      } catch (e) {
        showToast('Error updating FIM baseline', 'error');
      } finally {
        fimModal.loading = false;
      }
    };

    onMounted(async () => {
      applyTheme();
      await checkAuthStatus();
      setInterval(() => {
        if (isAuthenticated.value) {
          fetchOverview();
        }
      }, 5000);
    });

    return {
      currentView,
      wsConnected,
      telemetry,
      overviewData,
      toasts,
      navigate,
      showToast,
      removeToast,
      // Theme
      isDark,
      toggleTheme,
      // Authentication & Brute-Force
      authEnabled,
      isAuthenticated,
      mustChangePassword,
      currentUsername,
      authLoading,
      showPassword,
      loginForm,
      loginState,
      pwdForm,
      formatCountdown,
      submitLogin,
      submitPasswordChange,
      logout,
      // Modals
      blockModal,
      triggerBlockModal,
      confirmBlockIP,
      killModal,
      triggerKillModal,
      confirmKillSession,
      unblockModal,
      triggerUnblockModal,
      confirmUnblockIP,
      fimModal,
      triggerFimModal,
      confirmUpdateFim,
    };
  }
});

app.mount('#app');
