// app.js - CyberSentinel Main Reactive Application
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

    // Theme Manager (Dark SOC / Clean Light Mode)
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

    // Modal States
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

    // Toast Manager
    const showToast = (message, type = 'info') => {
      const id = Date.now() + Math.random();
      toasts.value.push({ id, message, type });
      setTimeout(() => {
        toasts.value = toasts.value.filter(t => t.id !== id);
      }, 4000);
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
      try {
        const res = await fetch('/api/overview');
        if (res.ok) {
          overviewData.value = await res.json();
        }
      } catch (e) {
        console.error('Failed fetching overview:', e);
      }
    };

    // WebSocket Live Telemetry Connection
    let ws = null;
    let reconnectTimer = null;

    const connectWebSocket = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/live`;

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
          reconnectTimer = setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = () => {
          wsConnected.value = false;
        };
      } catch (e) {
        console.error('WebSocket connection failed:', e);
        reconnectTimer = setTimeout(connectWebSocket, 3000);
      }
    };

    // Modal Triggers
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
            session_id: killModal.session.session_id,
            tty: killModal.session.tty,
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`Session ${killModal.session.user}@${killModal.session.tty} terminated!`, 'success');
          killModal.open = false;
          fetchOverview();
        } else {
          showToast(data.detail || 'Failed to terminate session', 'error');
        }
      } catch (e) {
        showToast('Network error terminating session', 'error');
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
      unblockModal.loading = true;
      try {
        const res = await fetch('/api/firewall/unban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: unblockModal.ip })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`Unblocked ${unblockModal.ip} from firewall tables`, 'success');
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
          showToast(`Updated FIM baseline (${data.files_indexed} critical files hashed)`, 'success');
          fimModal.open = false;
          fetchOverview();
        } else {
          showToast('Failed to update FIM baseline', 'error');
        }
      } catch (e) {
        showToast('Error updating FIM baseline', 'error');
      } finally {
        fimModal.loading = false;
      }
    };

    onMounted(() => {
      applyTheme();
      fetchOverview();
      connectWebSocket();
      setInterval(fetchOverview, 5000); // regular sync for overview stats
      if (window.lucide) window.lucide.createIcons();
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
