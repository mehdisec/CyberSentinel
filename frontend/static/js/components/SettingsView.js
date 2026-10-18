// SettingsView.js - Settings & Agent Configuration
const SettingsView = {
  name: 'SettingsView',
  emits: ['show-toast'],
  data() {
    return {
      settings: {
        server: { auth_enabled: false, admin_token_set: false },
        alerts: { failed_logins_threshold_1h: 10, bandwidth_spike_mbps: 100, threat_score_high: 65 },
        notifications: { enabled: false, discord_webhook_url: '', telegram_bot_token: '', telegram_chat_id: '', generic_webhook_url: '' },
        firewall_backend: 'nftables',
      },
      sysInfo: {},
      newAdminToken: '',
      loading: false,
      saving: false,
    };
  },
  template: `
    <div class="space-y-6 max-w-4xl">
      <!-- Top Title -->
      <div>
        <h2 class="text-base font-bold text-white flex items-center gap-2">
          <i data-lucide="settings" class="w-4 h-4 text-cyan-400"></i>
          CyberSentinel Daemon Configuration & Alert Settings
        </h2>
        <p class="text-xs text-slate-400 mt-0.5">Customize threat thresholds, webhook integrations, and authentication policies</p>
      </div>

      <!-- Form Grid -->
      <form @submit.prevent="saveSettings" class="space-y-6">
        <!-- 1. Alert Thresholds Card -->
        <div class="glass-panel p-5 rounded-xl space-y-4">
          <h3 class="font-bold text-white text-sm border-b border-slate-800 pb-2 flex items-center gap-2">
            <i data-lucide="bell" class="w-4 h-4 text-amber-400"></i>
            Defense & Threat Score Thresholds
          </h3>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Failed SSH Logins (1h Alert Trigger)</label>
              <input
                v-model.number="settings.alerts.failed_logins_threshold_1h"
                type="number"
                min="1"
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
              />
              <span class="text-[10px] text-slate-500 block mt-1">Default: 10 attempts</span>
            </div>

            <div>
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Bandwidth Anomaly Spike (Mbps)</label>
              <input
                v-model.number="settings.alerts.bandwidth_spike_mbps"
                type="number"
                min="1"
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
              />
              <span class="text-[10px] text-slate-500 block mt-1">Default: 100 Mbps</span>
            </div>

            <div>
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Critical Threat Score Level</label>
              <input
                v-model.number="settings.alerts.threat_score_high"
                type="number"
                min="10"
                max="100"
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
              />
              <span class="text-[10px] text-slate-500 block mt-1">Default: 65</span>
            </div>
          </div>
        </div>

        <!-- 2. Webhook & Incident Dispatchers Card -->
        <div class="glass-panel p-5 rounded-xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 class="font-bold text-white text-sm flex items-center gap-2">
              <i data-lucide="send" class="w-4 h-4 text-blue-400"></i>
              Real-Time Security Incident Dispatchers
            </h3>

            <label class="flex items-center gap-2 cursor-pointer">
              <span class="text-xs text-slate-400">Dispatch Alerts:</span>
              <input
                v-model="settings.notifications.enabled"
                type="checkbox"
                class="w-4 h-4 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
              />
            </label>
          </div>

          <div class="space-y-4">
            <div>
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Discord Webhook URL</label>
              <input
                v-model="settings.notifications.discord_webhook_url"
                type="url"
                placeholder="https://discord.com/api/webhooks/..."
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs text-slate-400 mb-1 font-semibold">Telegram Bot Token</label>
                <input
                  v-model="settings.notifications.telegram_bot_token"
                  type="text"
                  placeholder="123456789:ABCdefGhI..."
                  class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label class="block text-xs text-slate-400 mb-1 font-semibold">Telegram Chat ID</label>
                <input
                  v-model="settings.notifications.telegram_chat_id"
                  type="text"
                  placeholder="-100123456789"
                  class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            <div>
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Generic Webhook (POST JSON)</label>
              <input
                v-model="settings.notifications.generic_webhook_url"
                type="url"
                placeholder="https://soc-collector.example.com/api/alerts"
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div class="flex justify-end">
              <button
                type="button"
                @click="sendTestAlert"
                class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition flex items-center gap-1.5"
              >
                <i data-lucide="radio" class="w-3.5 h-3.5 text-cyan-400"></i>
                Send Test Webhook Ping
              </button>
            </div>
          </div>
        </div>

        <!-- 3. Dashboard Authentication Card -->
        <div class="glass-panel p-5 rounded-xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 class="font-bold text-white text-sm flex items-center gap-2">
              <i data-lucide="lock" class="w-4 h-4 text-rose-400"></i>
              Panel Access & API Authentication
            </h3>

            <label class="flex items-center gap-2 cursor-pointer">
              <span class="text-xs text-slate-400">Enforce Authentication:</span>
              <input
                v-model="settings.server.auth_enabled"
                type="checkbox"
                class="w-4 h-4 rounded bg-slate-900 border-slate-700 text-rose-600 focus:ring-0"
              />
            </label>
          </div>

          <div>
            <label class="block text-xs text-slate-400 mb-1 font-semibold">Admin Access Token / Secret Key</label>
            <input
              v-model="newAdminToken"
              type="password"
              placeholder="Leave blank to keep current secret token"
              class="w-full sm:w-96 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-rose-500"
            />
            <span class="text-[10px] text-slate-500 block mt-1">Used for Bearer authorization header or ?token= query parameter</span>
          </div>
        </div>

        <!-- Save Button -->
        <div class="flex justify-end">
          <button
            type="submit"
            :disabled="saving"
            class="px-6 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-lg shadow-emerald-900/30 transition flex items-center gap-2"
          >
            <i data-lucide="save" class="w-4 h-4"></i>
            {{ saving ? 'Saving Changes...' : 'Save Configuration' }}
          </button>
        </div>
      </form>

      <!-- System Diagnostic Summary Card -->
      <div class="glass-panel p-5 rounded-xl space-y-3">
        <h3 class="font-bold text-white text-sm border-b border-slate-800 pb-2 flex items-center gap-2">
          <i data-lucide="cpu" class="w-4 h-4 text-cyan-400"></i>
          Host System Diagnostics & Security Primitives
        </h3>

        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div>
            <span class="text-slate-500 block font-sans">Hostname:</span>
            <span class="text-slate-200 font-bold">{{ sysInfo.hostname || '-' }}</span>
          </div>
          <div>
            <span class="text-slate-500 block font-sans">OS Distribution:</span>
            <span class="text-slate-200 font-bold">{{ sysInfo.os_distro || '-' }}</span>
          </div>
          <div>
            <span class="text-slate-500 block font-sans">Kernel:</span>
            <span class="text-slate-200 font-bold">{{ sysInfo.kernel || '-' }}</span>
          </div>
          <div>
            <span class="text-slate-500 block font-sans">Firewall Engine:</span>
            <span class="text-cyan-400 font-bold uppercase">{{ sysInfo.firewall_backend || settings.firewall_backend }}</span>
          </div>
        </div>
      </div>
    </div>
  `,
  methods: {
    async fetchSettings() {
      try {
        const [resSet, resSys] = await Promise.all([
          fetch('/api/settings'),
          fetch('/api/system/info')
        ]);
        if (resSet.ok) this.settings = await resSet.json();
        if (resSys.ok) this.sysInfo = await resSys.json();
      } catch (e) {
        console.error('Failed fetching settings:', e);
      }
    },
    async saveSettings() {
      this.saving = true;
      try {
        const payload = {
          auth_enabled: this.settings.server.auth_enabled,
          failed_logins_threshold_1h: this.settings.alerts.failed_logins_threshold_1h,
          bandwidth_spike_mbps: this.settings.alerts.bandwidth_spike_mbps,
          threat_score_high: this.settings.alerts.threat_score_high,
          notifications_enabled: this.settings.notifications.enabled,
          discord_webhook_url: this.settings.notifications.discord_webhook_url,
          telegram_bot_token: this.settings.notifications.telegram_bot_token,
          telegram_chat_id: this.settings.notifications.telegram_chat_id,
          generic_webhook_url: this.settings.notifications.generic_webhook_url,
        };
        if (this.newAdminToken) {
          payload.admin_token = this.newAdminToken;
        }

        const res = await fetch('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok && data.success) {
          this.$emit('show-toast', 'Configuration saved and active!', 'success');
          this.newAdminToken = '';
        } else {
          this.$emit('show-toast', 'Failed saving configuration', 'error');
        }
      } catch (e) {
        this.$emit('show-toast', 'Error communicating with daemon', 'error');
      } finally {
        this.saving = false;
      }
    },
    async sendTestAlert() {
      try {
        const res = await fetch('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ test_webhook: true })
        });
        const data = await res.json();
        if (res.ok && data.test_sent) {
          this.$emit('show-toast', 'Test webhook alert dispatched!', 'success');
        } else {
          this.$emit('show-toast', 'No active webhook configured or dispatch failed.', 'warning');
        }
      } catch (e) {
        this.$emit('show-toast', 'Error testing webhook', 'error');
      }
    }
  },
  mounted() {
    this.fetchSettings();
    if (window.lucide) window.lucide.createIcons();
  },
  updated() {
    if (window.lucide) window.lucide.createIcons();
  }
};
