// FirewallView.js - Firewall & Blocklist Management
const FirewallView = {
  name: 'FirewallView',
  emits: ['open-unblock-modal', 'show-toast'],
  data() {
    return {
      bansData: { backend: 'nftables', managed_bans: [], system_bans: [], total_managed: 0, total_banned: 0 },
      whitelist: [],
      newBanIp: '',
      newBanDuration: 86400, // 24 hours default
      newBanReason: 'Manual SOC Operator Drop',
      newWhitelistIp: '',
      loading: false,
      searchQuery: '',
    };
  },
  template: `
    <div class="space-y-6">
      <!-- Top Action: Manual Ban & Quick Whitelist Grid -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Manual Ban Form Card -->
        <div class="glass-panel p-5 rounded-xl lg:col-span-2 space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 class="font-bold text-white text-sm flex items-center gap-2">
              <i data-lucide="shield-minus" class="w-4 h-4 text-rose-400"></i>
              Deploy Kernel-Level Drop Rule ({{ bansData.backend }})
            </h3>
            <span class="text-xs text-slate-400 font-mono">Real-time nftables / iptables set insertion</span>
          </div>

          <form @submit.prevent="submitBan" class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div class="sm:col-span-1">
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Target IPv4 / IPv6 / CIDR</label>
              <input
                v-model="newBanIp"
                required
                type="text"
                placeholder="e.g. 198.51.100.25"
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-rose-500"
              />
            </div>

            <div class="sm:col-span-1">
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Expiration Duration</label>
              <select v-model="newBanDuration" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500">
                <option :value="3600">1 Hour (3,600s)</option>
                <option :value="86400">24 Hours (86,400s)</option>
                <option :value="604800">7 Days (604,800s)</option>
                <option :value="0">Permanent (No Expiry)</option>
              </select>
            </div>

            <div class="sm:col-span-1">
              <label class="block text-xs text-slate-400 mb-1 font-semibold">Defense Audit Reason</label>
              <input
                v-model="newBanReason"
                type="text"
                placeholder="e.g. Hostile port scan"
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500"
              />
            </div>

            <div class="sm:col-span-3 flex justify-end">
              <button
                type="submit"
                class="px-5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-lg shadow-rose-900/40 transition flex items-center gap-2"
              >
                <i data-lucide="ban" class="w-4 h-4"></i>
                Enforce Kernel Drop Rule
              </button>
            </div>
          </form>
        </div>

        <!-- Whitelist Manager Card -->
        <div class="glass-panel p-5 rounded-xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 class="font-bold text-white text-sm flex items-center gap-2">
              <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i>
              Whitelist Manager
            </h3>
            <span class="text-[11px] text-slate-500">Anti-Lockout</span>
          </div>

          <!-- Add to Whitelist -->
          <div class="flex gap-2">
            <input
              v-model="newWhitelistIp"
              @keyup.enter="addToWhitelist"
              type="text"
              placeholder="IP or CIDR (e.g. 10.0.0.0/8)"
              class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <button @click="addToWhitelist" class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs transition">
              Add
            </button>
          </div>

          <!-- Whitelist Chips -->
          <div class="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto">
            <span
              v-for="item in whitelist"
              :key="item"
              class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 text-[11px] font-mono border border-slate-700"
            >
              {{ item }}
              <button @click="removeFromWhitelist(item)" class="text-slate-500 hover:text-rose-400 font-bold ml-1">&times;</button>
            </span>
          </div>
        </div>
      </div>

      <!-- Banned IPs Table -->
      <div class="glass-panel rounded-xl p-5 space-y-4">
        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h3 class="font-bold text-white text-sm">Active Kernel Blocklist & Drop Rules</h3>
            <p class="text-xs text-slate-400">
              Active drop rules in kernel tables ({{ bansData.total_managed }} CyberSentinel managed, {{ bansData.total_system }} system/fail2ban drops)
            </p>
          </div>

          <div class="flex items-center gap-2 w-full sm:w-auto">
            <input
              v-model="searchQuery"
              type="text"
              placeholder="Filter banned IP or reason..."
              class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 w-full sm:w-64"
            />
            <button @click="fetchRules" class="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition" title="Refresh">
              <i data-lucide="refresh-cw" class="w-4 h-4"></i>
            </button>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
              <tr>
                <th class="pb-2.5">Banned IP / Network</th>
                <th class="pb-2.5">Source / Backend</th>
                <th class="pb-2.5">Expiration / Duration</th>
                <th class="pb-2.5">Audit Reason</th>
                <th class="pb-2.5 text-right font-sans">Action</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              <!-- Managed Bans -->
              <tr v-for="b in filteredManagedBans" :key="b.ip" class="hover:bg-slate-800/40 transition">
                <td class="py-3 font-bold text-rose-400">{{ b.ip }}</td>
                <td class="py-3 font-sans">
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                    CyberSentinel ({{ b.backend }})
                  </span>
                </td>
                <td class="py-3 font-sans">
                  <span v-if="b.expires_in_seconds > 0" class="text-amber-400 font-semibold flex items-center gap-1">
                    <i data-lucide="timer" class="w-3.5 h-3.5"></i>
                    Expires in {{ formatSeconds(b.expires_in_seconds) }}
                  </span>
                  <span v-else class="text-slate-400 font-medium">Permanent</span>
                </td>
                <td class="py-3 text-slate-300 font-sans">{{ b.reason }}</td>
                <td class="py-3 text-right font-sans">
                  <button
                    @click="$emit('open-unblock-modal', b.ip)"
                    class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition"
                  >
                    Unblock
                  </button>
                </td>
              </tr>

              <!-- System Bans (fail2ban / iptables) -->
              <tr v-for="sb in filteredSystemBans" :key="sb.ip" class="hover:bg-slate-800/30 text-slate-400">
                <td class="py-2.5 font-semibold text-slate-300">{{ sb.ip }}</td>
                <td class="py-2.5 font-sans">
                  <span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">
                    {{ sb.source }}
                  </span>
                </td>
                <td class="py-2.5 font-sans text-slate-500">
                  <span v-if="sb.pkts_dropped">{{ sb.pkts_dropped }} pkts dropped</span>
                  <span v-else>Managed by OS</span>
                </td>
                <td class="py-2.5 font-sans text-slate-400">{{ sb.reason }}</td>
                <td class="py-2.5 text-right font-sans">
                  <button
                    @click="$emit('open-unblock-modal', sb.ip)"
                    class="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition"
                  >
                    Unblock
                  </button>
                </td>
              </tr>

              <tr v-if="filteredManagedBans.length === 0 && filteredSystemBans.length === 0">
                <td colspan="5" class="py-8 text-center text-slate-500 font-sans">No active firewall drop rules match the criteria.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `,
  computed: {
    filteredManagedBans() {
      if (!this.searchQuery) return this.bansData.managed_bans || [];
      const q = this.searchQuery.toLowerCase();
      return (this.bansData.managed_bans || []).filter(b => b.ip.toLowerCase().includes(q) || (b.reason || '').toLowerCase().includes(q));
    },
    filteredSystemBans() {
      if (!this.searchQuery) return this.bansData.system_bans || [];
      const q = this.searchQuery.toLowerCase();
      return (this.bansData.system_bans || []).filter(b => b.ip.toLowerCase().includes(q) || (b.reason || '').toLowerCase().includes(q));
    }
  },
  methods: {
    formatSeconds(sec) {
      if (!sec || sec <= 0) return '0s';
      const m = Math.floor(sec / 60);
      const s = Math.floor(sec % 60);
      if (m > 60) {
        const h = Math.floor(m / 60);
        return `${h}h ${m % 60}m`;
      }
      return `${m}m ${s}s`;
    },
    async fetchRules() {
      try {
        const res = await fetch('/api/firewall/rules');
        if (res.ok) this.bansData = await res.json();
      } catch (e) {
        console.error('Failed fetching rules:', e);
      }
    },
    async fetchWhitelist() {
      try {
        const res = await fetch('/api/firewall/whitelist');
        if (res.ok) {
          const data = await res.json();
          this.whitelist = data.whitelist || [];
        }
      } catch (e) {
        console.error('Failed fetching whitelist:', e);
      }
    },
    async submitBan() {
      if (!this.newBanIp) return;
      try {
        const res = await fetch('/api/firewall/ban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip: this.newBanIp,
            duration: this.newBanDuration,
            reason: this.newBanReason,
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          this.$emit('show-toast', `Blocked IP ${this.newBanIp} successfully in kernel!`, 'success');
          this.newBanIp = '';
          this.fetchRules();
        } else {
          this.$emit('show-toast', data.detail || data.error || 'Failed to ban IP', 'error');
        }
      } catch (e) {
        this.$emit('show-toast', 'Network error deploying ban rule', 'error');
      }
    },
    async addToWhitelist() {
      if (!this.newWhitelistIp) return;
      try {
        const res = await fetch('/api/firewall/whitelist/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip_or_cidr: this.newWhitelistIp })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          this.whitelist = data.whitelist;
          this.newWhitelistIp = '';
          this.$emit('show-toast', 'Added to whitelist', 'success');
        }
      } catch (e) {
        this.$emit('show-toast', 'Error updating whitelist', 'error');
      }
    },
    async removeFromWhitelist(item) {
      try {
        const res = await fetch('/api/firewall/whitelist/remove', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip_or_cidr: item })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          this.whitelist = data.whitelist;
          this.$emit('show-toast', `Removed ${item} from whitelist`, 'info');
        }
      } catch (e) {
        this.$emit('show-toast', 'Error removing whitelist item', 'error');
      }
    }
  },
  mounted() {
    this.fetchRules();
    this.fetchWhitelist();
    if (window.lucide) window.lucide.createIcons();
  },
  updated() {
    if (window.lucide) window.lucide.createIcons();
  }
};
