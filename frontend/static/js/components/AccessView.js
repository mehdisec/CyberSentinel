// AccessView.js - Identity & Access (SSH & Users)
const AccessView = {
  name: 'AccessView',
  emits: ['open-kill-modal', 'open-block-modal'],
  data() {
    return {
      activeTab: 'sessions', // 'sessions' | 'failed' | 'sudo'
      sessions: [],
      failedData: { total_failed_events: 0, unique_attackers: 0, attackers: [] },
      sudoLogs: [],
      loading: false,
      searchQuery: '',
    };
  },
  template: `
    <div class="space-y-6">
      <!-- Subnavigation Tabs -->
      <div class="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          @click="activeTab = 'sessions'"
          :class="[
            'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
            activeTab === 'sessions' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
          ]"
        >
          <i data-lucide="users" class="w-4 h-4"></i>
          Active Sessions ({{ sessions.length }})
        </button>

        <button
          @click="activeTab = 'failed'"
          :class="[
            'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
            activeTab === 'failed' ? 'bg-rose-600 text-white shadow-lg shadow-rose-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
          ]"
        >
          <i data-lucide="shield-x" class="w-4 h-4"></i>
          Failed SSH & Brute-Force Tracker ({{ failedData.unique_attackers || 0 }})
        </button>

        <button
          @click="activeTab = 'sudo'"
          :class="[
            'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
            activeTab === 'sudo' ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
          ]"
        >
          <i data-lucide="terminal" class="w-4 h-4"></i>
          Sudo Execution History ({{ sudoLogs.length }})
        </button>

        <div class="ml-auto">
          <button @click="refreshCurrent" class="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition" title="Refresh">
            <i data-lucide="refresh-cw" class="w-4 h-4"></i>
          </button>
        </div>
      </div>

      <!-- TAB 1: ACTIVE SESSIONS -->
      <div v-if="activeTab === 'sessions'" class="glass-panel rounded-xl p-5 space-y-4">
        <div class="flex items-center justify-between">
          <div>
            <h3 class="font-bold text-white text-sm">Active Interactive User Sessions (loginctl / who)</h3>
            <p class="text-xs text-slate-400">Real-time inspection of shell logins with instant session termination capabilities</p>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
              <tr>
                <th class="pb-2.5">User</th>
                <th class="pb-2.5">TTY / Seat</th>
                <th class="pb-2.5">Remote Origin IP</th>
                <th class="pb-2.5">Geo / ISP</th>
                <th class="pb-2.5">Login Time</th>
                <th class="pb-2.5">PID / Command</th>
                <th class="pb-2.5 text-right font-sans">Emergency Defense</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              <tr v-for="sess in sessions" :key="sess.session_id" class="hover:bg-slate-800/40 transition">
                <td class="py-3 font-sans font-bold">
                  <span :class="['px-2 py-0.5 rounded text-[11px]', sess.is_root ? 'bg-rose-950 text-rose-300 border border-rose-800 font-black' : 'bg-slate-800 text-slate-200']">
                    {{ sess.user }}
                  </span>
                </td>
                <td class="py-3 text-slate-300">{{ sess.tty }}</td>
                <td class="py-3 text-slate-200 font-semibold">{{ sess.remote_ip }}</td>
                <td class="py-3 font-sans text-slate-400">
                  <div class="flex items-center gap-1.5">
                    <span class="px-1.5 py-0.2 rounded text-[10px] font-bold bg-slate-800 text-slate-300">{{ sess.geo?.country_code || 'LOC' }}</span>
                    <span>{{ sess.geo?.country || 'Local' }}</span>
                  </div>
                  <div class="text-[10px] text-slate-500 truncate max-w-xs">{{ sess.geo?.isp || '-' }}</div>
                </td>
                <td class="py-3 text-slate-400">{{ sess.login_time }}</td>
                <td class="py-3 text-slate-300 font-sans">
                  <div class="truncate max-w-xs font-mono text-[11px] bg-slate-950 px-2 py-1 rounded border border-slate-800">
                    {{ sess.command }}
                  </div>
                </td>
                <td class="py-3 text-right font-sans">
                  <button
                    @click="$emit('open-kill-modal', sess)"
                    class="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-md shadow-rose-900/40 transition flex items-center gap-1 ml-auto"
                  >
                    <i data-lucide="user-x" class="w-3.5 h-3.5"></i>
                    Kill Session
                  </button>
                </td>
              </tr>
              <tr v-if="sessions.length === 0">
                <td colspan="7" class="py-8 text-center text-slate-500 font-sans">No active interactive sessions found.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- TAB 2: FAILED LOGIN & BRUTE-FORCE TRACKER -->
      <div v-if="activeTab === 'failed'" class="glass-panel rounded-xl p-5 space-y-4">
        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h3 class="font-bold text-white text-sm">Failed SSH Authenticators & Preauth Probes</h3>
            <p class="text-xs text-slate-400">Parsed from /var/log/auth.log with automatic GeoIP & ISP resolution</p>
          </div>
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search IP, username, country..."
            class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 w-full sm:w-64"
          />
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
              <tr>
                <th class="pb-2.5">Attacker IP</th>
                <th class="pb-2.5">Origin Country / ISP</th>
                <th class="pb-2.5 text-center">Attempts</th>
                <th class="pb-2.5">Targeted Accounts</th>
                <th class="pb-2.5">Last Seen</th>
                <th class="pb-2.5 text-right font-sans">Defense Action</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              <tr v-for="att in filteredAttackers" :key="att.ip" class="hover:bg-slate-800/40 transition">
                <td class="py-3 font-bold text-slate-200">{{ att.ip }}</td>
                <td class="py-3 font-sans text-slate-300">
                  <div class="flex items-center gap-1.5">
                    <span class="px-1.5 py-0.2 rounded text-[10px] font-bold bg-slate-800 text-slate-300">{{ att.geo?.country_code || 'UN' }}</span>
                    <span>{{ att.geo?.country || 'Unknown' }}</span>
                  </div>
                  <div class="text-[10px] text-slate-500 truncate max-w-xs">{{ att.geo?.isp || '-' }}</div>
                </td>
                <td class="py-3 text-center">
                  <span class="px-2 py-0.5 rounded text-xs font-black bg-rose-500/20 text-rose-400 border border-rose-500/30">
                    {{ att.count }}
                  </span>
                </td>
                <td class="py-3 font-sans">
                  <div class="flex flex-wrap gap-1 max-w-md">
                    <span v-for="u in att.attacked_users" :key="u" class="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                      {{ u }}
                    </span>
                    <span v-if="att.total_users_targeted > 10" class="text-[10px] text-slate-500 font-sans">
                      +{{ att.total_users_targeted - 10 }} more
                    </span>
                  </div>
                </td>
                <td class="py-3 text-slate-400 text-[11px]">{{ att.last_seen }}</td>
                <td class="py-3 text-right font-sans">
                  <button
                    @click="$emit('open-block-modal', att.ip, 'SSH Brute-force: ' + att.count + ' failed attempts')"
                    class="px-2.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-md shadow-rose-900/30 transition flex items-center gap-1 ml-auto"
                  >
                    <i data-lucide="shield-alert" class="w-3.5 h-3.5"></i>
                    Block IP
                  </button>
                </td>
              </tr>
              <tr v-if="filteredAttackers.length === 0">
                <td colspan="6" class="py-8 text-center text-slate-500 font-sans">No failed authentication records found.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- TAB 3: SUDO EXECUTION HISTORY -->
      <div v-if="activeTab === 'sudo'" class="glass-panel rounded-xl p-5 space-y-4">
        <div class="flex items-center justify-between">
          <div>
            <h3 class="font-bold text-white text-sm">Privileged Sudo Command Execution Audit</h3>
            <p class="text-xs text-slate-400">Detailed security log of commands invoked with elevated root privileges</p>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
              <tr>
                <th class="pb-2.5">Timestamp</th>
                <th class="pb-2.5">User</th>
                <th class="pb-2.5">Target</th>
                <th class="pb-2.5">TTY</th>
                <th class="pb-2.5">Command Executed</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              <tr v-for="log in sudoLogs" :key="log.timestamp + log.command" class="hover:bg-slate-800/40 transition">
                <td class="py-2.5 text-slate-400 text-[11px]">{{ log.timestamp }}</td>
                <td class="py-2.5 font-bold text-slate-200">{{ log.user }}</td>
                <td class="py-2.5 text-rose-400 font-semibold">{{ log.target_user }}</td>
                <td class="py-2.5 text-slate-400">{{ log.tty }}</td>
                <td class="py-2.5">
                  <div class="flex items-center gap-2">
                    <span v-if="log.is_sensitive" class="badge-critical px-1.5 py-0.2 rounded text-[9px] font-sans font-bold">CRITICAL</span>
                    <span class="text-emerald-300 font-semibold break-all">{{ log.command }}</span>
                  </div>
                  <div class="text-[10px] text-slate-500 font-sans">PWD: {{ log.pwd }}</div>
                </td>
              </tr>
              <tr v-if="sudoLogs.length === 0">
                <td colspan="5" class="py-8 text-center text-slate-500 font-sans">No recent sudo executions captured in auth log.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `,
  computed: {
    filteredAttackers() {
      if (!this.searchQuery) return this.failedData.attackers || [];
      const q = this.searchQuery.toLowerCase();
      return (this.failedData.attackers || []).filter(att => {
        const str = `${att.ip} ${att.geo?.country} ${att.geo?.isp} ${(att.attacked_users || []).join(' ')}`.toLowerCase();
        return str.includes(q);
      });
    }
  },
  methods: {
    async fetchSessions() {
      try {
        const res = await fetch('/api/access/sessions');
        if (res.ok) {
          const data = await res.json();
          this.sessions = data.sessions || [];
        }
      } catch (e) {
        console.error('Error fetching sessions:', e);
      }
    },
    async fetchFailedLogins() {
      try {
        const res = await fetch('/api/access/failed-logins?limit=100');
        if (res.ok) {
          this.failedData = await res.json();
        }
      } catch (e) {
        console.error('Error fetching failed logins:', e);
      }
    },
    async fetchSudoHistory() {
      try {
        const res = await fetch('/api/access/sudo-history?limit=100');
        if (res.ok) {
          const data = await res.json();
          this.sudoLogs = data.history || [];
        }
      } catch (e) {
        console.error('Error fetching sudo history:', e);
      }
    },
    refreshCurrent() {
      this.fetchSessions();
      this.fetchFailedLogins();
      this.fetchSudoHistory();
      this.$nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    }
  },
  mounted() {
    this.refreshCurrent();
  },
  updated() {
    if (window.lucide) window.lucide.createIcons();
  }
};
