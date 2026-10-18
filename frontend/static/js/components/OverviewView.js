// OverviewView.js - Consolidated SOC Dashboard
const OverviewView = {
  name: 'OverviewView',
  props: ['telemetry', 'overviewData'],
  emits: ['open-block-modal', 'open-kill-modal', 'navigate'],
  template: `
    <div class="space-y-6">
      <!-- Threat Alert Banner -->
      <div :class="[
        'p-5 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 transition-all duration-300',
        threatLevel === 'CRITICAL' ? 'bg-rose-950/40 border-rose-500/40 shadow-lg shadow-rose-950/50' :
        threatLevel === 'HIGH' ? 'bg-orange-950/40 border-orange-500/40 shadow-lg shadow-orange-950/50' :
        threatLevel === 'ELEVATED' ? 'bg-amber-950/30 border-amber-500/30' : 'bg-slate-900/60 border-emerald-500/30'
      ]">
        <div class="flex items-center gap-4">
          <div :class="[
            'w-14 h-14 rounded-xl flex items-center justify-center font-bold text-xl shrink-0 border',
            threatLevel === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 pulse-threat' :
            threatLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
            threatLevel === 'ELEVATED' ? 'bg-amber-500/20 text-amber-400 border-amber-500/40' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
          ]">
            {{ threatScore }}
          </div>
          <div>
            <div class="flex items-center gap-2">
              <span class="text-xs uppercase tracking-wider font-semibold text-slate-400">Cybersecurity Posture</span>
              <span :class="[
                'text-xs font-bold px-2 py-0.5 rounded-full border uppercase',
                threatLevel === 'CRITICAL' ? 'badge-critical' :
                threatLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/30' :
                threatLevel === 'ELEVATED' ? 'badge-warning' : 'badge-normal'
              ]">{{ threatLevel }} RISK</span>
            </div>
            <h2 class="text-lg font-bold text-white mt-0.5">
              {{ threatLevel === 'CRITICAL' ? 'High Threat Anomalies Detected' :
                 threatLevel === 'HIGH' ? 'Elevated Attack Activity Observed' :
                 threatLevel === 'ELEVATED' ? 'Moderate Probing & Scans Active' : 'Normal Host Security Operations' }}
            </h2>
            <p class="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
              {{ threatReasons[0] || 'System kernel primitives and SSH daemon operating within nominal threat thresholds.' }}
            </p>
          </div>
        </div>

        <div class="flex items-center gap-2 shrink-0">
          <button @click="$emit('navigate', 'network')" class="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition flex items-center gap-1.5">
            <i data-lucide="activity" class="w-3.5 h-3.5 text-cyan-400"></i>
            Live Network
          </button>
          <button @click="$emit('navigate', 'firewall')" class="px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white shadow transition flex items-center gap-1.5">
            <i data-lucide="shield-alert" class="w-3.5 h-3.5"></i>
            Defense Rules
          </button>
        </div>
      </div>

      <!-- 4 Quick Stats Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Failed Logins -->
        <div class="glass-panel glass-panel-hover p-4 rounded-xl">
          <div class="flex items-center justify-between text-slate-400">
            <span class="text-xs font-medium uppercase tracking-wider">Failed Logins (24h)</span>
            <div class="p-2 rounded-lg bg-rose-500/10 text-rose-400">
              <i data-lucide="shield-x" class="w-4 h-4"></i>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span class="text-2xl font-bold font-mono text-white">{{ stats.failed_logins_count || 0 }}</span>
            <span class="text-xs text-rose-400 font-medium">from {{ stats.unique_attackers_count || 0 }} IPs</span>
          </div>
          <div class="mt-3 text-xs text-slate-400 flex items-center justify-between border-t border-slate-800/80 pt-2">
            <span>SSH Brute Force</span>
            <button @click="$emit('navigate', 'access')" class="text-blue-400 hover:text-blue-300 text-xs font-medium">View Tracker &rarr;</button>
          </div>
        </div>

        <!-- Active Sessions -->
        <div class="glass-panel glass-panel-hover p-4 rounded-xl">
          <div class="flex items-center justify-between text-slate-400">
            <span class="text-xs font-medium uppercase tracking-wider">Active User Sessions</span>
            <div class="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <i data-lucide="users" class="w-4 h-4"></i>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span class="text-2xl font-bold font-mono text-white">{{ stats.active_sessions_count || 0 }}</span>
            <span class="text-xs text-emerald-400 font-medium">Interactive Logins</span>
          </div>
          <div class="mt-3 text-xs text-slate-400 flex items-center justify-between border-t border-slate-800/80 pt-2">
            <span>loginctl & who</span>
            <button @click="$emit('navigate', 'access')" class="text-blue-400 hover:text-blue-300 text-xs font-medium">Inspect Sessions &rarr;</button>
          </div>
        </div>

        <!-- Listening Ports -->
        <div class="glass-panel glass-panel-hover p-4 rounded-xl">
          <div class="flex items-center justify-between text-slate-400">
            <span class="text-xs font-medium uppercase tracking-wider">Listening Sockets</span>
            <div class="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
              <i data-lucide="radio" class="w-4 h-4"></i>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span class="text-2xl font-bold font-mono text-white">{{ stats.listening_ports_count || 0 }}</span>
            <span class="text-xs text-cyan-400 font-medium">Bound Ports</span>
          </div>
          <div class="mt-3 text-xs text-slate-400 flex items-center justify-between border-t border-slate-800/80 pt-2">
            <span>Verified PIDs</span>
            <button @click="$emit('navigate', 'persistence')" class="text-blue-400 hover:text-blue-300 text-xs font-medium">Verify Daemons &rarr;</button>
          </div>
        </div>

        <!-- Banned IPs -->
        <div class="glass-panel glass-panel-hover p-4 rounded-xl">
          <div class="flex items-center justify-between text-slate-400">
            <span class="text-xs font-medium uppercase tracking-wider">Blocked Attackers</span>
            <div class="p-2 rounded-lg bg-purple-500/10 text-purple-400">
              <i data-lucide="ban" class="w-4 h-4"></i>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span class="text-2xl font-bold font-mono text-white">{{ stats.banned_ips_count || 0 }}</span>
            <span class="text-xs text-purple-400 font-medium">nftables / drops</span>
          </div>
          <div class="mt-3 text-xs text-slate-400 flex items-center justify-between border-t border-slate-800/80 pt-2">
            <span>Kernel Packet Filter</span>
            <button @click="$emit('navigate', 'firewall')" class="text-blue-400 hover:text-blue-300 text-xs font-medium">Manage Rules &rarr;</button>
          </div>
        </div>
      </div>

      <!-- Live Resource, Fail2Ban & Traffic Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- CPU Sparkline -->
        <div class="glass-panel p-4 rounded-xl flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs uppercase text-slate-400 font-semibold tracking-wider">CPU Utilization</span>
              <h3 class="text-xl font-bold font-mono text-white mt-1">{{ cpuPercent }}%</h3>
            </div>
            <div class="text-right text-xs text-slate-400">
              <span>{{ cpuCores }} Cores</span>
              <div class="text-slate-500">/proc/stat</div>
            </div>
          </div>
          <div class="w-full bg-slate-800/80 h-2 rounded-full overflow-hidden mt-4">
            <div :class="['h-full transition-all duration-500 rounded-full', cpuPercent > 80 ? 'bg-rose-500' : cpuPercent > 50 ? 'bg-amber-500' : 'bg-emerald-500']" :style="{ width: cpuPercent + '%' }"></div>
          </div>
        </div>

        <!-- RAM Sparkline -->
        <div class="glass-panel p-4 rounded-xl flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs uppercase text-slate-400 font-semibold tracking-wider">Memory Allocation</span>
              <h3 class="text-xl font-bold font-mono text-white mt-1">{{ memPercent }}%</h3>
            </div>
            <div class="text-right text-xs text-slate-400">
              <span>{{ memUsedGb }} / {{ memTotalGb }} GB</span>
              <div class="text-slate-500">/proc/meminfo</div>
            </div>
          </div>
          <div class="w-full bg-slate-800/80 h-2 rounded-full overflow-hidden mt-4">
            <div :class="['h-full transition-all duration-500 rounded-full', memPercent > 85 ? 'bg-rose-500' : memPercent > 65 ? 'bg-amber-500' : 'bg-cyan-500']" :style="{ width: memPercent + '%' }"></div>
          </div>
        </div>

        <!-- Fail2Ban Protection & Jails -->
        <div class="glass-panel p-4 rounded-xl flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <div>
              <div class="flex items-center gap-1.5">
                <span class="text-xs uppercase text-slate-400 font-semibold tracking-wider">Fail2Ban Protection</span>
                <span :class="['px-1.5 py-0.2 rounded text-[9px] font-bold uppercase border', fail2banRunning ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border-rose-500/30']">
                  {{ fail2banRunning ? 'ACTIVE' : 'OFFLINE' }}
                </span>
              </div>
              <h3 class="text-xl font-bold font-mono text-white mt-1">{{ fail2banBannedCount.toLocaleString() }} <span class="text-xs text-slate-400 font-normal">Banned IPs</span></h3>
            </div>
            <div class="text-right text-xs text-slate-400">
              <span class="font-bold text-cyan-400">{{ fail2banJailsCount }} Jails</span>
              <div class="text-slate-500 font-mono text-[10px]">fail2ban-server</div>
            </div>
          </div>
          <div class="w-full bg-slate-800/80 h-2 rounded-full overflow-hidden mt-4">
            <div class="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full" :style="{ width: fail2banRunning ? '100%' : '15%' }"></div>
          </div>
        </div>

        <!-- Network Bandwidth Sparkline -->
        <div class="glass-panel p-4 rounded-xl flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs uppercase text-slate-400 font-semibold tracking-wider">Live Network Traffic</span>
              <div class="flex items-center gap-2 mt-1">
                <span class="text-xs font-mono text-cyan-400 font-bold">↓ {{ rxRate }} KB/s</span>
                <span class="text-xs font-mono text-emerald-400 font-bold">↑ {{ txRate }} KB/s</span>
              </div>
            </div>
            <div class="text-right text-xs text-slate-400">
              <span class="text-slate-300">/proc/net/dev</span>
              <div class="text-slate-500">Uptime: {{ uptimeStr }}</div>
            </div>
          </div>
          <div class="mt-4 flex items-center justify-between text-[11px] text-slate-400 pt-1.5 border-t border-slate-800">
            <span>Load: <strong class="text-slate-200">{{ loadAvg }}</strong></span>
            <button @click="$emit('navigate', 'network')" class="text-blue-400 hover:text-blue-300 font-medium">Metrics &rarr;</button>
          </div>
        </div>
      </div>

      <!-- Top IP Negotiations Banner Preview -->
      <div class="glass-panel rounded-xl p-5">
        <div class="flex items-center justify-between mb-4">
          <div class="flex items-center gap-2">
            <i data-lucide="handshake" class="w-4 h-4 text-cyan-400"></i>
            <div>
              <h3 class="font-bold text-white text-sm">Top IP Connection Negotiations (Real-Time Handshake Matrix)</h3>
              <p class="text-[11px] text-slate-400">Remote peers with highest concurrent TCP negotiations, SYN handshakes, and active socket flows</p>
            </div>
          </div>
          <button @click="$emit('navigate', 'network')" class="text-xs text-blue-400 hover:text-blue-300 font-medium">Full Matrix &rarr;</button>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
              <tr>
                <th class="pb-2">Remote Peer</th>
                <th class="pb-2">Origin / ISP</th>
                <th class="pb-2 text-center">Active Negotiations</th>
                <th class="pb-2">Handshake States</th>
                <th class="pb-2">Target Ports</th>
                <th class="pb-2 text-right font-sans">Action</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              <tr v-for="neg in topNegotiations" :key="neg.ip" class="hover:bg-slate-800/30 transition">
                <td class="py-2.5 font-bold text-slate-200">{{ neg.ip }}</td>
                <td class="py-2.5 font-sans text-slate-300">
                  <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 mr-1.5">{{ neg.geo?.country_code || 'UN' }}</span>
                  {{ neg.geo?.country || 'Unknown' }}
                </td>
                <td class="py-2.5 text-center font-bold text-white">
                  <span class="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">{{ neg.total_negotiations }}</span>
                </td>
                <td class="py-2.5 font-sans">
                  <div class="flex gap-1 text-[10px]">
                    <span v-if="neg.states.SYN_RECV > 0" class="px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 font-bold">SYN_RECV: {{ neg.states.SYN_RECV }}</span>
                    <span v-if="neg.states.ESTAB > 0" class="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300">ESTAB: {{ neg.states.ESTAB }}</span>
                    <span v-if="neg.states.TIME_WAIT > 0" class="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">TIME_WAIT: {{ neg.states.TIME_WAIT }}</span>
                  </div>
                </td>
                <td class="py-2.5 text-cyan-400">
                  {{ neg.target_ports.map(p => ':' + p).join(' ') || '-' }}
                </td>
                <td class="py-2.5 text-right font-sans">
                  <button
                    @click="$emit('open-block-modal', neg.ip, 'Aggressive negotiation: ' + neg.total_negotiations + ' sessions')"
                    class="px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold border border-rose-500/30 transition"
                  >
                    Block IP
                  </button>
                </td>
              </tr>
              <tr v-if="!topNegotiations || topNegotiations.length === 0">
                <td colspan="6" class="py-6 text-center text-slate-500 font-sans">No active remote negotiations detected.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Two Column Bottom Section: Top Attackers & Active Sessions Preview -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Top Probing Attackers Table -->
        <div class="glass-panel rounded-xl p-5">
          <div class="flex items-center justify-between mb-4">
            <div class="flex items-center gap-2">
              <i data-lucide="crosshair" class="w-4 h-4 text-rose-400"></i>
              <h3 class="font-bold text-white text-sm">Top Brute-Force Probing IPs</h3>
            </div>
            <button @click="$emit('navigate', 'access')" class="text-xs text-blue-400 hover:text-blue-300 font-medium">View All &rarr;</button>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
              <thead class="text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="pb-2">Attacker IP</th>
                  <th class="pb-2">Country / ISP</th>
                  <th class="pb-2 text-right">Attempts</th>
                  <th class="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60 font-mono">
                <tr v-for="att in topAttackers" :key="att.ip" class="hover:bg-slate-800/30 transition">
                  <td class="py-2.5 text-slate-200 font-semibold">{{ att.ip }}</td>
                  <td class="py-2.5 text-slate-400 font-sans">
                    <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 mr-1.5">{{ att.geo?.country_code || 'UN' }}</span>
                    {{ att.geo?.country || 'Unknown' }}
                  </td>
                  <td class="py-2.5 text-right font-bold text-rose-400">{{ att.count }}</td>
                  <td class="py-2.5 text-right font-sans">
                    <button @click="$emit('open-block-modal', att.ip, 'Brute-force SSH attack')" class="px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold border border-rose-500/30 transition">
                      Block IP
                    </button>
                  </td>
                </tr>
                <tr v-if="!topAttackers || topAttackers.length === 0">
                  <td colspan="4" class="py-6 text-center text-slate-500 font-sans">No hostile brute-force activity logged recently.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Active Interactive Sessions Preview -->
        <div class="glass-panel rounded-xl p-5">
          <div class="flex items-center justify-between mb-4">
            <div class="flex items-center gap-2">
              <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i>
              <h3 class="font-bold text-white text-sm">Active Interactive Sessions</h3>
            </div>
            <button @click="$emit('navigate', 'access')" class="text-xs text-blue-400 hover:text-blue-300 font-medium">Manage Sessions &rarr;</button>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
              <thead class="text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="pb-2">User / TTY</th>
                  <th class="pb-2">Origin IP</th>
                  <th class="pb-2">Login Time</th>
                  <th class="pb-2 text-right">Defense</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60 font-mono">
                <tr v-for="sess in recentSessions" :key="sess.session_id" class="hover:bg-slate-800/30 transition">
                  <td class="py-2.5">
                    <span :class="['px-1.5 py-0.5 rounded text-[10px] font-bold mr-1', sess.is_root ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-800 text-slate-300']">
                      {{ sess.user }}
                    </span>
                    <span class="text-slate-400 text-[11px]">{{ sess.tty }}</span>
                  </td>
                  <td class="py-2.5 text-slate-300">
                    <div>{{ sess.remote_ip }}</div>
                    <div class="text-[10px] font-sans text-slate-500">{{ sess.geo?.country || 'Local' }}</div>
                  </td>
                  <td class="py-2.5 text-slate-400">{{ sess.login_time }}</td>
                  <td class="py-2.5 text-right font-sans">
                    <button @click="$emit('open-kill-modal', sess)" class="px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-400 text-xs font-semibold border border-rose-500/30 transition">
                      Kill
                    </button>
                  </td>
                </tr>
                <tr v-if="!recentSessions || recentSessions.length === 0">
                  <td colspan="4" class="py-6 text-center text-slate-500 font-sans">No interactive sessions currently open.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `,
  computed: {
    threatScore() {
      return this.telemetry?.threat?.score ?? this.overviewData?.threat?.score ?? 0;
    },
    threatLevel() {
      return this.telemetry?.threat?.level ?? this.overviewData?.threat?.level ?? 'NORMAL';
    },
    threatReasons() {
      return this.telemetry?.threat?.reasons ?? this.overviewData?.threat?.reasons ?? [];
    },
    stats() {
      return this.overviewData?.stats || {};
    },
    cpuPercent() {
      return this.telemetry?.cpu?.total_percent ?? this.overviewData?.metrics?.cpu?.total_percent ?? 0;
    },
    cpuCores() {
      return this.telemetry?.cpu?.cores_count ?? this.overviewData?.metrics?.cpu?.cores_count ?? 1;
    },
    memPercent() {
      return this.telemetry?.memory?.percent ?? this.overviewData?.metrics?.memory?.percent ?? 0;
    },
    memUsedGb() {
      return this.telemetry?.memory?.used_gb ?? this.overviewData?.metrics?.memory?.used_gb ?? 0;
    },
    memTotalGb() {
      return this.telemetry?.memory?.total_gb ?? this.overviewData?.metrics?.memory?.total_gb ?? 0;
    },
    rxRate() {
      return this.telemetry?.bandwidth?.rx_kbps ?? this.overviewData?.metrics?.bandwidth?.rx_kbps ?? 0;
    },
    txRate() {
      return this.telemetry?.bandwidth?.tx_kbps ?? this.overviewData?.metrics?.bandwidth?.tx_kbps ?? 0;
    },
    uptimeStr() {
      return this.overviewData?.metrics?.uptime?.uptime_str || 'Running';
    },
    loadAvg() {
      const up = this.overviewData?.metrics?.uptime;
      return up ? `${up.load_1m}, ${up.load_5m}` : '-';
    },
    topAttackers() {
      return this.overviewData?.quick_data?.top_attackers || [];
    },
    recentSessions() {
      return this.overviewData?.quick_data?.recent_sessions || [];
    },
    topNegotiations() {
      return this.telemetry?.top_negotiations ?? this.overviewData?.quick_data?.top_negotiations ?? [];
    },
    fail2banData() {
      return this.telemetry?.fail2ban ?? this.overviewData?.fail2ban ?? {};
    },
    fail2banRunning() {
      return this.fail2banData?.running ?? true;
    },
    fail2banBannedCount() {
      return this.fail2banData?.total_currently_banned ?? this.overviewData?.stats?.fail2ban_banned_count ?? 0;
    },
    fail2banJailsCount() {
      return this.fail2banData?.total_jails ?? this.overviewData?.stats?.fail2ban_jails_count ?? 0;
    }
  },
  mounted() {
    if (window.lucide) window.lucide.createIcons();
  },
  updated() {
    if (window.lucide) window.lucide.createIcons();
  }
};
