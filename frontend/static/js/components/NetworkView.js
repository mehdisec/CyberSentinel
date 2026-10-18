// NetworkView.js - Live Network, Fail2Ban Defense Matrix, and Top IP Negotiations
const NetworkView = {
  name: 'NetworkView',
  props: ['telemetry'],
  emits: ['open-block-modal'],
  data() {
    return {
      activeSubTab: 'negotiations', // 'negotiations' | 'fail2ban' | 'sockets'
      sockets: [],
      summary: {},
      fail2banData: null,
      fail2banLogs: [],
      manualBanIp: '',
      manualBanJail: 'sshd-aggressive',
      actionLoading: false,
      topNegotiations: [],
      loading: true,
      searchQuery: '',
      selectedProto: 'all',
      selectedState: 'all',
      selectedDirection: 'all',
      chartInstance: null,
      selectedSocket: null,
      currentPage: 1,
      pageSize: 25,
    };
  },
  template: `
    <div class="space-y-6">
      <!-- Top Bandwidth & Traffic Graph Card -->
      <div class="glass-panel p-5 rounded-xl">
        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 class="text-base font-bold text-white flex items-center gap-2">
              <i data-lucide="activity" class="w-4 h-4 text-cyan-400"></i>
              Real-Time Bandwidth & Network Throughput
            </h2>
            <p class="text-xs text-slate-400 mt-0.5">Continuous interface byte counter sampling via /proc/net/dev</p>
          </div>
          <div class="flex items-center gap-4 text-xs font-mono">
            <div class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-cyan-400 inline-block"></span>
              <span class="text-slate-300">RX (Inbound): <strong>{{ currentRx }} KB/s</strong></span>
            </div>
            <div class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-emerald-400 inline-block"></span>
              <span class="text-slate-300">TX (Outbound): <strong>{{ currentTx }} KB/s</strong></span>
            </div>
          </div>
        </div>

        <!-- Chart Container -->
        <div class="h-44 w-full">
          <canvas id="bandwidthChart"></canvas>
        </div>
      </div>

      <!-- Network Sub-Navigation Tabs -->
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div class="flex items-center gap-2">
          <!-- Tab 1: Top IP Negotiations -->
          <button
            @click="activeSubTab = 'negotiations'"
            :class="[
              'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
              activeSubTab === 'negotiations' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
            ]"
          >
            <i data-lucide="handshake" class="w-4 h-4"></i>
            Top IP Negotiations & Handshakes ({{ topNegotiations.length }})
          </button>

          <!-- Tab 2: Fail2Ban Jails & Defense Matrix -->
          <button
            @click="activeSubTab = 'fail2ban'"
            :class="[
              'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
              activeSubTab === 'fail2ban' ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
            ]"
          >
            <i data-lucide="shield-alert" class="w-4 h-4"></i>
            Fail2Ban Jails & Defense Matrix
            <span class="px-1.5 py-0.2 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
              {{ (fail2ban?.total_currently_banned || 0).toLocaleString() }} Banned
            </span>
          </button>

          <!-- Tab 3: Active Sockets Table -->
          <button
            @click="activeSubTab = 'sockets'"
            :class="[
              'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
              activeSubTab === 'sockets' ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
            ]"
          >
            <i data-lucide="network" class="w-4 h-4"></i>
            All Kernel Sockets ({{ summary.total_connections || sockets.length }})
          </button>
        </div>

        <button @click="refreshAll" class="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition" title="Refresh Now">
          <i data-lucide="refresh-cw" class="w-4 h-4"></i>
        </button>
      </div>

      <!-- ============================================================ -->
      <!-- SECTION 1: TOP IP NEGOTIATIONS & HANDSHAKE MATRIX            -->
      <!-- ============================================================ -->
      <div v-if="activeSubTab === 'negotiations'" class="space-y-4">
        <div class="glass-panel p-5 rounded-xl space-y-4">
          <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <h3 class="font-bold text-white text-sm flex items-center gap-2">
                <i data-lucide="crosshair" class="w-4 h-4 text-cyan-400"></i>
                Active Remote IP Connection Negotiations & Handshake Matrix
              </h3>
              <p class="text-xs text-slate-400">
                Aggregates TCP handshake negotiations (SYN_RECV / SYN_SENT), active sessions, and teardown cooldowns grouped by remote IP.
              </p>
            </div>
            <span class="text-xs font-mono text-slate-400">Inspecting {{ topNegotiations.length }} Negotiating Peers</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
                <tr>
                  <th class="pb-2.5">Remote Negotiator IP</th>
                  <th class="pb-2.5">Origin / ISP</th>
                  <th class="pb-2.5 text-center">Negotiation Volume</th>
                  <th class="pb-2.5">Handshake State Breakdown</th>
                  <th class="pb-2.5">Target Services / Ports</th>
                  <th class="pb-2.5">Process</th>
                  <th class="pb-2.5 text-right font-sans">Defense Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60">
                <tr v-for="neg in topNegotiations" :key="neg.ip" class="hover:bg-slate-800/40 transition">
                  <!-- IP -->
                  <td class="py-3 font-bold text-slate-200">
                    <div>{{ neg.ip }}</div>
                    <span :class="[
                      'px-1.5 py-0.2 rounded text-[9px] font-sans font-bold uppercase inline-block mt-0.5',
                      neg.risk_classification === 'SUSPECT_SYN_PROBE' ? 'badge-critical' :
                      neg.risk_classification === 'HIGH_CONCURRENCY' ? 'badge-warning' : 'badge-normal'
                    ]">{{ neg.risk_classification.replace(/_/g, ' ') }}</span>
                  </td>

                  <!-- Origin / ISP -->
                  <td class="py-3 font-sans text-slate-300">
                    <div class="flex items-center gap-1.5">
                      <span class="px-1.5 py-0.2 rounded text-[10px] font-bold bg-slate-800 text-slate-300">{{ neg.geo?.country_code || 'UN' }}</span>
                      <span>{{ neg.geo?.country || 'Unknown' }}</span>
                    </div>
                    <div class="text-[10px] text-slate-500 truncate max-w-xs">{{ neg.geo?.isp || '-' }}</div>
                  </td>

                  <!-- Volume -->
                  <td class="py-3 text-center">
                    <span class="px-2.5 py-1 rounded-lg text-sm font-bold bg-slate-800 text-white border border-slate-700">
                      {{ neg.total_negotiations }}
                    </span>
                  </td>

                  <!-- State Breakdown -->
                  <td class="py-3 font-sans">
                    <div class="flex flex-wrap gap-1.5 text-[10px]">
                      <span v-if="neg.states.SYN_RECV > 0" class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">
                        SYN_RECV (Half-Open): {{ neg.states.SYN_RECV }}
                      </span>
                      <span v-if="neg.states.SYN_SENT > 0" class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30">
                        SYN_SENT: {{ neg.states.SYN_SENT }}
                      </span>
                      <span v-if="neg.states.ESTAB > 0" class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                        ESTABLISHED: {{ neg.states.ESTAB }}
                      </span>
                      <span v-if="neg.states.TIME_WAIT > 0" class="px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                        TIME_WAIT: {{ neg.states.TIME_WAIT }}
                      </span>
                      <span v-if="neg.states.OTHER > 0" class="px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                        OTHER: {{ neg.states.OTHER }}
                      </span>
                    </div>
                  </td>

                  <!-- Ports -->
                  <td class="py-3 text-cyan-400 font-semibold">
                    <div class="flex flex-wrap gap-1">
                      <span v-for="pt in neg.target_ports" :key="pt" class="bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded text-[11px]">
                        :{{ pt }}
                      </span>
                    </div>
                  </td>

                  <!-- Processes -->
                  <td class="py-3 font-sans text-slate-300 font-semibold">
                    {{ neg.processes.join(', ') || '-' }}
                  </td>

                  <!-- Action -->
                  <td class="py-3 text-right font-sans">
                    <button
                      @click="$emit('open-block-modal', neg.ip, 'Aggressive negotiation: ' + neg.total_negotiations + ' sessions')"
                      class="px-2.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-md shadow-rose-900/30 transition flex items-center gap-1 ml-auto"
                    >
                      <i data-lucide="ban" class="w-3.5 h-3.5"></i>
                      Block Negotiator
                    </button>
                  </td>
                </tr>

                <tr v-if="topNegotiations.length === 0">
                  <td colspan="7" class="py-8 text-center text-slate-500 font-sans">No active remote negotiations detected.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- SECTION 2: FAIL2BAN JAILS & DEFENSE MATRIX                   -->
      <!-- ============================================================ -->
      <div v-if="activeSubTab === 'fail2ban'" class="space-y-6">
        <!-- Fail2Ban Top Status Banner -->
        <div class="glass-panel p-5 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border border-blue-500/30 bg-blue-950/10">
          <div class="flex items-center gap-4">
            <div class="w-12 h-12 rounded-xl flex items-center justify-center font-bold text-lg shrink-0 border bg-blue-500/20 text-cyan-300 border-blue-500/40">
              <i data-lucide="shield-check" class="w-6 h-6"></i>
            </div>
            <div>
              <div class="flex items-center gap-2">
                <span class="text-xs uppercase font-semibold text-slate-400">Host Defense Engine</span>
                <span :class="['px-2 py-0.5 rounded-full text-xs font-bold uppercase border', fail2ban?.running ? 'badge-normal' : 'badge-critical']">
                  {{ fail2ban?.running ? 'SERVICE ACTIVE (RUNNING)' : 'SERVICE OFFLINE' }}
                </span>
                <span class="text-xs text-slate-400 font-mono">3 Active Jails</span>
              </div>
              <h3 class="text-base font-bold text-white mt-0.5">
                Fail2Ban Kernel Ingress Filter & Automated Intrusion Prevention
              </h3>
              <p class="text-xs text-slate-300 mt-1 max-w-2xl">
                Monitors SSH authentication and system access logs in real-time, executing automated kernel-level drop rules across active jails for brute-force attacks and protocol abuse.
              </p>
            </div>
          </div>

          <div class="flex items-center gap-6 shrink-0">
            <div class="text-right">
              <span class="text-xs text-slate-400 block font-mono">Active Jails</span>
              <span class="text-2xl font-bold font-mono text-cyan-400">{{ fail2ban?.total_jails || 0 }}</span>
            </div>
            <div class="text-right">
              <span class="text-xs text-slate-400 block font-mono">Currently Banned</span>
              <span class="text-2xl font-bold font-mono text-rose-400">{{ (fail2ban?.total_currently_banned || 0).toLocaleString() }}</span>
            </div>
            <div class="text-right">
              <span class="text-xs text-slate-400 block font-mono">Historical Drops</span>
              <span class="text-2xl font-bold font-mono text-amber-400">{{ (fail2ban?.total_historical_bans || 0).toLocaleString() }}</span>
            </div>
          </div>
        </div>

        <!-- Active Jails Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <div v-for="jail in (fail2ban?.jails || [])" :key="jail.name" class="glass-panel p-4 rounded-xl border border-slate-800 space-y-3">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
                <h4 class="font-bold font-mono text-sm text-white uppercase">{{ jail.name }}</h4>
              </div>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                {{ jail.currently_banned }} BANNED
              </span>
            </div>

            <div class="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800/80">
                <span class="text-[10px] text-slate-500 uppercase block font-sans">Active Failures</span>
                <span class="text-amber-400 font-bold text-sm">{{ jail.currently_failed }}</span>
              </div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800/80">
                <span class="text-[10px] text-slate-500 uppercase block font-sans">Total Failures</span>
                <span class="text-slate-300 font-bold text-sm">{{ jail.total_failed }}</span>
              </div>
            </div>

            <div class="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
              <span>Lifetime Bans: <strong class="text-slate-200 font-mono">{{ jail.total_banned }}</strong></span>
              <button 
                @click="manualBanJail = jail.name" 
                class="text-[11px] text-cyan-400 hover:text-cyan-300 underline font-sans"
              >
                Target Jail
              </button>
            </div>
          </div>
        </div>

        <!-- Manual Ban Toolbar -->
        <div class="glass-panel p-4 rounded-xl border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div class="flex items-center gap-2 w-full sm:w-auto">
            <i data-lucide="shield-plus" class="w-5 h-5 text-rose-400 shrink-0"></i>
            <div>
              <h4 class="text-xs font-bold text-white uppercase">Manual Fail2Ban Rule Injection</h4>
              <p class="text-[11px] text-slate-400">Directly ban an IP in Fail2Ban without waiting for threshold triggers</p>
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            <input 
              v-model="manualBanIp" 
              placeholder="e.g. 198.51.100.25" 
              class="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-blue-500 focus:outline-none w-44"
            />
            <select 
              v-model="manualBanJail" 
              class="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:border-blue-500 focus:outline-none"
            >
              <option v-for="j in (fail2ban?.jails || [])" :key="j.name" :value="j.name">{{ j.name }}</option>
            </select>
            <button 
              @click="submitFail2banBan" 
              :disabled="!manualBanIp || actionLoading"
              class="px-3 py-1.5 rounded-lg text-xs font-bold bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white transition flex items-center gap-1.5 shadow"
            >
              <i data-lucide="lock" class="w-3.5 h-3.5"></i>
              Ban in Jail
            </button>
          </div>
        </div>

        <!-- Banned IPs Inspection Table -->
        <div class="glass-panel rounded-xl overflow-hidden border border-slate-800">
          <div class="p-4 border-b border-slate-800 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="ban" class="w-4 h-4 text-rose-400"></i>
              <h4 class="font-bold text-white text-sm">Active Banned IPs Enriched with GeoIP ({{ fail2ban?.unique_banned_ips_count || fail2ban?.total_currently_banned || 0 }})</h4>
            </div>
            <button 
              @click="fetchFail2ban" 
              class="text-xs text-slate-400 hover:text-white flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 border border-slate-800"
            >
              <i data-lucide="refresh-cw" class="w-3 h-3"></i>
              Refresh
            </button>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="bg-slate-950/80 text-slate-400 text-[11px] uppercase tracking-wider border-b border-slate-800 font-sans">
                <tr>
                  <th class="p-3.5">Attacker IP</th>
                  <th class="p-3.5">Geolocation & ISP</th>
                  <th class="p-3.5">Assigned Jails</th>
                  <th class="p-3.5 text-right">Defense Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60 text-slate-300">
                <tr v-for="item in (fail2ban?.sample_banned_ips || [])" :key="item.ip" class="hover:bg-slate-900/40 transition">
                  <td class="p-3.5 font-bold text-rose-400 flex items-center gap-2">
                    <i data-lucide="alert-octagon" class="w-3.5 h-3.5 text-rose-500 shrink-0"></i>
                    {{ item.ip }}
                  </td>
                  <td class="p-3.5 text-slate-300 font-sans text-xs">
                    <span v-if="item.geo?.city || item.geo?.country" class="font-semibold text-slate-200">
                      {{ item.geo?.city ? item.geo.city + ', ' : '' }}{{ item.geo?.country || '' }}
                    </span>
                    <span v-else class="text-slate-500">Local / Public IP</span>
                    <span v-if="item.geo?.isp" class="text-slate-500 text-[11px] block">
                      ISP: {{ item.geo.isp }}
                    </span>
                  </td>
                  <td class="p-3.5">
                    <div class="flex flex-wrap gap-1">
                      <span v-for="j in item.jails" :key="j" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-900 border border-slate-700 text-cyan-300">
                        {{ j }}
                      </span>
                    </div>
                  </td>
                  <td class="p-3.5 text-right font-sans">
                    <button 
                      @click="submitFail2banUnban(item.ip)" 
                      :disabled="actionLoading"
                      class="px-2.5 py-1 rounded text-xs font-bold bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 hover:text-white transition flex items-center gap-1.5 ml-auto"
                    >
                      <i data-lucide="unlock" class="w-3.5 h-3.5 text-emerald-400"></i>
                      Unban IP
                    </button>
                  </td>
                </tr>
                <tr v-if="!(fail2ban?.sample_banned_ips?.length)">
                  <td colspan="4" class="p-6 text-center text-slate-500 font-sans">
                    No active Fail2Ban banned IPs detected in current active jails.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Fail2Ban Audit Log Stream -->
        <div class="glass-panel rounded-xl overflow-hidden border border-slate-800 space-y-3 p-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <div class="flex items-center gap-2">
              <i data-lucide="scroll-text" class="w-4 h-4 text-cyan-400"></i>
              <h4 class="font-bold text-white text-sm">Recent Fail2Ban Activity Log (/var/log/fail2ban.log)</h4>
            </div>
            <button 
              @click="fetchFail2banLogs" 
              class="text-xs text-slate-400 hover:text-white flex items-center gap-1"
            >
              <i data-lucide="refresh-cw" class="w-3 h-3"></i>
              Refresh Logs
            </button>
          </div>

          <div class="terminal-window p-3 max-h-56 overflow-y-auto space-y-1">
            <div v-for="(log, idx) in fail2banLogs" :key="idx" class="flex items-center gap-3 text-[11px]">
              <span class="text-slate-500 shrink-0 font-mono">{{ log.timestamp }}</span>
              <span :class="[
                'px-1.5 py-0.2 rounded text-[10px] font-bold uppercase shrink-0',
                log.action === 'BAN' ? 'bg-rose-500/20 text-rose-300' :
                log.action === 'UNBAN' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-blue-500/20 text-blue-300'
              ]">{{ log.action }}</span>
              <span class="text-cyan-400 font-mono shrink-0">[{{ log.jail }}]</span>
              <span class="text-white font-mono font-bold">{{ log.ip }}</span>
            </div>
            <div v-if="!fail2banLogs.length" class="text-slate-500 text-xs italic">
              Loading recent Fail2Ban log events...
            </div>
          </div>
        </div>
      </div>

      <!-- ============================================================ -->
      <!-- SECTION 3: ALL KERNEL ACTIVE SOCKETS TABLE                   -->
      <!-- ============================================================ -->
      <div v-if="activeSubTab === 'sockets'" class="glass-panel rounded-xl p-5 space-y-4">
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div>
            <h3 class="text-sm font-bold text-white flex items-center gap-2">
              <i data-lucide="network" class="w-4 h-4 text-blue-400"></i>
              Live Active Socket Inspection (ss /proc)
            </h3>
            <span class="text-xs text-slate-400">Showing {{ filteredSockets.length }} active sockets</span>
          </div>

          <!-- Filters -->
          <div class="flex flex-wrap items-center gap-2 w-full lg:w-auto">
            <input
              v-model="searchQuery"
              type="text"
              placeholder="Filter IP, port, PID, process..."
              class="w-full sm:w-64 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />

            <select v-model="selectedDirection" class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none">
              <option value="all">All Directions</option>
              <option value="inbound">Inbound</option>
              <option value="outbound">Outbound</option>
              <option value="listen">Listening</option>
            </select>

            <select v-model="selectedProto" class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none">
              <option value="all">All Proto</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>

            <select v-model="selectedState" class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none">
              <option value="all">All States</option>
              <option value="ESTAB">ESTABLISHED</option>
              <option value="LISTEN">LISTEN</option>
              <option value="TIME-WAIT">TIME-WAIT</option>
              <option value="CLOSE-WAIT">CLOSE-WAIT</option>
            </select>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
              <tr>
                <th class="pb-2.5">Proto</th>
                <th class="pb-2.5">State</th>
                <th class="pb-2.5">Local Address:Port</th>
                <th class="pb-2.5">Direction</th>
                <th class="pb-2.5">Remote Address:Port</th>
                <th class="pb-2.5">Process / PID</th>
                <th class="pb-2.5 text-right font-sans">Action</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              <tr v-for="sock in paginatedSockets" :key="sock.local_ip + sock.local_port + sock.remote_ip + sock.remote_port" class="hover:bg-slate-800/40 transition">
                <td class="py-2.5 uppercase font-bold text-slate-300">{{ sock.proto }}</td>
                <td class="py-2.5">
                  <span :class="[
                    'px-2 py-0.5 rounded text-[10px] font-bold font-sans uppercase',
                    sock.state === 'ESTAB' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' :
                    sock.state === 'LISTEN' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30' :
                    'bg-slate-800 text-slate-400'
                  ]">{{ sock.state }}</span>
                </td>
                <td class="py-2.5 text-slate-200">
                  <span class="font-semibold">{{ sock.local_ip }}</span><span class="text-cyan-400 font-bold">:{{ sock.local_port }}</span>
                </td>
                <td class="py-2.5 font-sans">
                  <span v-if="sock.direction === 'inbound'" class="text-cyan-400 flex items-center gap-1 font-semibold text-[11px]">
                    <i data-lucide="arrow-down-left" class="w-3.5 h-3.5"></i> Inbound
                  </span>
                  <span v-else-if="sock.direction === 'outbound'" class="text-purple-400 flex items-center gap-1 font-semibold text-[11px]">
                    <i data-lucide="arrow-up-right" class="w-3.5 h-3.5"></i> Outbound
                  </span>
                  <span v-else-if="sock.direction === 'listen'" class="text-slate-400 text-[11px]">Listening</span>
                  <span v-else class="text-slate-500 text-[11px]">-</span>
                </td>
                <td class="py-2.5 text-slate-300">
                  <span v-if="sock.remote_ip !== '*'">
                    {{ sock.remote_ip }}<span class="text-slate-500">:{{ sock.remote_port }}</span>
                  </span>
                  <span v-else class="text-slate-600">*:*</span>
                </td>
                <td class="py-2.5 font-sans">
                  <div class="flex items-center gap-1.5">
                    <span class="font-bold text-slate-200">{{ sock.process_name }}</span>
                    <span v-if="sock.pid" class="text-slate-500 font-mono text-[10px]">[PID {{ sock.pid }}]</span>
                    <span v-if="sock.is_deleted_exe" class="badge-critical px-1 py-0.2 rounded text-[9px] font-bold">DELETED EXE</span>
                  </div>
                </td>
                <td class="py-2.5 text-right font-sans">
                  <div class="flex items-center justify-end gap-1.5">
                    <button
                      v-if="sock.remote_ip && sock.remote_ip !== '*' && sock.remote_ip !== '127.0.0.1' && sock.remote_ip !== '::1'"
                      @click="$emit('open-block-modal', sock.remote_ip, 'Active socket: ' + sock.process_name)"
                      class="px-2 py-0.5 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold border border-rose-500/30 transition"
                    >
                      Block IP
                    </button>
                    <button
                      @click="inspectSocket(sock)"
                      class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition"
                    >
                      Inspect
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredSockets.length === 0">
                <td colspan="7" class="py-8 text-center text-slate-500 font-sans">No sockets match the specified filters.</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        <div v-if="filteredSockets.length > pageSize" class="flex items-center justify-between pt-3 border-t border-slate-800 text-xs text-slate-400">
          <div>Showing {{ (currentPage - 1) * pageSize + 1 }} to {{ Math.min(currentPage * pageSize, filteredSockets.length) }} of {{ filteredSockets.length }} sockets</div>
          <div class="flex items-center gap-2">
            <button :disabled="currentPage === 1" @click="currentPage--" class="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-40 text-slate-200">Previous</button>
            <span class="font-mono text-slate-300">Page {{ currentPage }} / {{ totalPages }}</span>
            <button :disabled="currentPage >= totalPages" @click="currentPage++" class="px-2.5 py-1 rounded bg-slate-800 disabled:opacity-40 text-slate-200">Next</button>
          </div>
        </div>
      </div>

      <!-- Process Inspection Drawer Modal -->
      <div v-if="selectedSocket" class="fixed inset-0 z-50 flex items-center justify-center p-4 modal-overlay" @click.self="selectedSocket = null">
        <div class="glass-panel border border-slate-700 bg-slate-900 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 class="font-bold text-white text-base flex items-center gap-2">
              <i data-lucide="info" class="w-4 h-4 text-cyan-400"></i>
              Process & Socket Diagnostics
            </h3>
            <button @click="selectedSocket = null" class="text-slate-400 hover:text-white">&times;</button>
          </div>

          <div class="space-y-3 text-xs font-mono">
            <div>
              <span class="text-slate-500 block font-sans">Process Name & PID:</span>
              <span class="text-white font-bold">{{ selectedSocket.process_name }}</span> (PID: {{ selectedSocket.pid || 'N/A' }})
            </div>
            <div>
              <span class="text-slate-500 block font-sans">Local / Remote Endpoints:</span>
              <span class="text-cyan-400">{{ selectedSocket.local_ip }}:{{ selectedSocket.local_port }}</span>
              &rarr;
              <span class="text-emerald-400">{{ selectedSocket.remote_ip }}:{{ selectedSocket.remote_port }}</span>
            </div>
            <div>
              <span class="text-slate-500 block font-sans">Executable Symlink (/proc/[pid]/exe):</span>
              <span class="text-slate-300 break-all bg-slate-950 p-2 rounded block mt-1 border border-slate-800">{{ selectedSocket.exe_path || 'Unknown / Restricted' }}</span>
              <span v-if="selectedSocket.is_deleted_exe" class="text-rose-400 font-bold block mt-1">⚠️ CRITICAL: Executable was deleted from disk while running in memory!</span>
            </div>
            <div>
              <span class="text-slate-500 block font-sans">Command Line (/proc/[pid]/cmdline):</span>
              <pre class="text-slate-300 break-all bg-slate-950 p-2 rounded block mt-1 border border-slate-800 whitespace-pre-wrap">{{ selectedSocket.cmdline || 'None' }}</pre>
            </div>
          </div>

          <div class="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <button @click="selectedSocket = null" class="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-xs font-semibold">Close</button>
            <button
              v-if="selectedSocket.remote_ip && selectedSocket.remote_ip !== '*' && selectedSocket.remote_ip !== '127.0.0.1'"
              @click="$emit('open-block-modal', selectedSocket.remote_ip, 'Diagnostic action'); selectedSocket = null;"
              class="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
            >
              Block Remote IP
            </button>
          </div>
        </div>
      </div>
    </div>
  `,
  computed: {
    currentRx() {
      return this.telemetry?.bandwidth?.rx_kbps ?? 0;
    },
    currentTx() {
      return this.telemetry?.bandwidth?.tx_kbps ?? 0;
    },
    fail2ban() {
      return this.fail2banData || this.telemetry?.fail2ban;
    },
    filteredSockets() {
      return this.sockets.filter(sock => {
        if (this.selectedProto !== 'all' && sock.proto !== this.selectedProto) return false;
        if (this.selectedState !== 'all' && sock.state !== this.selectedState) return false;
        if (this.selectedDirection !== 'all' && sock.direction !== this.selectedDirection) return false;
        if (this.searchQuery) {
          const q = this.searchQuery.toLowerCase();
          const target = `${sock.local_ip} ${sock.local_port} ${sock.remote_ip} ${sock.remote_port} ${sock.process_name} ${sock.pid} ${sock.state}`.toLowerCase();
          if (!target.includes(q)) return false;
        }
        return true;
      });
    },
    totalPages() {
      return Math.ceil(this.filteredSockets.length / this.pageSize) || 1;
    },
    paginatedSockets() {
      const start = (this.currentPage - 1) * this.pageSize;
      return this.filteredSockets.slice(start, start + this.pageSize);
    }
  },
  methods: {
    async fetchSockets() {
      try {
        const res = await fetch('/api/network/sockets');
        if (res.ok) {
          const data = await res.json();
          this.sockets = data.sockets || [];
          this.summary = data.summary || {};
        }
      } catch (e) {
        console.error('Failed fetching sockets:', e);
      }
    },
    async fetchFail2ban() {
      try {
        const res = await fetch('/api/fail2ban/status');
        if (res.ok) this.fail2banData = await res.json();
      } catch (e) {
        console.error('Failed fetching Fail2Ban status:', e);
      }
    },
    async fetchFail2banLogs() {
      try {
        const res = await fetch('/api/fail2ban/logs?limit=50');
        if (res.ok) {
          const data = await res.json();
          this.fail2banLogs = data.logs || [];
        }
      } catch (e) {
        console.error('Failed fetching Fail2Ban logs:', e);
      }
    },
    async submitFail2banUnban(ip) {
      if (!confirm(`Are you sure you want to unban IP ${ip} from Fail2Ban?`)) return;
      this.actionLoading = true;
      try {
        const res = await fetch('/api/fail2ban/unban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          alert(`Successfully unbanned ${ip}`);
          this.fetchFail2ban();
          this.fetchFail2banLogs();
        } else {
          alert(`Failed to unban: ${data.detail || data.error || 'Unknown error'}`);
        }
      } catch (e) {
        alert(`Error unbanning IP: ${e}`);
      } finally {
        this.actionLoading = false;
      }
    },
    async submitFail2banBan() {
      if (!this.manualBanIp) return;
      this.actionLoading = true;
      try {
        const res = await fetch('/api/fail2ban/ban', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: this.manualBanIp.trim(), jail: this.manualBanJail })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          alert(`Successfully banned ${this.manualBanIp} in jail ${this.manualBanJail}`);
          this.manualBanIp = '';
          this.fetchFail2ban();
          this.fetchFail2banLogs();
        } else {
          alert(`Failed to ban: ${data.detail || data.error || 'Unknown error'}`);
        }
      } catch (e) {
        alert(`Error banning IP: ${e}`);
      } finally {
        this.actionLoading = false;
      }
    },
    async fetchNegotiations() {
      try {
        const res = await fetch('/api/network/top-negotiations?limit=25');
        if (res.ok) {
          const data = await res.json();
          this.topNegotiations = data.negotiations || [];
        }
      } catch (e) {
        console.error('Failed fetching top negotiations:', e);
      }
    },
    refreshAll() {
      this.fetchSockets();
      this.fetchFail2ban();
      this.fetchFail2banLogs();
      this.fetchNegotiations();
      this.$nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    },
    inspectSocket(sock) {
      this.selectedSocket = sock;
      this.$nextTick(() => {
        if (window.lucide) window.lucide.createIcons();
      });
    },
    initChart() {
      const ctx = document.getElementById('bandwidthChart');
      if (!ctx || !window.Chart) return;

      const history = this.telemetry?.bandwidth?.history || { timestamps: [], rx: [], tx: [] };

      this.chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: history.timestamps || [],
          datasets: [
            {
              label: 'Inbound RX (KB/s)',
              data: history.rx || [],
              borderColor: '#06b6d4',
              backgroundColor: 'rgba(6, 182, 212, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.3,
              pointRadius: 0,
            },
            {
              label: 'Outbound TX (KB/s)',
              data: history.tx || [],
              borderColor: '#10b981',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.3,
              pointRadius: 0,
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          scales: {
            x: {
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: { color: '#64748b', font: { size: 10 } }
            },
            y: {
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: { color: '#64748b', font: { size: 10 } },
              beginAtZero: true
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    },
    updateChart(bw) {
      if (!this.chartInstance || !bw?.history) return;
      this.chartInstance.data.labels = bw.history.timestamps;
      this.chartInstance.data.datasets[0].data = bw.history.rx;
      this.chartInstance.data.datasets[1].data = bw.history.tx;
      this.chartInstance.update();
    }
  },
  watch: {
    'telemetry.bandwidth': {
      handler(newBw) {
        if (newBw) this.updateChart(newBw);
      },
      deep: true
    },
    'telemetry.fail2ban': {
      handler(newF2b) {
        if (newF2b) this.fail2banData = newF2b;
      },
      deep: true
    },
    'telemetry.top_negotiations': {
      handler(newNeg) {
        if (newNeg && newNeg.length > 0) this.topNegotiations = newNeg;
      },
      deep: true
    }
  },
  mounted() {
    this.refreshAll();
    this.initChart();
    if (window.lucide) window.lucide.createIcons();
  },
  updated() {
    if (window.lucide) window.lucide.createIcons();
  }
};
