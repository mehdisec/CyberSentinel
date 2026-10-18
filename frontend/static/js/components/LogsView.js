// LogsView.js - Security Logs & Audit Stream
const LogsView = {
  name: 'LogsView',
  props: ['telemetry'],
  data() {
    return {
      logs: [],
      loading: false,
      search: '',
      regex: '',
      facility: 'all',
      severity: 'all',
      limit: 100,
      autoScroll: true,
      paused: false,
    };
  },
  template: `
    <div class="space-y-6">
      <!-- Top Control Bar -->
      <div class="glass-panel p-4 rounded-xl flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <i data-lucide="file-text" class="w-5 h-5 text-cyan-400"></i>
          <div>
            <h2 class="text-sm font-bold text-white">Security & Audit Log Stream</h2>
            <p class="text-xs text-slate-400">Real-time log ingestion from /var/log/auth.log and systemd journalctl</p>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <!-- Text Search -->
          <input
            v-model="search"
            @keyup.enter="fetchLogs"
            type="text"
            placeholder="Search keywords..."
            class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-36 sm:w-48"
          />

          <!-- Regex Search -->
          <input
            v-model="regex"
            @keyup.enter="fetchLogs"
            type="text"
            placeholder="Regex pattern..."
            class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono w-32 sm:w-40"
          />

          <!-- Severity Filter -->
          <select v-model="severity" @change="fetchLogs" class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>

          <!-- Facility Filter -->
          <select v-model="facility" @change="fetchLogs" class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none">
            <option value="all">All Facilities</option>
            <option value="sshd">sshd</option>
            <option value="sudo">sudo</option>
            <option value="firewall">firewall</option>
            <option value="system">system</option>
          </select>

          <!-- Query Button -->
          <button @click="fetchLogs" class="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition flex items-center gap-1.5">
            <i data-lucide="search" class="w-3.5 h-3.5"></i>
            Filter
          </button>

          <!-- Auto Scroll & Pause Controls -->
          <button @click="paused = !paused" :class="['px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition flex items-center gap-1', paused ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-800 text-slate-300 border-slate-700']">
            <i :data-lucide="paused ? 'play' : 'pause'" class="w-3.5 h-3.5"></i>
            {{ paused ? 'Resume Stream' : 'Pause' }}
          </button>

          <button @click="exportLogs" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition" title="Export JSON">
            <i data-lucide="download" class="w-4 h-4"></i>
          </button>
        </div>
      </div>

      <!-- Terminal Log View Container -->
      <div class="terminal-window p-4 rounded-xl shadow-2xl relative h-[560px] flex flex-col">
        <div class="flex items-center justify-between text-[11px] text-slate-500 border-b border-slate-800/80 pb-2 mb-2 font-mono">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span>
            <span class="text-slate-400 font-semibold ml-2">/var/log/auth.log ~ live audit output</span>
          </div>
          <div class="flex items-center gap-4">
            <span v-if="paused" class="text-amber-400 font-bold flex items-center gap-1">
              <i data-lucide="pause-circle" class="w-3 h-3"></i> STREAM PAUSED
            </span>
            <span v-else class="text-emerald-400 font-bold flex items-center gap-1">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 pulse-live"></span> LIVE STREAMING
            </span>
            <span>Total Buffer: {{ logs.length }} lines</span>
          </div>
        </div>

        <div id="logTerminalBody" class="flex-1 overflow-y-auto space-y-1 pr-2">
          <div v-for="(log, idx) in logs" :key="idx" class="flex items-start gap-3 py-1 px-2 rounded hover:bg-slate-800/40 transition">
            <!-- Severity Badge -->
            <span :class="[
              'px-1.5 py-0.2 rounded text-[10px] uppercase font-bold shrink-0 mt-0.5',
              log.severity === 'critical' ? 'badge-critical' :
              log.severity === 'warning' ? 'badge-warning' : 'badge-info'
            ]">
              {{ log.severity }}
            </span>

            <!-- Facility -->
            <span class="text-slate-500 text-[11px] shrink-0 w-14 font-semibold uppercase">
              [{{ log.facility }}]
            </span>

            <!-- Raw Content -->
            <span :class="[
              'break-all text-xs font-mono leading-relaxed',
              log.severity === 'critical' ? 'text-rose-200' :
              log.severity === 'warning' ? 'text-amber-200' : 'text-slate-300'
            ]">
              {{ log.raw }}
            </span>
          </div>

          <div v-if="logs.length === 0" class="py-16 text-center text-slate-500">
            No matching log entries found for current criteria.
          </div>
        </div>
      </div>
    </div>
  `,
  methods: {
    async fetchLogs() {
      try {
        let url = `/api/logs?limit=${this.limit}`;
        if (this.search) url += `&search=${encodeURIComponent(this.search)}`;
        if (this.regex) url += `&regex=${encodeURIComponent(this.regex)}`;
        if (this.facility !== 'all') url += `&facility=${encodeURIComponent(this.facility)}`;
        if (this.severity !== 'all') url += `&severity=${encodeURIComponent(this.severity)}`;

        const res = await fetch(url);
        if (res.ok) {
          const data = await res.json();
          this.logs = data.logs || [];
          if (this.autoScroll) {
            this.$nextTick(() => {
              const el = document.getElementById('logTerminalBody');
              if (el) el.scrollTop = 0; // most recent first
            });
          }
        }
      } catch (e) {
        console.error('Failed fetching logs:', e);
      }
    },
    exportLogs() {
      const blob = new Blob([JSON.stringify(this.logs, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cybersentinel_logs_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  },
  watch: {
    'telemetry.latest_logs': {
      handler(newLogs) {
        if (!this.paused && newLogs && newLogs.length > 0 && !this.search && !this.regex && this.severity === 'all' && this.facility === 'all') {
          // Prepend new unique lines
          const existingRaws = new Set(this.logs.map(l => l.raw));
          for (const nl of newLogs) {
            if (!existingRaws.has(nl.raw)) {
              this.logs.unshift(nl);
              if (this.logs.length > 300) this.logs.pop();
            }
          }
        }
      },
      deep: true
    }
  },
  mounted() {
    this.fetchLogs();
    if (window.lucide) window.lucide.createIcons();
  },
  updated() {
    if (window.lucide) window.lucide.createIcons();
  }
};
