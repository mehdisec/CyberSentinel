// PersistenceView.js - Threat Detection & Persistence Auditing
const PersistenceView = {
  name: 'PersistenceView',
  emits: ['open-fim-modal'],
  data() {
    return {
      activeTab: 'fim', // 'fim' | 'cron' | 'ports'
      fimData: { files: [], anomalies_count: 0, baseline_created_at: '-' },
      persistenceData: { cron_entries: [], systemd_timers: [], custom_services: [] },
      portsData: [],
      loading: false,
    };
  },
  template: `
    <div class="space-y-6">
      <!-- Subnavigation Tabs -->
      <div class="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          @click="activeTab = 'fim'"
          :class="[
            'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
            activeTab === 'fim' ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
          ]"
        >
          <i data-lucide="file-check" class="w-4 h-4"></i>
          File Integrity Monitor (FIM)
          <span v-if="fimData.anomalies_count > 0" class="px-1.5 py-0.2 rounded text-[10px] font-black bg-rose-500 text-white pulse-threat">
            {{ fimData.anomalies_count }}
          </span>
        </button>

        <button
          @click="activeTab = 'ports'"
          :class="[
            'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
            activeTab === 'ports' ? 'bg-rose-600 text-white shadow-lg shadow-rose-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
          ]"
        >
          <i data-lucide="radio" class="w-4 h-4"></i>
          Port-to-Process Verification ({{ portsData.length }})
        </button>

        <button
          @click="activeTab = 'cron'"
          :class="[
            'px-4 py-2 rounded-lg text-xs font-bold transition flex items-center gap-2',
            activeTab === 'cron' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30' : 'bg-slate-900 text-slate-400 hover:text-white'
          ]"
        >
          <i data-lucide="clock" class="w-4 h-4"></i>
          Crontabs & Systemd Timers ({{ persistenceData.total_cron || 0 }})
        </button>

        <div class="ml-auto">
          <button @click="refreshCurrent" class="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition" title="Refresh">
            <i data-lucide="refresh-cw" class="w-4 h-4"></i>
          </button>
        </div>
      </div>

      <!-- TAB 1: FILE INTEGRITY MONITOR (FIM) -->
      <div v-if="activeTab === 'fim'" class="space-y-4">
        <!-- FIM Status Header Banner -->
        <div class="glass-panel p-5 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div class="flex items-center gap-2">
              <span :class="[
                'w-3 h-3 rounded-full',
                fimData.anomalies_count > 0 ? 'bg-rose-500 pulse-threat' : 'bg-emerald-400'
              ]"></span>
              <h3 class="font-bold text-white text-sm">
                {{ fimData.anomalies_count > 0 ? 'File Integrity Anomalies Detected!' : 'All Monitored Critical Files Verified & Intact' }}
              </h3>
            </div>
            <p class="text-xs text-slate-400 mt-1">
              Active baseline snapshot: <strong class="text-slate-300">{{ fimData.baseline_created_at }}</strong>
              &bull; Monitored targets: <strong class="text-slate-300">{{ fimData.total_monitored || 0 }} files</strong>
            </p>
          </div>

          <button
            @click="$emit('open-fim-modal')"
            class="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow transition flex items-center gap-1.5"
          >
            <i data-lucide="check-circle" class="w-3.5 h-3.5"></i>
            Update / Accept Baseline
          </button>
        </div>

        <!-- Monitored Files Table -->
        <div class="glass-panel rounded-xl p-5">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
                <tr>
                  <th class="pb-2.5">Monitored Target Path</th>
                  <th class="pb-2.5">Status</th>
                  <th class="pb-2.5">Current SHA-256 Digest</th>
                  <th class="pb-2.5">Perms / Owner</th>
                  <th class="pb-2.5">Integrity Diagnostics</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60">
                <tr v-for="f in fimData.files" :key="f.path" class="hover:bg-slate-800/40 transition">
                  <td class="py-3 font-bold text-slate-200">{{ f.path }}</td>
                  <td class="py-3 font-sans">
                    <span :class="[
                      'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                      f.status === 'VERIFIED_OK' ? 'badge-normal' :
                      f.status === 'MODIFIED' ? 'badge-critical' : 'badge-warning'
                    ]">
                      {{ f.status }}
                    </span>
                  </td>
                  <td class="py-3 text-slate-400">
                    <span v-if="f.current?.sha256" class="text-cyan-300 font-mono text-[11px] truncate block max-w-xs">
                      {{ f.current.sha256 }}
                    </span>
                    <span v-else class="text-slate-600 font-sans">File Missing</span>
                  </td>
                  <td class="py-3 text-slate-300 font-sans">
                    <span class="font-mono text-slate-400">{{ f.current?.mode || '-' }}</span>
                    <span class="text-slate-500 text-[10px] ml-1">({{ f.current?.owner || '-' }}:{{ f.current?.group || '-' }})</span>
                  </td>
                  <td class="py-3 font-sans">
                    <span :class="[
                      'text-xs',
                      f.severity === 'critical' ? 'text-rose-400 font-bold' :
                      f.severity === 'warning' ? 'text-amber-400 font-semibold' : 'text-slate-400'
                    ]">
                      {{ f.diff }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- TAB 2: PORT-TO-PROCESS VERIFICATION -->
      <div v-if="activeTab === 'ports'" class="glass-panel rounded-xl p-5 space-y-4">
        <div>
          <h3 class="font-bold text-white text-sm flex items-center gap-2">
            <i data-lucide="shield-alert" class="w-4 h-4 text-rose-400"></i>
            Listening Ports & Binary Memory Verification
          </h3>
          <p class="text-xs text-slate-400">
            Cross-references kernel socket bindings with /proc/[pid]/exe and /proc/[pid]/cmdline to uncover rootkits, deleted drop binaries, or suspicious listeners.
          </p>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs font-mono">
            <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
              <tr>
                <th class="pb-2.5">Port / Proto</th>
                <th class="pb-2.5">Bind Address</th>
                <th class="pb-2.5">Process & PID</th>
                <th class="pb-2.5">User</th>
                <th class="pb-2.5">Executable Location (/proc/[pid]/exe)</th>
                <th class="pb-2.5 text-right font-sans">Risk Assessment</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              <tr v-for="p in portsData" :key="p.ip + p.port + p.proto" class="hover:bg-slate-800/40 transition">
                <td class="py-3 font-bold text-cyan-400">
                  {{ p.port }} <span class="text-slate-500 font-sans uppercase text-[10px]">/ {{ p.proto }}</span>
                </td>
                <td class="py-3 text-slate-300">{{ p.ip }}</td>
                <td class="py-3 font-sans">
                  <span class="font-bold text-slate-200">{{ p.process_name }}</span>
                  <span class="text-slate-500 font-mono text-[10px] ml-1">[PID {{ p.pid }}]</span>
                </td>
                <td class="py-3 text-slate-400 font-sans">{{ p.user }}</td>
                <td class="py-3 text-slate-300">
                  <span class="text-slate-300 font-mono text-[11px] break-all block max-w-sm">{{ p.exe_path }}</span>
                  <span v-if="p.is_deleted" class="text-rose-400 font-sans text-[10px] font-bold block mt-0.5">
                    ⚠️ Deleted binary executing in RAM!
                  </span>
                </td>
                <td class="py-3 text-right font-sans">
                  <span :class="[
                    'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                    p.risk_level === 'CRITICAL' ? 'badge-critical' :
                    p.risk_level === 'SUSPICIOUS' ? 'badge-warning' : 'badge-normal'
                  ]">
                    {{ p.risk_level }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- TAB 3: CRONTABS & SYSTEMD TIMERS -->
      <div v-if="activeTab === 'cron'" class="space-y-6">
        <!-- Crontab Entries -->
        <div class="glass-panel rounded-xl p-5 space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="font-bold text-white text-sm">Active Cron Persistence Entries</h3>
              <p class="text-xs text-slate-400">Scanned from /etc/crontab, /etc/cron.d/*, and /var/spool/cron/crontabs/*</p>
            </div>
            <span class="text-xs font-mono text-slate-400">{{ persistenceData.total_cron || 0 }} entries found</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
                <tr>
                  <th class="pb-2.5">Source File</th>
                  <th class="pb-2.5">User</th>
                  <th class="pb-2.5">Scheduled Command</th>
                  <th class="pb-2.5 text-right font-sans">Safety Check</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60">
                <tr v-for="(cr, idx) in persistenceData.cron_entries" :key="idx" class="hover:bg-slate-800/40 transition">
                  <td class="py-2.5 font-bold text-slate-300">{{ cr.source }}</td>
                  <td class="py-2.5 text-slate-400">{{ cr.user }}</td>
                  <td class="py-2.5 text-slate-200 break-all">{{ cr.command }}</td>
                  <td class="py-2.5 text-right font-sans">
                    <span v-if="cr.is_suspicious" class="badge-critical px-2 py-0.5 rounded text-[10px] font-bold">SUSPICIOUS SCRIPT</span>
                    <span v-else class="text-emerald-400 text-xs font-medium">Standard</span>
                  </td>
                </tr>
                <tr v-if="persistenceData.cron_entries.length === 0">
                  <td colspan="4" class="py-8 text-center text-slate-500 font-sans">No cron entries found.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Systemd Timers -->
        <div class="glass-panel rounded-xl p-5 space-y-4">
          <div>
            <h3 class="font-bold text-white text-sm">Systemd Timers & Scheduled Triggers</h3>
            <p class="text-xs text-slate-400">Periodic timer units executing system background jobs</p>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="text-slate-400 border-b border-slate-800 font-sans uppercase text-[10px] tracking-wider">
                <tr>
                  <th class="pb-2.5">Timer Unit</th>
                  <th class="pb-2.5">Target Service Activated</th>
                  <th class="pb-2.5">Details</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60">
                <tr v-for="t in persistenceData.systemd_timers" :key="t.timer" class="hover:bg-slate-800/40 transition">
                  <td class="py-2.5 font-bold text-cyan-300">{{ t.timer }}</td>
                  <td class="py-2.5 text-emerald-300 font-semibold">{{ t.activates }}</td>
                  <td class="py-2.5 text-slate-400 text-[11px] truncate max-w-sm">{{ t.raw }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `,
  methods: {
    async fetchFim() {
      try {
        const res = await fetch('/api/persistence/fim');
        if (res.ok) this.fimData = await res.json();
      } catch (e) {
        console.error('Failed fetching FIM:', e);
      }
    },
    async fetchPersistence() {
      try {
        const res = await fetch('/api/persistence/artifacts');
        if (res.ok) this.persistenceData = await res.json();
      } catch (e) {
        console.error('Failed fetching persistence:', e);
      }
    },
    async fetchPorts() {
      try {
        const res = await fetch('/api/persistence/ports');
        if (res.ok) {
          const data = await res.json();
          this.portsData = data.ports || [];
        }
      } catch (e) {
        console.error('Failed fetching ports:', e);
      }
    },
    refreshCurrent() {
      this.fetchFim();
      this.fetchPersistence();
      this.fetchPorts();
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
