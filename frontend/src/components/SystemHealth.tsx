import { useState, useEffect } from 'react';
import { Activity, Database, Layers, ShieldCheck, RefreshCw, Cpu } from 'lucide-react';

interface IHealthData {
  status: string;
  timestamp: string;
  services: {
    database: {
      status: string;
      provider: string;
      scansCount: number;
      activeHoneytokens: number;
      error?: string;
    };
    queue: {
      status: string;
      driver: string;
    };
    shield: {
      status: string;
      vectorFirewallRulesCount: number;
    };
  };
}

export function SystemHealth() {
  const [health, setHealth] = useState<IHealthData | null>(null);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState<{ time: string; event: string; status: 'info' | 'success' | 'warn' }[]>([]);

  // Fetch health data
  const fetchHealth = async () => {
    setLoading(true);
    const start = performance.now();
    try {
      const response = await fetch('/api/v1/health');
      if (response.ok) {
        const data = await response.json();
        setHealth(data);
        const latency = (performance.now() - start).toFixed(0);
        addLog(`System health audit complete. Status: ${data.status} | Latency: ${latency}ms`, 'success');
      } else {
        addLog('System health audit failed. Status code: ' + response.status, 'warn');
      }
    } catch (e: any) {
      addLog('Failed to connect to health API: ' + e.message, 'warn');
    } finally {
      setLoading(false);
    }
  };

  const addLog = (event: string, status: 'info' | 'success' | 'warn') => {
    const time = new Date().toLocaleTimeString();
    setLogs(prev => [{ time, event, status }, ...prev].slice(0, 30));
  };

  useEffect(() => {
    fetchHealth();
    addLog('System health monitor initialized.', 'info');
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Activity className="text-emerald-400" size={22} /> Enclave Diagnostics & Health
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time status monitoring of database adapters, background processing workers, WAF configurations, and server connectivity.
          </p>
        </div>

        <button
          onClick={fetchHealth}
          disabled={loading}
          className="px-3.5 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-bold text-slate-200 hover:text-slate-100 hover:border-slate-700 disabled:opacity-50 transition-all flex items-center gap-2"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Run Health Audit
        </button>
      </div>

      {/* Main Status Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left: Overall Enclave Status & Metrics */}
        <div className="lg:col-span-8 space-y-6">
          
          {/* Card: Overall Health */}
          <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-6 flex flex-col md:flex-row justify-between items-center gap-6">
            <div className="flex items-center gap-5">
              {/* Animated status ring */}
              <div className="relative flex items-center justify-center">
                <div className={`absolute w-16 h-16 rounded-full opacity-20 animate-ping ${
                  health?.status === 'UP' ? 'bg-emerald-500' : 'bg-red-500'
                }`}></div>
                <div className={`w-14 h-14 rounded-full border-2 flex items-center justify-center font-black text-sm z-10 ${
                  health?.status === 'UP' 
                    ? 'bg-emerald-950/40 border-emerald-500 text-emerald-400' 
                    : 'bg-red-950/40 border-red-500 text-red-400'
                }`}>
                  {health?.status || 'OFF'}
                </div>
              </div>

              <div>
                <h3 className="text-base font-bold text-slate-200">
                  Enclave Status: {health?.status === 'UP' ? 'Operational' : 'Degraded'}
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Last Checked: {health ? new Date(health.timestamp).toLocaleTimeString() : 'N/A'}
                </p>
                <div className="text-[10px] text-slate-500 font-mono mt-1 uppercase tracking-wider">
                  Host: Localhost:3000 | Zone: Loopback Enclave
                </div>
              </div>
            </div>

            <div className="flex gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-center min-w-[90px]">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-black block">Scans</span>
                <span className="text-lg font-black text-slate-200 mt-1 block">
                  {health?.services.database.scansCount ?? 0}
                </span>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-center min-w-[90px]">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-black block">Decoys</span>
                <span className="text-lg font-black text-slate-200 mt-1 block">
                  {health?.services.database.activeHoneytokens ?? 0}
                </span>
              </div>
            </div>
          </div>

          {/* Cards Grid: Services details */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Database Service */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex justify-between items-start mb-3">
                  <span className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg text-emerald-400">
                    <Database size={16} />
                  </span>
                  <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                    health?.services.database.status === 'UP' 
                      ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-900/60' 
                      : 'bg-red-950/40 text-red-400 border border-red-900/60'
                  }`}>
                    {health?.services.database.status || 'DOWN'}
                  </span>
                </div>
                <h4 className="text-xs font-black text-slate-200 uppercase tracking-wider">Database Service</h4>
                <p className="text-[10px] text-slate-400 mt-1">
                  Active connection to relational SQLite store. Handles scans configuration and compliance certifications.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-900 text-[10px] text-slate-500 font-mono flex justify-between">
                <span>Driver: {health?.services.database.provider || 'sqlite'}</span>
                <span>Enrolled</span>
              </div>
            </div>

            {/* Background Workers Queue */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex justify-between items-start mb-3">
                  <span className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg text-indigo-400">
                    <Layers size={16} />
                  </span>
                  <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                    health?.services.queue.status === 'UP' 
                      ? 'bg-indigo-950/40 text-indigo-400 border border-indigo-900/60' 
                      : 'bg-red-950/40 text-red-400 border border-red-900/60'
                  }`}>
                    {health?.services.queue.status || 'DOWN'}
                  </span>
                </div>
                <h4 className="text-xs font-black text-slate-200 uppercase tracking-wider">Background Workers</h4>
                <p className="text-[10px] text-slate-400 mt-1">
                  BullMQ asynchronous workers queue. Manages parallel security scans scheduling and file structure audits.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-900 text-[10px] text-slate-500 font-mono flex justify-between">
                <span>Driver: {health?.services.queue.driver || 'in-memory'}</span>
                <span>Active</span>
              </div>
            </div>

            {/* AI Vector Shield Firewall */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <div className="flex justify-between items-start mb-3">
                  <span className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg text-blue-400">
                    <ShieldCheck size={16} />
                  </span>
                  <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                    health?.services.shield.status === 'UP' 
                      ? 'bg-blue-950/40 text-blue-400 border border-blue-900/60' 
                      : 'bg-red-950/40 text-red-400 border border-red-900/60'
                  }`}>
                    {health?.services.shield.status || 'DOWN'}
                  </span>
                </div>
                <h4 className="text-xs font-black text-slate-200 uppercase tracking-wider">Defensive Shield</h4>
                <p className="text-[10px] text-slate-400 mt-1">
                  Active character bigram similarity WAF. Intercepts script injections and timing bot brute-forces.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-900 text-[10px] text-slate-500 font-mono flex justify-between">
                <span>WAF Rules: {health?.services.shield.vectorFirewallRulesCount || 0} active</span>
                <span>Guarded</span>
              </div>
            </div>

          </div>

        </div>

        {/* Right: Diagnostics Terminal Log */}
        <div className="lg:col-span-4 bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col min-h-[400px]">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
            <Cpu size={14} className="text-emerald-400" /> Diagnostics Audit Log
          </h3>

          <div className="flex-1 bg-slate-900/80 border border-slate-800 rounded-xl p-3 font-mono text-[10px] overflow-y-auto max-h-[360px] space-y-2">
            {logs.map((log, idx) => (
              <div key={idx} className="flex gap-2 items-start border-b border-slate-800/50 pb-1.5 last:border-0">
                <span className="text-slate-550">[{log.time}]</span>
                <span className={
                  log.status === 'success' ? 'text-emerald-400' : log.status === 'warn' ? 'text-red-400' : 'text-indigo-400'
                }>
                  {log.event}
                </span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
