import { useState } from 'react';
import { ShieldAlert, Zap, Lock, RefreshCw, Key, AlertTriangle, Layers, CheckCircle } from 'lucide-react';

export function ActiveHardening() {
  // Timing Safe Comparison state
  const [secret1, setSecret1] = useState('EnclaveSecretPassphrase2026!');
  const [secret2, setSecret2] = useState('EnclaveSecretPassphrase2026!');
  const [compareResult, setCompareResult] = useState<{ match: boolean; latencyMs: number } | null>(null);
  const [isComparing, setIsComparing] = useState(false);

  // Concurrency Simulation state
  const [concurrencyLogs, setConcurrencyLogs] = useState<{ id: number; time: string; action: string; status: 'pending' | 'success' | 'blocked'; message: string }[]>([]);
  const [isSimulatingRace, setIsSimulatingRace] = useState(false);

  // Parameter Pollution state
  const [pollutedQuery, setPollutedQuery] = useState('apiKey=dev_key_1&apiKey=attacker_injected_key_2');
  const [sanitizedParams, setSanitizedParams] = useState<Record<string, string> | null>(null);
  const [isSanitizing, setIsSanitizing] = useState(false);

  // 1. Run Timing-Safe Comparison simulation
  const handleCompare = async () => {
    setIsComparing(true);
    setCompareResult(null);
    const start = performance.now();
    try {
      const response = await fetch('/api/v1/shield/hardening/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret1, secret2 })
      });
      const data = await response.json();
      const end = performance.now();
      setCompareResult({
        match: data.match,
        latencyMs: parseFloat((end - start).toFixed(2))
      });
    } catch (e: any) {
      console.error(e);
    } finally {
      setIsComparing(false);
    }
  };

  // 2. Run Race Condition Transaction Simulation
  const handleSimulateRace = async () => {
    setIsSimulatingRace(false);
    setConcurrencyLogs([]);
    setIsSimulatingRace(true);

    const logItem = (action: string, status: 'pending' | 'success' | 'blocked', message: string) => {
      const time = new Date().toLocaleTimeString();
      setConcurrencyLogs(prev => [...prev, { id: Date.now() + Math.random(), time, action, status, message }]);
    };

    logItem('Starting concurrent transaction audit...', 'pending', 'Firing 4 parallel balance transfer requests...');

    const userId = 'user-matrix-' + Math.floor(Math.random() * 1000);
    const amount = 250;

    // Fire 4 overlapping balance transfers to the locking endpoint
    const requests = Array.from({ length: 4 }).map(async (_, idx) => {
      // Small randomized execution jitter to stagger requests at millisecond-scale
      await new Promise(r => setTimeout(r, idx * 8));
      
      try {
        const response = await fetch('/api/v1/shield/hardening/transaction', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId, amount })
        });
        const data = await response.json();
        
        if (response.status === 200) {
          logItem(
            `Request #${idx + 1} Accepted`, 
            'success', 
            `Lock acquired on key lock:user-transfer:${userId}. Balance $${amount} transferred.`
          );
        } else {
          logItem(
            `Request #${idx + 1} Blocked`, 
            'blocked', 
            `Status 400: ${data.message || 'Concurrency lock active'}`
          );
        }
      } catch (err: any) {
        logItem(`Request #${idx + 1} Failure`, 'blocked', err.message);
      }
    });

    await Promise.all(requests);
    logItem('Concurrency test complete.', 'success', 'Enclave Lock Manager successfully released lock.');
    setIsSimulatingRace(false);
  };

  // 3. Run HPP Sanitizer Simulation
  const handleSanitizeHpp = async () => {
    setIsSanitizing(true);
    try {
      const response = await fetch(`/api/v1/shield/hardening/query?${pollutedQuery}`);
      const data = await response.json();
      setSanitizedParams(data.sanitized);
    } catch (e: any) {
      console.error(e);
    } finally {
      setIsSanitizing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          <ShieldAlert className="text-indigo-400" size={22} /> Active Security Hardening
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Interact with server-side threat hardening components protecting against race conditions, timing attacks, and parameter pollution.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Widget 1: Concurrency Mutex Lock (Race Condition Sandbox) */}
        <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-start mb-3">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Lock className="text-emerald-400" size={16} /> Concurrency Lock Manager (Mutex)
              </h3>
              <span className="text-[10px] bg-emerald-950/40 text-emerald-400 border border-emerald-900/60 px-2 py-0.5 rounded-full font-bold uppercase tracking-wider">
                Active Protection
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Race conditions occur when duplicate parallel requests manipulate balances before a transaction completes. This module enforces key-based locks to block overlapping transaction attempts.
            </p>

            {/* Simulation Logger console output */}
            <div className="bg-slate-900/80 rounded-xl p-3 border border-slate-800 font-mono text-[11px] h-48 overflow-y-auto mb-4 space-y-2">
              {concurrencyLogs.length === 0 ? (
                <div className="text-slate-500 italic flex items-center justify-center h-full">
                  Click 'Simulate Race Condition' to test transaction locks.
                </div>
              ) : (
                concurrencyLogs.map((log, idx) => (
                  <div key={idx} className="flex gap-2 items-start border-b border-slate-800/50 pb-1.5 last:border-0">
                    <span className="text-slate-500">[{log.time}]</span>
                    <div className="flex-1">
                      <span className={`font-bold ${
                        log.status === 'success' ? 'text-emerald-400' : log.status === 'blocked' ? 'text-red-400' : 'text-indigo-400'
                      }`}>
                        {log.action}:
                      </span>
                      <span className="text-slate-300 ml-1.5">{log.message}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <button
            onClick={handleSimulateRace}
            disabled={isSimulatingRace}
            className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold text-xs rounded-xl transition-all flex items-center justify-center gap-2 shadow-md shadow-emerald-900/20"
          >
            {isSimulatingRace ? <RefreshCw size={14} className="animate-spin" /> : <Zap size={14} />}
            Simulate Race Condition Attack
          </button>
        </div>

        {/* Widget 2: Timing-Safe Comparison Engine */}
        <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-start mb-3">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Key className="text-indigo-400" size={16} /> Constant-Time Comparison Sandbox
              </h3>
              <span className="text-[10px] bg-indigo-950/40 text-indigo-400 border border-indigo-900/60 px-2 py-0.5 rounded-full font-bold uppercase tracking-wider">
                Anti-Leakage
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Standard comparisons exit early on mismatches, leaking timing secrets. We enforce constant-time comparisons (`crypto.timingSafeEqual`) to keep validation latency identical.
            </p>

            <div className="space-y-3.5 mb-4">
              <div>
                <label className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Enclave Value 1 (Server Key)</label>
                <input
                  type="text"
                  value={secret1}
                  onChange={(e) => setSecret1(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 mt-1 font-mono"
                />
              </div>
              <div>
                <label className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Enclave Value 2 (User / Attacker Input)</label>
                <input
                  type="text"
                  value={secret2}
                  onChange={(e) => setSecret2(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 mt-1 font-mono"
                />
              </div>
            </div>

            {compareResult && (
              <div className={`p-3 rounded-xl border mb-4 flex items-center gap-3 text-xs ${
                compareResult.match 
                  ? 'bg-emerald-950/20 border-emerald-900/60 text-emerald-400' 
                  : 'bg-red-950/20 border-red-900/60 text-red-400'
              }`}>
                {compareResult.match ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
                <div>
                  <span className="font-bold">{compareResult.match ? 'Secrets Match!' : 'Access Denied (Mismatch)'}</span>
                  <span className="text-[10px] block opacity-80 mt-0.5">Verification latency: {compareResult.latencyMs}ms (Constant Processing Time)</span>
                </div>
              </div>
            )}
          </div>

          <button
            onClick={handleCompare}
            disabled={isComparing}
            className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-bold text-xs rounded-xl transition-all flex items-center justify-center gap-2 shadow-md shadow-indigo-900/20"
          >
            {isComparing ? <RefreshCw size={14} className="animate-spin" /> : <Lock size={14} />}
            Secure Timing-Safe Compare
          </button>
        </div>

        {/* Widget 3: HTTP Parameter Pollution (HPP) Sandbox */}
        <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between lg:col-span-2">
          <div>
            <div className="flex justify-between items-start mb-3">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Layers className="text-purple-400" size={16} /> Parameter Pollution (HPP) Sanitizer
              </h3>
              <span className="text-[10px] bg-purple-950/40 text-purple-400 border border-indigo-900/60 px-2 py-0.5 rounded-full font-bold uppercase tracking-wider">
                Parameter Guard
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Attackers pass duplicate parameters in query strings (e.g. `apiKey=key1&apiKey=key2`) to bypass firewalls or alter business values. Our sanitizer flattens key parameters to their first secure index.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Query Parameters Input</label>
                <input
                  type="text"
                  value={pollutedQuery}
                  onChange={(e) => setPollutedQuery(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-purple-500 mt-1 font-mono"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">Edit parameters (use '&' to chain parameters with duplicate keys).</span>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Sanitized JSON Output (Server Parsed)</label>
                <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 h-[54px] text-xs text-slate-200 mt-1 font-mono flex items-center overflow-x-auto">
                  {sanitizedParams ? (
                    <code className="text-purple-400">{JSON.stringify(sanitizedParams)}</code>
                  ) : (
                    <span className="text-slate-500 italic">Click 'Sanitize Parameters' to display parsed API inputs.</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={handleSanitizeHpp}
            disabled={isSanitizing}
            className="w-full py-2.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold text-xs rounded-xl transition-all flex items-center justify-center gap-2 shadow-md shadow-purple-900/20"
          >
            {isSanitizing ? <RefreshCw size={14} className="animate-spin" /> : <Layers size={14} />}
            Sanitize Parameters
          </button>
        </div>

      </div>
    </div>
  );
}
