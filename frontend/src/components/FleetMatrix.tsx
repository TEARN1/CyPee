import { useState, useEffect } from 'react';
import { Shield, Server, Lock, RefreshCw, CheckCircle, Flame, ShieldAlert, Cpu } from 'lucide-react';

interface FleetEntity {
  id: string;
  name: string;
  role: 'HOST_PLATFORM' | 'APPLICATION';
  url: string;
  status: 'ONLINE' | 'QUARANTINED' | 'DEGRADED';
  postureScore: number;
  isolationLevel: string;
  attestationHash: string;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  lastAttested: string;
  activeDefenses: string[];
}

export function FleetMatrix() {
  const [fleet, setFleet] = useState<FleetEntity[]>([]);
  const [globalScore, setGlobalScore] = useState<number>(93);
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchFleet = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/shield/fleet/posture');
      if (res.ok) {
        const data = await res.json();
        setFleet(data.fleet);
        setGlobalScore(data.globalPostureScore);
      }
    } catch (e) {
      console.error('Failed to fetch fleet posture:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFleet();
  }, []);

  const handleQuarantine = async (id: string, name: string) => {
    try {
      const res = await fetch('/api/v1/shield/fleet/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, reason: `Admin triggered emergency isolation on ${name}` }),
      });
      if (res.ok) {
        setActionMessage(`Emergency Quarantine active: ${name} is isolated from the network.`);
        fetchFleet();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleRestore = async (id: string, name: string) => {
    try {
      const res = await fetch('/api/v1/shield/fleet/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      if (res.ok) {
        setActionMessage(`Remediation verified: ${name} restored to ONLINE status.`);
        fetchFleet();
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-950/60 border border-slate-800/80 rounded-2xl p-6 shadow-xl">
        <div>
          <div className="flex items-center gap-2.5">
            <Shield className="text-cyan-400 animate-pulse" size={24} />
            <h2 className="text-xl font-black tracking-tight text-white">
              Sovereign Enclave & Fleet Defense Matrix
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Bi-directional defense for <strong className="text-cyan-300">V-Gruvs (Host Platform)</strong> and your 3 applications: <strong className="text-slate-200">The Resident</strong>, <strong className="text-slate-200">The Gruvs</strong>, and <strong className="text-slate-200">Excellency</strong>.
          </p>
        </div>

        <div className="flex items-center gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-2 text-center">
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest block">Global Posture</span>
            <span className="text-xl font-black text-cyan-400">{globalScore}/100</span>
          </div>

          <button
            onClick={fetchFleet}
            disabled={loading}
            className="p-2.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-slate-300 hover:text-white transition-all"
            title="Refresh Fleet Status"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="p-3.5 bg-cyan-950/30 border border-cyan-800/60 rounded-xl text-xs text-cyan-300 flex items-center justify-between">
          <span className="flex items-center gap-2"><CheckCircle size={15} /> {actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-slate-500 hover:text-slate-300">✕</button>
        </div>
      )}

      {/* 4 Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {fleet.map((entity) => {
          const isHost = entity.role === 'HOST_PLATFORM';
          const isQuarantined = entity.status === 'QUARANTINED';

          return (
            <div
              key={entity.id}
              className={`rounded-2xl border p-5 transition-all flex flex-col justify-between ${
                isQuarantined
                  ? 'bg-red-950/20 border-red-900/60 shadow-lg shadow-red-950/20'
                  : isHost
                  ? 'bg-gradient-to-br from-slate-950/90 to-blue-950/20 border-cyan-900/50 shadow-lg shadow-cyan-950/20'
                  : 'bg-slate-950/50 border-slate-800/80 shadow-md'
              }`}
            >
              <div>
                {/* Header */}
                <div className="flex justify-between items-start gap-2">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-2 rounded-xl border ${
                      isHost ? 'bg-cyan-950/50 border-cyan-800 text-cyan-300' : 'bg-slate-900 border-slate-800 text-slate-300'
                    }`}>
                      {isHost ? <Server size={18} /> : <Cpu size={18} />}
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        {entity.name}
                        {isHost && (
                          <span className="text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded font-mono uppercase">
                            Host Enclave
                          </span>
                        )}
                      </h3>
                      <p className="text-[10px] text-slate-500 font-mono">{entity.url}</p>
                    </div>
                  </div>

                  <span className={`text-[10px] font-mono font-black px-2 py-0.5 rounded border ${
                    isQuarantined
                      ? 'bg-red-950/50 text-red-400 border-red-900'
                      : 'bg-emerald-950/50 text-emerald-400 border-emerald-900'
                  }`}>
                    {entity.status}
                  </span>
                </div>

                {/* Score & Isolation Mode */}
                <div className="grid grid-cols-2 gap-2 mt-4 pt-3 border-t border-slate-900">
                  <div className="bg-slate-900/60 border border-slate-800/60 rounded-lg p-2">
                    <span className="text-[9px] text-slate-500 block uppercase font-mono">Posture Score</span>
                    <span className="text-sm font-black text-white">{entity.postureScore}%</span>
                  </div>
                  <div className="bg-slate-900/60 border border-slate-800/60 rounded-lg p-2">
                    <span className="text-[9px] text-slate-500 block uppercase font-mono">Isolation Level</span>
                    <span className="text-[10px] font-bold text-cyan-300 truncate block">{entity.isolationLevel}</span>
                  </div>
                </div>

                {/* Active Defense Rules */}
                <div className="mt-4">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-1.5 flex items-center gap-1.5">
                    <Lock size={12} className="text-cyan-400" /> Active Security Controls
                  </span>
                  <div className="grid grid-cols-2 gap-1.5">
                    {entity.activeDefenses.map((def, idx) => (
                      <span key={idx} className="text-[10px] text-slate-300 bg-slate-900 border border-slate-800/80 px-2 py-1 rounded-md font-mono flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                        <span className="truncate">{def}</span>
                      </span>
                    ))}
                  </div>
                </div>

                {/* Attestation Stamp */}
                <div className="mt-4 pt-3 border-t border-slate-900 text-[9px] font-mono text-slate-500 flex justify-between items-center">
                  <span className="truncate max-w-[200px]" title={entity.attestationHash}>
                    Attestation: {entity.attestationHash.substring(0, 18)}...
                  </span>
                  <span>{new Date(entity.lastAttested).toLocaleTimeString()}</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="mt-5 pt-3 border-t border-slate-900 flex gap-2">
                {isQuarantined ? (
                  <button
                    onClick={() => handleRestore(entity.id, entity.name)}
                    className="w-full py-2 bg-emerald-700 hover:bg-emerald-600 text-white font-bold text-xs rounded-xl transition-all flex items-center justify-center gap-1.5"
                  >
                    <CheckCircle size={14} /> Restore to Mesh
                  </button>
                ) : (
                  <button
                    onClick={() => handleQuarantine(entity.id, entity.name)}
                    className="w-full py-2 bg-slate-900 hover:bg-red-950/50 hover:border-red-900/60 border border-slate-800 text-slate-400 hover:text-red-300 font-bold text-xs rounded-xl transition-all flex items-center justify-center gap-1.5"
                  >
                    <ShieldAlert size={14} /> Emergency Quarantine
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Bottom Explainer / Architecture Callout */}
      <div className="bg-slate-950/40 border border-slate-800 rounded-2xl p-5 text-xs text-slate-400 flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
        <div className="flex items-center gap-3">
          <Flame size={20} className="text-amber-400 shrink-0" />
          <div>
            <strong className="text-white block font-bold">Continuous Fleet Scanning Active</strong>
            CyPee's SAST scanner automatically inspects V-Gruvs, The Resident, The Gruvs, and Excellency for container escapes, BOLA/IDOR, formula injection, and race conditions.
          </div>
        </div>
        <div className="text-[10px] font-mono text-slate-500 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 shrink-0">
          Enclave Protocol: Ed25519-HMAC-v11
        </div>
      </div>
    </div>
  );
}
