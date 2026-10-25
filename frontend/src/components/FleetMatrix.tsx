import { useState, useEffect } from 'react';
import { Shield, Server, Lock, RefreshCw, CheckCircle, Flame, ShieldAlert, Cpu, Zap, Radio, Key, Database, HardDrive, Network } from 'lucide-react';

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

interface SovereignStatus {
  tier: string;
  frontiers: {
    kmsVaultCustody: { status: string; provider: string; activeKeyVersion: string; zeroDowntimeRotationReady: boolean };
    databaseKernelRls: { status: string; supportedEngines: string[]; enforcementLevel: string; migrationFile: string };
    storageAtRestAttestation: { status: string; grade: string; attestationHash: string; tempStoreInMemory: boolean };
    mtlsWorkloadMesh: { status: string; guard: string; spiffeNamespace: string; enclavesCovered: string[] };
  };
}

interface BreachStatus {
  defconLevel: string;
  totalTarpittedIps: number;
  totalBlacklistedIps: number;
  tarpittedIps: string[];
  blacklistedIps: string[];
  countermeasuresReady: string[];
}

export function FleetMatrix() {
  const [fleet, setFleet] = useState<FleetEntity[]>([]);
  const [globalScore, setGlobalScore] = useState<number>(93);
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [sovereign, setSovereign] = useState<SovereignStatus | null>(null);
  const [breachStatus, setBreachStatus] = useState<BreachStatus | null>(null);
  const [drillRunning, setDrillRunning] = useState(false);

  const fetchFleet = async () => {
    setLoading(true);
    try {
      const [resFleet, resSovereign, resBreach] = await Promise.all([
        fetch('/api/v1/shield/fleet/posture'),
        fetch('/api/v1/shield/breach/sovereign-status'),
        fetch('/api/v1/shield/breach/status'),
      ]);

      if (resFleet.ok) {
        const data = await resFleet.json();
        setFleet(data.fleet);
        setGlobalScore(data.globalPostureScore);
      }
      if (resSovereign.ok) {
        const sovData = await resSovereign.json();
        setSovereign(sovData);
      }
      if (resBreach.ok) {
        const breachData = await resBreach.json();
        setBreachStatus(breachData);
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

  const handleBreachDrill = async () => {
    setDrillRunning(true);
    try {
      const res = await fetch('/api/v1/shield/breach/trigger-drill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetApp: 'the-gruvs', attackerIp: '198.51.100.89' }),
      });
      if (res.ok) {
        await res.json();
        setActionMessage(`🚨 Simulated Breach Repelled! Tarpit deployed on 198.51.100.89. The Gruvs quarantined. Evidence frozen.`);
        fetchFleet();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setDrillRunning(false);
    }
  };

  const handleResetDefcon = async () => {
    try {
      const res = await fetch('/api/v1/shield/breach/reset-defcon', { method: 'POST' });
      if (res.ok) {
        setActionMessage(`DEFCON restored to DEFCON_5_NORMAL. Threat neutralized.`);
        fetchFleet();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleCryptoShred = async () => {
    if (!confirm('WARNING: Emergency Crypto-Shred will scrub encryption keys from memory. Decryption will halt until admin key reload. Proceed?')) {
      return;
    }
    try {
      const res = await fetch('/api/v1/shield/breach/crypto-shred', { method: 'POST' });
      if (res.ok) {
        setActionMessage('🚨 Master keys purged from RAM. Database vault is cryptographically locked.');
        fetchFleet();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const isDefcon1 = breachStatus?.defconLevel === 'DEFCON_1_BREACH_LOCKDOWN';

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

      {/* 4 Sovereign Tier-4 Pillars Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="bg-slate-950/70 border border-slate-800/90 rounded-xl p-3.5 flex items-start gap-3">
          <div className="p-2 bg-indigo-950/60 border border-indigo-800/80 rounded-lg text-indigo-400">
            <Key size={16} />
          </div>
          <div>
            <span className="text-[10px] text-slate-500 font-mono block uppercase">KMS Key Custody</span>
            <span className="text-xs font-bold text-slate-200">AES-256-GCM Envelope</span>
            <span className="text-[9px] text-emerald-400 font-mono block mt-0.5">● Multi-Key Rotation Ready</span>
          </div>
        </div>

        <div className="bg-slate-950/70 border border-slate-800/90 rounded-xl p-3.5 flex items-start gap-3">
          <div className="p-2 bg-emerald-950/60 border border-emerald-800/80 rounded-lg text-emerald-400">
            <Database size={16} />
          </div>
          <div>
            <span className="text-[10px] text-slate-500 font-mono block uppercase">Database Kernel RLS</span>
            <span className="text-xs font-bold text-slate-200">Postgres 14+ Policies</span>
            <span className="text-[9px] text-cyan-400 font-mono block mt-0.5">● Kernel-Enforced Boundaries</span>
          </div>
        </div>

        <div className="bg-slate-950/70 border border-slate-800/90 rounded-xl p-3.5 flex items-start gap-3">
          <div className="p-2 bg-purple-950/60 border border-purple-800/80 rounded-lg text-purple-400">
            <HardDrive size={16} />
          </div>
          <div>
            <span className="text-[10px] text-slate-500 font-mono block uppercase">Storage Attestation</span>
            <span className="text-xs font-bold text-slate-200">{sovereign?.frontiers.storageAtRestAttestation.grade || 'SOVEREIGN_ENCRYPTED'}</span>
            <span className="text-[9px] text-emerald-400 font-mono block mt-0.5">● In-Memory Temp Store</span>
          </div>
        </div>

        <div className="bg-slate-950/70 border border-slate-800/90 rounded-xl p-3.5 flex items-start gap-3">
          <div className="p-2 bg-cyan-950/60 border border-cyan-800/80 rounded-lg text-cyan-400">
            <Network size={16} />
          </div>
          <div>
            <span className="text-[10px] text-slate-500 font-mono block uppercase">mTLS Workload Mesh</span>
            <span className="text-xs font-bold text-slate-200">SPIFFE Identity Proof</span>
            <span className="text-[9px] text-emerald-400 font-mono block mt-0.5">● 4 Enclaves Bound</span>
          </div>
        </div>
      </div>

      {/* Active Breach Response & Countermeasures Command Center */}
      <div className={`rounded-2xl border p-5 transition-all ${
        isDefcon1 ? 'bg-red-950/30 border-red-800 shadow-2xl shadow-red-950/40' : 'bg-slate-950/80 border-slate-800'
      }`}>
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${isDefcon1 ? 'bg-red-900/60 border-red-700 text-red-300 animate-bounce' : 'bg-slate-900 border-slate-800 text-cyan-400'}`}>
              <Zap size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-black text-white uppercase tracking-wider">
                  Active Breach Defense & Countermeasures ("Fight Back" Protocol)
                </h3>
                <span className={`text-[10px] font-black px-2 py-0.5 rounded font-mono ${
                  isDefcon1 ? 'bg-red-600 text-white animate-pulse' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}>
                  {breachStatus?.defconLevel || 'DEFCON_5_NORMAL'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Automated four-phase containment, Slowloris tarpitting, disinformation injection, and cryptographic memory shredding.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleBreachDrill}
              disabled={drillRunning}
              className="px-3 py-2 bg-red-950/60 hover:bg-red-900/80 border border-red-800/80 text-red-200 font-bold text-xs rounded-xl transition-all flex items-center gap-1.5"
            >
              <Radio size={14} className={drillRunning ? 'animate-spin' : ''} />
              Simulate Breach Drill
            </button>

            <button
              onClick={handleCryptoShred}
              className="px-3 py-2 bg-slate-900 hover:bg-red-950/40 border border-slate-800 hover:border-red-800 text-slate-300 hover:text-red-300 font-bold text-xs rounded-xl transition-all"
              title="Purge master keys from RAM"
            >
              Crypto-Shred
            </button>

            {isDefcon1 && (
              <button
                onClick={handleResetDefcon}
                className="px-3 py-2 bg-emerald-700 hover:bg-emerald-600 text-white font-bold text-xs rounded-xl transition-all"
              >
                Reset DEFCON
              </button>
            )}
          </div>
        </div>

        {/* Countermeasures Live Readout */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 text-xs">
          <div className="bg-slate-900/60 border border-slate-800/70 rounded-xl p-3">
            <span className="text-[10px] text-slate-500 font-mono uppercase block">Active Tarpits (Slowloris Friction)</span>
            <span className="text-base font-black text-amber-400">{breachStatus?.totalTarpittedIps || 0} IPs Trapped</span>
            <p className="text-[10px] text-slate-400 mt-1">Holding attacker sockets open at 1 byte/2s</p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/70 rounded-xl p-3">
            <span className="text-[10px] text-slate-500 font-mono uppercase block">Edge Firewall Blacklist</span>
            <span className="text-base font-black text-red-400">{breachStatus?.totalBlacklistedIps || 0} IPs Dropped</span>
            <p className="text-[10px] text-slate-400 mt-1">Direct kernel/gateway block on malicious origins</p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/70 rounded-xl p-3">
            <span className="text-[10px] text-slate-500 font-mono uppercase block">Ghost Canary Disinformation</span>
            <span className="text-base font-black text-cyan-400">Active</span>
            <p className="text-[10px] text-slate-400 mt-1">Injecting poisoned credentials to trace threat groups</p>
          </div>
        </div>
      </div>

      {/* 4 Enclave Cards Grid */}
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
            <strong className="text-white block font-bold">Continuous Fleet Scanning & Active Countermeasures Active</strong>
            CyPee's SAST/DAST engine continuously safeguards V-Gruvs, The Resident, The Gruvs, and Excellency against container escapes, BOLA/IDOR, formula injection, and database tampering.
          </div>
        </div>
        <div className="text-[10px] font-mono text-slate-500 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 shrink-0">
          Enclave Protocol: Ed25519-HMAC-v11
        </div>
      </div>
    </div>
  );
}
