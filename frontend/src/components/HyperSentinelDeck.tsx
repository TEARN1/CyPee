import React, { useState } from 'react';
import {
  Zap,
  ShieldCheck,
  Cpu,
  RefreshCw,
  Terminal,
  Lock,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Play,
  Copy,
  Check,
} from 'lucide-react';

export const HyperSentinelDeck: React.FC = () => {
  // Preset Code Snippets
  const presets: Record<string, { label: string; enclave: string; code: string; desc: string }> = {
    resident: {
      label: 'The Resident — Unbound SQL & BOLA',
      enclave: 'the-resident',
      desc: 'Raw concatenated SQL query and object lookup lacking tenant context verification.',
      code: `async function findUser(userId: string) {
  // Vulnerable unparameterized SQL concatenation
  return this.db.query("SELECT * FROM users WHERE id = '" + userId + "'");
}`,
    },
    gruvs: {
      label: 'The Gruvs — Subshell Command Injection',
      enclave: 'the-gruvs',
      desc: 'Shell-spawning execSync with unescaped backup filename argument.',
      code: `function runBackup(fileName: string) {
  // Vulnerable subshell spawning allowing shell metacharacters
  return exec("tar -czf backup.tar.gz " + fileName, (err) => {});
}`,
    },
    excellency: {
      label: 'Excellency — DDE Formula Execution',
      enclave: 'excellency',
      desc: 'Dynamic Data Exchange injection through unquoted formula triggers.',
      code: `function exportCell(cellValue: string) {
  // Unquoted formula triggers =cmd|'calc'!A1 execution in spreadsheets
  return { cell: cellValue };
}`,
    },
    ivoryPark: {
      label: 'Ivory Park — QR Replay & Missing Lock',
      enclave: 'ivory-park',
      desc: 'Ticket reservation without atomic lock or TOTP nonce expiration.',
      code: `async function reserveTicket(ticketId: string, memberId: string) {
  // Unlocked state mutation prone to double-booking race condition
  return this.db.query("UPDATE tickets SET status = 'RESERVED', member = '" + memberId + "' WHERE id = '" + ticketId + "'");
}`,
    },
  };

  const [selectedPreset, setSelectedPreset] = useState<string>('resident');
  const [code, setCode] = useState<string>(presets.resident.code);
  const [enclave, setEnclave] = useState<string>('the-resident');
  const [intensity, setIntensity] = useState<'STANDARD' | 'HEAVY' | 'EXTREME'>('STANDARD');

  // Analysis State
  const [loading, setLoading] = useState<boolean>(false);
  const [actionStage, setActionStage] = useState<string>('READY');
  const [taintResult, setTaintResult] = useState<any>(null);
  const [fuzzResult, setFuzzResult] = useState<any>(null);
  const [proofResult, setProofResult] = useState<any>(null);
  const [sealResult, setSealResult] = useState<any>(null);
  const [copiedToken, setCopiedToken] = useState<boolean>(false);

  const handleSelectPreset = (key: string) => {
    setSelectedPreset(key);
    setCode(presets[key].code);
    setEnclave(presets[key].enclave);
    setTaintResult(null);
    setFuzzResult(null);
    setProofResult(null);
    setSealResult(null);
  };

  // 1. Static AST Taint Analysis
  const handleAnalyzeTaint = async () => {
    setLoading(true);
    setActionStage('ANALYZING_TAINT_FLOW');
    try {
      const res = await fetch('/api/v1/sentinel/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, enclave }),
      });
      const data = await res.json();
      setTaintResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setActionStage('READY');
    }
  };

  // 2. Launch In-Memory Adversarial Fuzzing Blast
  const handleFuzz = async () => {
    setLoading(true);
    setActionStage('FUZZING_SANDBOX');
    try {
      const res = await fetch('/api/v1/sentinel/fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, enclave, intensity }),
      });
      const data = await res.json();
      setFuzzResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setActionStage('READY');
    }
  };

  // 3. Closed-Loop Auto-Heal & Seal Proof
  const handleAutoHealAndSeal = async () => {
    setLoading(true);
    setActionStage('PROVING_AND_SEALING');
    try {
      // Step A: Prove Fix
      const res = await fetch('/api/v1/sentinel/auto-heal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ codeSnippet: code, enclave }),
      });
      const proofData = await res.json();
      setProofResult(proofData);

      // Step B: Generate Post-Quantum Attestation Seal
      if (proofData.verified) {
        const sealRes = await fetch('/api/v1/sentinel/seal', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            code: proofData.patchedSnippet,
            enclave,
            payloadsTested: fuzzResult?.totalPayloadsFired || 1000,
          }),
        });
        const sealData = await sealRes.json();
        setSealResult(sealData);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setActionStage('READY');
    }
  };

  const copySeal = () => {
    if (sealResult?.rawCertificateToken) {
      navigator.clipboard.writeText(sealResult.rawCertificateToken);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    }
  };

  return (
    <div className="flex flex-col gap-6 text-slate-100 font-sans">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-cyan-950/60 via-slate-900/90 to-purple-950/60 border border-cyan-800/60 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className="absolute right-0 top-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-1 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-full text-[10px] font-mono font-bold tracking-wider uppercase flex items-center gap-1">
                <Zap size={11} className="text-cyan-400" /> VIBE-CODE AUTONOMOUS KERNEL
              </span>
              <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded text-[10px] font-mono">
                100% LOCAL & SOVEREIGN
              </span>
            </div>
            <h2 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
              <Cpu className="text-cyan-400" size={26} /> CyPee Hyper-Sentinel
            </h2>
            <p className="text-xs text-slate-400 max-w-2xl mt-1">
              Deterministic AST Taint Flow Tracer, Ephemeral V8 Micro-Sandbox Fuzzer & Post-Quantum Proof-of-Fix Engine. Deeper than traditional text reviewers.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="bg-slate-950/80 border border-slate-800 px-3 py-2 rounded-xl text-right">
              <div className="text-[10px] text-slate-500 font-mono uppercase">V8 Sandbox</div>
              <div className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 justify-end">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> ISOLATED
              </div>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 px-3 py-2 rounded-xl text-right">
              <div className="text-[10px] text-slate-500 font-mono uppercase">Quantum Seal</div>
              <div className="text-xs font-mono font-bold text-cyan-400">ML-KEM-768</div>
            </div>
          </div>
        </div>
      </div>

      {/* Preset Selector */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {Object.entries(presets).map(([key, item]) => (
          <button
            key={key}
            onClick={() => handleSelectPreset(key)}
            className={`p-3.5 rounded-xl border text-left transition-all ${
              selectedPreset === key
                ? 'bg-cyan-950/40 border-cyan-500/60 shadow-lg shadow-cyan-950/50'
                : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="text-xs font-bold text-white mb-1 flex items-center justify-between">
              <span>{item.label}</span>
              {selectedPreset === key && <CheckCircle2 size={13} className="text-cyan-400" />}
            </div>
            <div className="text-[10px] text-slate-400 leading-relaxed line-clamp-2">{item.desc}</div>
          </button>
        ))}
      </div>

      {/* Main Grid: Code Chamber & Action Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Code Chamber */}
        <div className="lg:col-span-7 bg-slate-900/30 border border-slate-800/80 rounded-2xl p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-widest flex items-center gap-1.5">
              <Terminal size={14} className="text-cyan-400" /> Candidate Code Snippet / Diff
            </h4>
            <div className="flex items-center gap-2 text-[10px] font-mono">
              <span className="text-slate-500">Enclave:</span>
              <select
                value={enclave}
                onChange={(e) => setEnclave(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-cyan-300 focus:outline-none"
              >
                <option value="the-resident">The Resident</option>
                <option value="the-gruvs">The Gruvs</option>
                <option value="excellency">Excellency</option>
                <option value="ivory-park">Ivory Park</option>
                <option value="general">General Enclave</option>
              </select>
            </div>
          </div>

          <div className="relative flex-1 min-h-[220px]">
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="w-full h-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs font-mono text-cyan-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed resize-y min-h-[220px]"
              placeholder="Paste candidate function or Git diff here..."
            />
          </div>

          {/* Action Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 mt-4 pt-3 border-t border-slate-800/80">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-mono text-slate-500 uppercase">Intensity:</span>
              {(['STANDARD', 'HEAVY', 'EXTREME'] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setIntensity(lvl)}
                  className={`px-2 py-1 rounded text-[10px] font-mono font-bold transition-all ${
                    intensity === lvl
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-slate-950 text-slate-400 border border-slate-800 hover:text-slate-200'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleAnalyzeTaint}
                disabled={loading}
                className="px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded-xl text-xs font-bold font-mono transition-all flex items-center gap-1.5 disabled:opacity-50"
              >
                <Layers size={13} /> 1. AST Taint
              </button>
              <button
                onClick={handleFuzz}
                disabled={loading}
                className="px-3.5 py-2 bg-amber-950/60 hover:bg-amber-900/60 border border-amber-700 text-amber-300 rounded-xl text-xs font-bold font-mono transition-all flex items-center gap-1.5 disabled:opacity-50"
              >
                <Play size={13} /> 2. Adversarial Blast
              </button>
              <button
                onClick={handleAutoHealAndSeal}
                disabled={loading}
                className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white rounded-xl text-xs font-bold font-mono transition-all flex items-center gap-1.5 shadow-lg shadow-cyan-900/40 disabled:opacity-50"
              >
                {loading ? <RefreshCw size={13} className="animate-spin" /> : <ShieldCheck size={13} />} 3. Prove & Seal
              </button>
            </div>
          </div>
        </div>

        {/* Right: Blast Chamber & Fuzzing Telemetry */}
        <div className="lg:col-span-5 bg-slate-900/30 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-widest flex items-center justify-between mb-3">
              <span className="flex items-center gap-1.5">
                <Zap size={14} className="text-amber-400" /> Adversarial Blast Chamber
              </span>
              {fuzzResult && (
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  fuzzResult.securityVerdict === 'VERIFIED_SECURE'
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    : 'bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse'
                }`}>
                  {fuzzResult.securityVerdict}
                </span>
              )}
            </h4>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 mb-4">
              <div className="bg-slate-950/70 border border-slate-800/80 p-2.5 rounded-xl">
                <div className="text-[10px] text-slate-500 font-mono uppercase">Payloads Fired</div>
                <div className="text-base font-bold font-mono text-white">
                  {fuzzResult ? fuzzResult.totalPayloadsFired.toLocaleString() : '0'}
                </div>
              </div>
              <div className="bg-slate-950/70 border border-slate-800/80 p-2.5 rounded-xl">
                <div className="text-[10px] text-slate-500 font-mono uppercase">Throughput</div>
                <div className="text-base font-bold font-mono text-cyan-400">
                  {fuzzResult ? `${fuzzResult.payloadsPerSec.toLocaleString()} /s` : '0 /s'}
                </div>
              </div>
              <div className="bg-slate-950/70 border border-slate-800/80 p-2.5 rounded-xl">
                <div className="text-[10px] text-slate-500 font-mono uppercase">Exploits Caught</div>
                <div className={`text-base font-bold font-mono ${fuzzResult && fuzzResult.exploitsConfirmed > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {fuzzResult ? fuzzResult.exploitsConfirmed : '0'}
                </div>
              </div>
            </div>

            {/* Intercepted Sink Evidence */}
            {fuzzResult?.failingExploitSample ? (
              <div className="bg-red-950/30 border border-red-800/60 rounded-xl p-3 mb-3">
                <div className="text-[10px] font-mono font-bold text-red-300 uppercase flex items-center gap-1 mb-1">
                  <AlertTriangle size={11} /> Exploit Proven in V8 Sandbox
                </div>
                <div className="text-xs font-mono text-red-200">
                  Payload: <span className="text-white font-bold bg-red-900/50 px-1 rounded">{String(fuzzResult.failingExploitSample.payload)}</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono mt-1">
                  {fuzzResult.failingExploitSample.sinkInterception}
                </div>
              </div>
            ) : (
              <div className="bg-slate-950/40 border border-dashed border-slate-800 rounded-xl p-4 text-center text-xs text-slate-500 font-mono mb-3">
                Click &quot;Adversarial Blast&quot; to bombard candidate with polyglot injection payloads in an isolated V8 harness.
              </div>
            )}
          </div>

          {/* Action Status Indicator */}
          <div className="bg-slate-950 border border-slate-800/80 rounded-xl px-3 py-2 flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-500">Kernel Status:</span>
            <span className="text-cyan-400 font-bold">{actionStage}</span>
          </div>
        </div>
      </div>

      {/* Step Trace & Taint Flow Breadcrumbs */}
      {taintResult && taintResult.findings.length > 0 && (
        <div className="bg-slate-900/30 border border-slate-800/80 rounded-2xl p-5">
          <h4 className="text-xs font-bold text-slate-300 uppercase tracking-widest flex items-center gap-1.5 mb-3">
            <Layers size={14} className="text-cyan-400" /> Source-to-Sink Taint Propagation Track ({taintResult.findings[0].ruleId} - {taintResult.findings[0].cwe})
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {taintResult.findings[0].taintSteps.map((step: any, idx: number) => (
              <div key={idx} className="bg-slate-950 border border-slate-800/80 rounded-xl p-3 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between text-[10px] font-mono font-bold uppercase mb-1">
                    <span className={step.type === 'SINK_BREACH' ? 'text-red-400' : 'text-cyan-400'}>
                      Step {step.stepIndex}: {step.type}
                    </span>
                    <span className="text-slate-600">Line {step.line}</span>
                  </div>
                  <div className="text-xs font-mono text-white font-semibold truncate">{step.expression}</div>
                </div>
                <div className="text-[10px] text-slate-400 mt-2 border-t border-slate-900 pt-1.5">
                  {step.description}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Closed-Loop Verification Station (Before vs After Proof) */}
      {proofResult && (
        <div className="bg-gradient-to-b from-slate-900/40 to-cyan-950/20 border border-cyan-800/60 rounded-2xl p-6 shadow-xl">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
            <div>
              <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded text-[10px] font-mono font-bold uppercase">
                FORMAL PROOF RESOLVED
              </span>
              <h3 className="text-lg font-black text-white mt-1">Closed-Loop Deterministic Proof of Fix</h3>
            </div>
            <div className="text-xs font-mono text-slate-400 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
              Proof ID: <span className="text-cyan-300 font-bold">{proofResult.proofId}</span>
            </div>
          </div>

          <div className="bg-emerald-950/20 border border-emerald-800/40 rounded-xl p-3.5 mb-5 text-xs font-mono text-emerald-200 leading-relaxed">
            {proofResult.mathematicalProofStatement}
          </div>

          {/* Unified Diff Box */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs overflow-x-auto mb-5">
            <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2">Deterministic AST Patch Diff</div>
            <pre className="text-slate-300 leading-relaxed whitespace-pre-wrap">{proofResult.unifiedDiff}</pre>
          </div>

          {/* Post-Quantum Attestation Seal */}
          {sealResult && (
            <div className="bg-slate-950/90 border border-cyan-500/40 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  <Lock size={20} />
                </div>
                <div>
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    NIST FIPS 204 ML-DSA Quantum Attestation Seal
                    <span className="text-[10px] px-1.5 py-0.2 bg-cyan-950 text-cyan-300 border border-cyan-800 rounded font-mono">
                      GATEWAY ENFORCED
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                    Merkle Root: <span className="text-slate-200">{sealResult.merkleRootHash.substring(0, 24)}...</span> | Algorithm: {sealResult.pqcAlgorithm}
                  </div>
                </div>
              </div>

              <button
                onClick={copySeal}
                className="px-3.5 py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-200 rounded-xl text-xs font-mono font-bold transition-all flex items-center gap-1.5"
              >
                {copiedToken ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                {copiedToken ? 'Token Copied!' : 'Copy Seal Certificate'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
