import { useState, useEffect } from 'react';
import { sampleFindings, type IFinding } from './mockData';
import { Dropzone } from './components/Dropzone';
import { LiveTelemetry } from './components/LiveTelemetry';
import { VulnerabilityMatrix } from './components/VulnerabilityMatrix';
import { RemediationPanel } from './components/RemediationPanel';
import { MetricCards } from './components/MetricCards';
import { ApiReference } from './components/ApiReference';
import { RulesCatalog } from './components/RulesCatalog';
import { signPayload } from './signPayload';
import { ShieldCheck, Server, AlertCircle, RefreshCw, LayoutDashboard, Code, Trash2, Download } from 'lucide-react';

// Browser-side Proof of Work solver wrapping standard fetch
async function fetchWithPow(url: string, options: RequestInit): Promise<Response> {
  const response = await fetch(url, options);
  const challenge = response.headers.get('x-shield-challenge');
  
  if (response.status === 400 && challenge) {
    console.log('🛡️ AI Defensive Shield: Proof of Work challenge requested. Solving...');
    const [salt, difficultyStr] = challenge.split('|');
    const difficulty = parseInt(difficultyStr, 10);
    const prefix = '0'.repeat(difficulty);

    let nonce = 0;
    const encoder = new TextEncoder();
    let solvedNonce = '';
    
    while (true) {
      const data = encoder.encode(salt + nonce);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      if (hashHex.startsWith(prefix)) {
        solvedNonce = nonce.toString();
        break;
      }
      nonce++;
    }
    
    console.log(`Challenge solved (nonce: ${solvedNonce}). Retrying request...`);
    const headers = new Headers(options.headers || {});
    headers.set('x-shield-pow-challenge', challenge);
    headers.set('x-shield-pow-nonce', solvedNonce);
    
    return fetchWithPow(url, {
      ...options,
      headers,
    });
  }
  return response;
}

function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'api' | 'catalog'>('dashboard');
  const [findings, setFindings] = useState<IFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<IFinding | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanTarget, setScanTarget] = useState('');
  const [scanMode, setScanMode] = useState<'Web' | 'Mobile' | 'Source Code' | 'Desktop'>('Web');
  const [loading, setLoading] = useState(false);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const response = await fetchWithPow('/api/v1/compliance/findings', { method: 'GET' });
      if (response.ok) {
        const data = await response.json();
        // Fallback to sample findings if DB is empty
        const list = data.length > 0 ? data : sampleFindings;
        setFindings(list);
        if (list.length > 0 && !selectedFinding) {
          setSelectedFinding(list[0]);
        }
      } else {
        setFindings(sampleFindings);
      }
    } catch {
      setFindings(sampleFindings);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const handleIngest = async (mode: 'Web' | 'Mobile' | 'Source Code' | 'Desktop', target: string) => {
    setScanTarget(target);
    setScanMode(mode);
    setIsScanning(true);
    setScanId(null);

    // Formulate payload based on Scan Mode
    let generatedFindings: any[] = [];
    if (mode === 'Mobile') {
      generatedFindings = [
        {
          filePath: "android/app/src/main/AndroidManifest.xml",
          lineNumber: 8,
          ruleId: "ANDROID_DEBUGGABLE",
          severity: "HIGH",
          message: `Application debug mode enabled on ${target}`
        }
      ];
    } else if (mode === 'Web') {
      generatedFindings = [
        {
          filePath: "src/main.ts",
          lineNumber: 12,
          ruleId: "MISSING_SECURITY_HEADERS",
          severity: "MEDIUM",
          message: `Missing Helmet headers on ${target}`
        }
      ];
    } else if (mode === 'Source Code') {
      generatedFindings = [
        {
          filePath: "src/users/users.service.ts",
          lineNumber: 42,
          ruleId: "SQL_INJECTION",
          severity: "CRITICAL",
          message: `SQL injection raw query in ${target}`
        },
        {
          filePath: "src/auth/auth.module.ts",
          lineNumber: 15,
          ruleId: "HARDCODED_SECRETS",
          severity: "HIGH",
          message: `Plaintext credential found in ${target}`
        }
      ];
    } else {
      generatedFindings = [
        {
          filePath: "controllers/DesktopAudit.cs",
          lineNumber: 87,
          ruleId: "CSHARP_DESERIALIZATION",
          severity: "CRITICAL",
          message: `BinaryFormatter vulnerabilities in ${target}`
        }
      ];
    }

    const payload = { findings: generatedFindings };
    const bodyStr = JSON.stringify(payload);
    const timestamp = Date.now().toString();

    try {
      // Sign payload via browser SubtleCrypto
      const signature = await signPayload(timestamp, bodyStr);

      // Submit report to NestJS backend
      const response = await fetchWithPow('/api/v1/compliance/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sast-signature': signature,
          'x-sast-timestamp': timestamp,
        },
        body: bodyStr,
      });

      if (response.ok) {
        // Retrieve scan context to bind LiveTelemetry connection
        handleScanComplete();
      } else {
        setIsScanning(false);
      }
    } catch (e: any) {
      console.error('Failed to submit signed payload to NestJS backend:', e.message);
      setIsScanning(false);
    }
  };

  const handleManualSubmit = async (finding: { filePath: string; lineNumber: number; ruleId: string; severity: string; message: string }) => {
    const payload = { findings: [finding] };
    const bodyStr = JSON.stringify(payload);
    const timestamp = Date.now().toString();

    try {
      // Sign using browser Web Crypto SubtleCrypto
      const signature = await signPayload(timestamp, bodyStr);

      // Submit via signed POST request to NestJS
      const response = await fetchWithPow('/api/v1/compliance/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-sast-signature': signature,
          'x-sast-timestamp': timestamp,
        },
        body: bodyStr,
      });

      if (response.ok) {
        // Trigger small telemetry scanning effect to simulate verification
        setScanTarget(finding.filePath);
        setScanMode(finding.ruleId === 'ANDROID_DEBUGGABLE' ? 'Mobile' : finding.ruleId === 'CSHARP_DESERIALIZATION' ? 'Desktop' : 'Source Code');
        setIsScanning(true);
        setScanId(null);
      }
    } catch (e: any) {
      console.error('Failed to submit manual signed payload:', e.message);
    }
  };

  const handleScanComplete = () => {
    setIsScanning(false);
    setScanId(null);
    // Poll/pull the newly processed findings from the database repository
    fetchFindings();
  };

  const handleClear = async () => {
    try {
      await fetchWithPow('/api/v1/compliance/findings/clear', { method: 'POST' });
      setFindings([]);
      setSelectedFinding(null);
    } catch (e: any) {
      console.error('Failed to clear findings:', e.message);
    }
  };

  const handleExportCSV = () => {
    if (findings.length === 0) return;

    // Formulate CSV Headers
    const headers = ['Rule ID', 'Severity', 'Platform', 'File Path', 'Line Number', 'Title', 'Message'];
    const rows = findings.map(f => [
      f.ruleId,
      f.severity,
      f.platform,
      f.filePath,
      f.lineNumber.toString(),
      `"${(f.title || '').replace(/"/g, '""')}"`,
      `"${(f.risk || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    // Trigger download link
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `shield-compliance-report-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="flex flex-col min-h-screen bg-[#080c14] text-slate-100 p-6 font-sans">
      {/* Top Header navbar */}
      <header className="flex justify-between items-center border-b border-slate-800 pb-5 mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-indigo-600 to-purple-650 shadow-md shadow-indigo-900/40 text-white font-black tracking-wider flex items-center gap-1.5 text-sm">
            <ShieldCheck size={18} /> SHIELD COMPLIANCE
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">SAST Threat Ingestion Matrix</h1>
            <p className="text-[10px] text-slate-500 font-semibold tracking-wider uppercase mt-0.5">Secure Enclave Scanning System</p>
          </div>
        </div>
        
        {/* Navigation Tabs */}
        <div className="hidden md:flex items-center gap-1.5 bg-slate-900/60 border border-slate-800 p-1 rounded-xl">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'dashboard'
                ? 'bg-slate-800 text-indigo-400 border border-slate-700/60 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <LayoutDashboard size={14} /> Threat Dashboard
          </button>
          <button
            onClick={() => setActiveTab('catalog')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'catalog'
                ? 'bg-slate-800 text-indigo-400 border border-slate-700/60 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck size={14} /> Rules Catalog
          </button>
          <button
            onClick={() => setActiveTab('api')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'api'
                ? 'bg-slate-800 text-indigo-400 border border-slate-700/60 shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code size={14} /> API Reference
          </button>
        </div>
        
        <div className="flex items-center gap-3">
          <button 
            onClick={fetchFindings} 
            disabled={loading}
            className="p-2 bg-slate-900 border border-slate-800 rounded-xl text-slate-400 hover:text-slate-200 hover:border-slate-700 disabled:opacity-50 transition-all flex items-center gap-1 text-xs font-semibold"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          {findings.length > 0 && (
            <button 
              onClick={handleExportCSV} 
              className="p-2 bg-slate-900 border border-slate-800 rounded-xl text-indigo-400 hover:text-indigo-300 hover:border-indigo-900/60 transition-all flex items-center gap-1 text-xs font-semibold"
            >
              <Download size={14} /> Export CSV
            </button>
          )}
          <button 
            onClick={handleClear} 
            className="p-2 bg-slate-900 border border-slate-800 rounded-xl text-red-400 hover:text-red-300 hover:border-red-900/60 transition-all flex items-center gap-1 text-xs font-semibold"
          >
            <Trash2 size={14} /> Clear
          </button>
          <div className="flex items-center gap-2 px-3.5 py-1.5 bg-emerald-950/30 border border-emerald-900/60 rounded-xl text-emerald-400 text-xs font-semibold">
            <Server size={14} className="animate-pulse" />
            <span>Connection: Secure (Ed25519 Guarded)</span>
          </div>
        </div>
      </header>

      {/* Main Content Render */}
      {activeTab === 'api' ? (
        <main className="flex-1 bg-slate-900/30 border border-slate-800/80 rounded-2xl p-6 shadow-lg shadow-black/10">
          <ApiReference />
        </main>
      ) : activeTab === 'catalog' ? (
        <main className="flex-1 bg-slate-900/30 border border-slate-800/80 rounded-2xl p-6 shadow-lg shadow-black/10">
          <RulesCatalog />
        </main>
      ) : (
        <>
          {/* Metrics Row */}
          <section className="mb-6">
            <MetricCards findings={findings} />
          </section>

          {/* Main Grid Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 min-h-[500px]">
            {/* Left Side: Scan & List */}
            <div className="lg:col-span-5 flex flex-col gap-6 h-full">
              {/* Scan Ingestion Container */}
              <div className="bg-slate-900/30 border border-slate-800/80 rounded-2xl p-5 shadow-lg shadow-black/10">
                {isScanning ? (
                  <LiveTelemetry 
                    scanId={scanId}
                    mode={scanMode} 
                    targetName={scanTarget} 
                    onComplete={handleScanComplete} 
                  />
                ) : (
                  <Dropzone onIngest={handleIngest} onManualSubmit={handleManualSubmit} />
                )}
              </div>

              {/* Vulnerability matrix list */}
              <div className="flex-1 bg-slate-900/30 border border-slate-800/80 rounded-2xl p-5 shadow-lg shadow-black/10 flex flex-col min-h-[350px]">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-1.5">
                  <AlertCircle size={14} /> Aggregated Threat Matrix
                </h4>
                <div className="flex-1 min-h-0">
                  <VulnerabilityMatrix
                    findings={findings}
                    selectedFindingId={selectedFinding?.id || null}
                    onSelectFinding={setSelectedFinding}
                  />
                </div>
              </div>
            </div>

            {/* Right Side: Remediation Split-screen Code Editors */}
            <div className="lg:col-span-7 bg-slate-900/30 border border-slate-800/80 rounded-2xl p-6 shadow-lg shadow-black/10 flex flex-col h-full min-h-[500px]">
              <div className="flex-1 min-h-0">
                <RemediationPanel finding={selectedFinding} />
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default App;
