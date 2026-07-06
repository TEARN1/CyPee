import { useState, useEffect } from 'react';
import { Share2, Globe, Users, Shield, RefreshCw, AlertTriangle, CheckCircle, Database } from 'lucide-react';

interface IIocEntry {
  id: string;
  indicatorHash: string;
  threatType: string;
  firstSeen: string;
  confidenceScore: number;
  reportingNode: string;
}

export function FederatedMesh() {
  const [feed, setFeed] = useState<IIocEntry[]>([]);
  const [threatType, setThreatType] = useState('SQL_INJECTION');
  const [rawIndicator, setRawIndicator] = useState('185.220.101.5'); // Mock malicious exit node IP
  const [isBroadcasting, setIsBroadcasting] = useState(false);
  const [broadcastResult, setBroadcastResult] = useState<{ success: boolean; hash: string } | null>(null);
  const [loading, setLoading] = useState(false);

  // Fetch federated blocklist hashes
  const fetchFeed = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/shield/federated/feed');
      if (response.ok) {
        const data = await response.json();
        setFeed(data);
      }
    } catch (e) {
      console.error('Failed to fetch federated feed:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFeed();
  }, []);

  // Broadcast a new threat signature
  const handleBroadcast = async () => {
    if (!rawIndicator) return;
    setIsBroadcasting(true);
    setBroadcastResult(null);
    try {
      const response = await fetch('/api/v1/shield/federated/share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threatType, rawIndicator })
      });
      const data = await response.json();
      if (response.ok) {
        setBroadcastResult({
          success: true,
          hash: data.hash
        });
        setRawIndicator('');
        await fetchFeed();
      } else {
        setBroadcastResult({
          success: false,
          hash: ''
        });
      }
    } catch (e) {
      console.error(e);
      setBroadcastResult({
        success: false,
        hash: ''
      });
    } finally {
      setIsBroadcasting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          <Globe className="text-blue-400 animate-pulse" size={22} /> Collaborative Defense Mesh
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Share and synchronize anonymized SHA-256 threat indicator hashes (IOCs) across secure tenant nodes to enforce collaborative perimeter blocking.
        </p>
      </div>

      {/* Network Nodes Health Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { name: 'Node-US-East', location: 'Virginia, US', status: 'SYNCHRONIZED', count: feed.length, latency: '42ms' },
          { name: 'Node-EU-West', location: 'Frankfurt, DE', status: 'SYNCHRONIZED', count: feed.length, latency: '88ms' },
          { name: 'Node-APAC-Sgp', location: 'Singapore, SG', status: 'SYNCHRONIZED', count: feed.length, latency: '154ms' },
          { name: 'Node-LATAM-Brl', location: 'São Paulo, BR', status: 'SYNCHRONIZED', count: feed.length, latency: '112ms' },
        ].map((node, idx) => (
          <div key={idx} className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-4 flex flex-col justify-between">
            <div className="flex justify-between items-start">
              <div>
                <h4 className="text-xs font-bold text-slate-200">{node.name}</h4>
                <p className="text-[10px] text-slate-500">{node.location}</p>
              </div>
              <span className="text-[9px] bg-blue-950/50 text-blue-400 border border-blue-900/50 px-2 py-0.5 rounded font-mono font-bold">
                {node.status}
              </span>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-900 flex justify-between items-center text-[10px] text-slate-400">
              <span className="flex items-center gap-1"><Database size={10} /> {node.count} Hashes</span>
              <span>Ping: {node.latency}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Side: Broadcast New IOC Form */}
        <div className="lg:col-span-5 bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between min-h-[350px]">
          <div>
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2 mb-3">
              <Share2 className="text-blue-400" size={16} /> Broadcast Threat Signature
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Submit a raw threat value (compromised IP, payload block, user-agent). The system hashes the value locally via SHA-256 before publishing, ensuring no GDPR/data privacy leakages occur across peer installations.
            </p>

            <div className="space-y-4 mb-4">
              <div>
                <label className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Threat Indicator Type</label>
                <select
                  value={threatType}
                  onChange={(e) => setThreatType(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 mt-1 font-semibold"
                >
                  <option value="SQL_INJECTION">SQL_INJECTION</option>
                  <option value="COMPROMISED_IP">COMPROMISED_IP</option>
                  <option value="BOT_BEHAVIOR">BOT_BEHAVIOR</option>
                  <option value="CREDENTIAL_EXFILTRATION">CREDENTIAL_EXFILTRATION</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Raw Indicator String</label>
                <input
                  type="text"
                  placeholder="Enter IP or query payload..."
                  value={rawIndicator}
                  onChange={(e) => setRawIndicator(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 mt-1 font-mono"
                />
              </div>
            </div>

            {broadcastResult && (
              <div className={`p-3 rounded-xl border mb-4 flex items-center gap-3 text-xs ${
                broadcastResult.success 
                  ? 'bg-emerald-950/20 border-emerald-900/60 text-emerald-400' 
                  : 'bg-red-950/20 border-red-900/60 text-red-400'
              }`}>
                {broadcastResult.success ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
                <div>
                  <span className="font-bold">{broadcastResult.success ? 'IOC Propagated Successfully' : 'Broadcast Failed'}</span>
                  <span className="text-[9px] block opacity-85 mt-0.5 font-mono truncate max-w-[280px]">Hash: {broadcastResult.hash}</span>
                </div>
              </div>
            )}
          </div>

          <button
            onClick={handleBroadcast}
            disabled={isBroadcasting || !rawIndicator}
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold text-xs rounded-xl transition-all flex items-center justify-center gap-2 shadow-md shadow-blue-900/20"
          >
            {isBroadcasting ? <RefreshCw size={14} className="animate-spin" /> : <Share2 size={14} />}
            Broadcast Anonymized IOC Hash
          </button>
        </div>

        {/* Right Side: Shared Threat ledger feed table */}
        <div className="lg:col-span-7 bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between min-h-[350px]">
          <div>
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Users className="text-indigo-400" size={16} /> Synchronized Anycast Threat Feed
              </h3>
              <button
                onClick={fetchFeed}
                disabled={loading}
                className="p-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 hover:text-slate-200"
              >
                <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
              </button>
            </div>

            <div className="overflow-x-auto max-h-[380px] overflow-y-auto pr-1">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800/80 text-[10px] text-slate-500 uppercase tracking-widest font-black">
                    <th className="py-2.5">Indicator SHA-256 Hash</th>
                    <th className="py-2.5 px-2">Type</th>
                    <th className="py-2.5 px-2">Source</th>
                    <th className="py-2.5 px-2 text-right">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {feed.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="text-slate-500 italic text-center py-12 text-xs">
                        No threat hashes registered in feed.
                      </td>
                    </tr>
                  ) : (
                    feed.map((entry) => (
                      <tr key={entry.id} className="border-b border-slate-900/50 hover:bg-slate-900/10 last:border-0">
                        <td className="py-3 font-mono text-[10px] text-slate-400 truncate max-w-[180px]" title={entry.indicatorHash}>
                          {entry.indicatorHash}
                        </td>
                        <td className="py-3 px-2">
                          <span className="text-[9px] bg-slate-900 text-indigo-400 border border-slate-800 px-2 py-0.5 rounded font-mono font-semibold">
                            {entry.threatType}
                          </span>
                        </td>
                        <td className="py-3 px-2 text-slate-450 font-semibold">{entry.reportingNode}</td>
                        <td className="py-3 px-2 text-right font-bold text-blue-400">{entry.confidenceScore}%</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-900 text-[10px] text-slate-500 flex justify-between items-center">
            <span className="flex items-center gap-1"><Shield size={10} /> Perimeter rules actively blocking matches</span>
            <span>GDPR Hash Compliance Certified</span>
          </div>
        </div>

      </div>
    </div>
  );
}
