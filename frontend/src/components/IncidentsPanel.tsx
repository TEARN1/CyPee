import { useState, useEffect } from 'react';
import { ShieldAlert, Terminal, User, Cpu, Network, Briefcase, RefreshCw, AlertOctagon } from 'lucide-react';

interface IIncident {
  id: string;
  type: string;
  sourceIp: string;
  targetPath: string;
  timestamp: string;
  tenantId: string;
}

interface IForensics {
  adversary: {
    suspectedGroups: string[];
    threatActorMapping: string;
  };
  capability: {
    vectorType: string;
    mitreTechnique: string;
    description: string;
  };
  infrastructure: {
    sourceIp: string;
    targetPath: string;
    requestHeaderUserAgent: string;
  };
  victim: {
    tenantId: string;
    targetedZone: string;
  };
  timeline: {
    id: string;
    action: string;
    timestamp: string;
    hash: string;
  }[];
}

export function IncidentsPanel() {
  const [incidents, setIncidents] = useState<IIncident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IIncident | null>(null);
  const [forensics, setForensics] = useState<IForensics | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingForensics, setLoadingForensics] = useState(false);
  const [isTriggeringDecoy, setIsTriggeringDecoy] = useState(false);

  // Fetch active incident list
  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/compliance/incidents');
      if (response.ok) {
        const data = await response.json();
        setIncidents(data);
        if (data.length > 0 && !selectedIncident) {
          setSelectedIncident(data[0]);
        }
      }
    } catch (e) {
      console.error('Failed to fetch security incidents:', e);
    } finally {
      setLoading(false);
    }
  };

  // Fetch forensics report for selected incident
  const fetchForensics = async (incidentId: string) => {
    setLoadingForensics(true);
    setForensics(null);
    try {
      const response = await fetch(`/api/v1/compliance/incidents/${incidentId}/forensics`);
      if (response.ok) {
        const data = await response.json();
        setForensics(data);
      }
    } catch (e) {
      console.error('Failed to fetch incident forensics:', e);
    } finally {
      setLoadingForensics(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  useEffect(() => {
    if (selectedIncident) {
      fetchForensics(selectedIncident.id);
    }
  }, [selectedIncident]);

  // Trigger decoy trap directly from UI
  const triggerDecoy = async (type: 'db' | 'aws') => {
    setIsTriggeringDecoy(true);
    try {
      const path = type === 'db' ? '/api/v1/admin/db-backup' : '/api/v1/config/aws-credentials';
      await fetch(path);
      // Wait a moment for database persistence and reload
      setTimeout(async () => {
        await fetchIncidents();
        setIsTriggeringDecoy(false);
      }, 500);
    } catch (e) {
      console.error(e);
      setIsTriggeringDecoy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="text-red-400 animate-pulse" size={22} /> Incident Forensics (DFIR)
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time attribution and cryptographic analysis of security incidents triggered by vector firewall interceptions or honeytoken access.
          </p>
        </div>

        {/* Decoy triggers */}
        <div className="flex gap-2">
          <button
            onClick={() => triggerDecoy('aws')}
            disabled={isTriggeringDecoy}
            className="px-3 py-1.5 bg-red-950/40 hover:bg-red-900/40 border border-red-900/60 rounded-xl text-red-400 text-xs font-bold transition-all"
          >
            Trigger AWS Decoy
          </button>
          <button
            onClick={() => triggerDecoy('db')}
            disabled={isTriggeringDecoy}
            className="px-3 py-1.5 bg-red-950/40 hover:bg-red-900/40 border border-red-900/60 rounded-xl text-red-400 text-xs font-bold transition-all"
          >
            Trigger DB Decoy
          </button>
          <button
            onClick={fetchIncidents}
            disabled={loading}
            className="p-2 bg-slate-900 border border-slate-800 rounded-xl text-slate-400 hover:text-slate-200"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left column: Incident Alerts List */}
        <div className="lg:col-span-4 bg-slate-950/40 border border-slate-800/80 rounded-2xl p-4 flex flex-col min-h-[450px]">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
            <AlertOctagon size={14} className="text-red-400" /> Active Alert Ledger ({incidents.length})
          </h3>

          <div className="flex-1 overflow-y-auto space-y-2 max-h-[500px] pr-1">
            {incidents.length === 0 ? (
              <div className="text-slate-500 italic text-center py-12 text-xs">
                No security incidents logged. Click a 'Trigger Decoy' button above to simulate a threat.
              </div>
            ) : (
              incidents.map((incident) => (
                <button
                  key={incident.id}
                  onClick={() => setSelectedIncident(incident)}
                  className={`w-full text-left p-3 rounded-xl border transition-all flex flex-col gap-1.5 ${
                    selectedIncident?.id === incident.id
                      ? 'bg-red-950/20 border-red-900/80 shadow-md shadow-red-900/10'
                      : 'bg-slate-900/50 border-slate-850 hover:border-slate-700'
                  }`}
                >
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] bg-red-950/50 text-red-400 border border-red-900/50 px-2 py-0.5 rounded font-bold uppercase tracking-wider">
                      {incident.type}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(incident.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="text-xs font-bold text-slate-200 truncate">
                    Access to: {incident.targetPath}
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono">
                    Source IP: {incident.sourceIp}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Right column: Diamond Model & Cryptographic Timelines */}
        <div className="lg:col-span-8 space-y-6">
          
          {/* Diamond Model Visualization */}
          <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5 flex flex-col justify-between min-h-[300px]">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">
              🛡️ Diamond Model Threat Attribution Map
            </h3>

            {loadingForensics ? (
              <div className="flex-1 flex flex-col justify-center items-center gap-3 text-slate-500 text-xs py-12">
                <RefreshCw size={24} className="animate-spin text-indigo-400" />
                <span>Computing forensic model vectors...</span>
              </div>
            ) : !forensics ? (
              <div className="flex-1 flex justify-center items-center text-slate-500 italic text-xs py-12">
                Select an incident from the ledger to view the Diamond Model attribution.
              </div>
            ) : (
              <div className="relative flex justify-center items-center py-6 min-h-[220px]">
                
                {/* Connector lines (Diamond CSS) */}
                <div className="absolute inset-0 flex justify-center items-center pointer-events-none">
                  <div className="w-48 h-48 border border-slate-800 rotate-45 border-dashed"></div>
                </div>

                {/* Top: Adversary */}
                <div className="absolute top-0 flex flex-col items-center z-10">
                  <div className="w-10 h-10 rounded-full bg-slate-900 border-2 border-red-500 flex items-center justify-center text-red-400 shadow-lg shadow-red-950/40">
                    <User size={16} />
                  </div>
                  <span className="text-[10px] font-bold text-slate-400 mt-1 uppercase tracking-wider">Adversary</span>
                  <span className="text-xs font-bold text-red-400 bg-red-950/20 px-2 py-0.5 rounded border border-red-900/40 mt-0.5">
                    {forensics.adversary.suspectedGroups[0] || 'Unknown'}
                  </span>
                </div>

                {/* Left: Capability */}
                <div className="absolute left-6 flex flex-col items-center z-10">
                  <div className="w-10 h-10 rounded-full bg-slate-900 border-2 border-orange-500 flex items-center justify-center text-orange-400 shadow-lg shadow-orange-950/40">
                    <Cpu size={16} />
                  </div>
                  <span className="text-[10px] font-bold text-slate-400 mt-1 uppercase tracking-wider">Capability</span>
                  <span className="text-xs font-bold text-orange-400 bg-orange-950/20 px-2 py-0.5 rounded border border-orange-900/40 mt-0.5">
                    {forensics.capability.mitreTechnique}
                  </span>
                </div>

                {/* Right: Infrastructure */}
                <div className="absolute right-6 flex flex-col items-center z-10">
                  <div className="w-10 h-10 rounded-full bg-slate-900 border-2 border-blue-500 flex items-center justify-center text-blue-400 shadow-lg shadow-blue-950/40">
                    <Network size={16} />
                  </div>
                  <span className="text-[10px] font-bold text-slate-400 mt-1 uppercase tracking-wider">Infrastructure</span>
                  <span className="text-xs font-bold text-blue-400 bg-blue-950/20 px-2 py-0.5 rounded border border-blue-900/40 mt-0.5">
                    IP: {forensics.infrastructure.sourceIp}
                  </span>
                </div>

                {/* Bottom: Victim */}
                <div className="absolute bottom-0 flex flex-col items-center z-10">
                  <div className="w-10 h-10 rounded-full bg-slate-900 border-2 border-emerald-500 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-950/40">
                    <Briefcase size={16} />
                  </div>
                  <span className="text-[10px] font-bold text-slate-400 mt-1 uppercase tracking-wider">Victim Target</span>
                  <span className="text-xs font-bold text-emerald-400 bg-emerald-950/20 px-2 py-0.5 rounded border border-emerald-900/40 mt-0.5">
                    {forensics.victim.targetedZone}
                  </span>
                </div>

                {/* Center Core: Incident Details */}
                <div className="w-28 h-28 bg-slate-900 border border-slate-800 rounded-2xl flex flex-col items-center justify-center text-center p-2 shadow-2xl z-20">
                  <span className="text-[9px] text-slate-500 uppercase tracking-widest font-black">Attribution</span>
                  <span className="text-[11px] font-bold text-slate-200 mt-1 leading-snug">
                    {selectedIncident?.type === 'HONEYTOKEN_ACCESS' ? 'Decoy Triggered' : 'Shield Alert'}
                  </span>
                  <span className="text-[9px] text-slate-400 font-mono mt-1 truncate max-w-full">
                    {selectedIncident?.id.substring(0, 8)}
                  </span>
                </div>

              </div>
            )}
          </div>

          {/* Cryptographic Event Timeline */}
          {forensics && forensics.timeline && (
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-5">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-1.5">
                <Terminal size={14} className="text-indigo-400" /> Cryptographic Ledger Audit Timeline
              </h3>

              <div className="space-y-4">
                {forensics.timeline.map((event) => (
                  <div key={event.id} className="relative flex gap-4 items-start pl-6 border-l border-slate-800">
                    {/* Node Dot */}
                    <div className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-indigo-500 border border-slate-950"></div>
                    
                    <div className="flex-1 bg-slate-900/40 border border-slate-850 rounded-xl p-3 text-xs flex flex-col md:flex-row md:justify-between md:items-center gap-2">
                      <div>
                        <div className="font-bold text-slate-200">{event.action}</div>
                        <div className="text-[10px] text-slate-500 mt-0.5">SHA-256 Ledger Hash: <code className="text-indigo-400/90 font-mono">{event.hash.substring(0, 32)}...</code></div>
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono self-start md:self-center">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
}
