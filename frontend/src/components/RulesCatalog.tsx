import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Database,
  Lock,
  Layers,
  FileSpreadsheet,
  Server,
  Cpu,
  Globe,
  Radio,
} from 'lucide-react';

interface SecurityLogic {
  logicId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  domain: string;
  cwe: string;
  mitre: string;
  enforcementAction: string;
  triggerCondition: string;
  mitigation: string;
}

export const RulesCatalog: React.FC = () => {
  const [logics, setLogics] = useState<SecurityLogic[]>([]);
  const [totalCount, setTotalCount] = useState<number>(800);
  const [filteredCount, setFilteredCount] = useState<number>(800);
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(25);
  const [totalPages, setTotalPages] = useState<number>(32);
  const [domainFilter, setDomainFilter] = useState<string>('All');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const domains = [
    'All',
    'Web & API Exploitation',
    'Database & Storage Kernel',
    'The Resident (Identity & Boundary)',
    'The Gruvs (Workflow & Concurrency)',
    'Excellency (Financials & Spreadsheets)',
    'V-Gruvs Host & Hypervisor',
    'Cryptography & Post-Quantum',
    'Cloud, Network & Supply Chain',
  ];

  const fetchLogics = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        limit: String(limit),
      });
      if (domainFilter !== 'All') params.append('domain', domainFilter);
      if (severityFilter !== 'All') params.append('severity', severityFilter);
      if (searchQuery.trim()) params.append('search', searchQuery.trim());

      const res = await fetch(`/api/v1/compliance/logics?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setLogics(data.logics || []);
        setTotalCount(data.totalCount || 800);
        setFilteredCount(data.filteredCount || 800);
        setTotalPages(data.totalPages || 32);
      }
    } catch (e) {
      console.error('Failed to load 800 security logics:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogics();
  }, [page, limit, domainFilter, severityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchLogics();
  };

  const getDomainIcon = (domain: string) => {
    if (domain.includes('Web')) return <Globe size={13} className="text-cyan-400" />;
    if (domain.includes('Database')) return <Database size={13} className="text-emerald-400" />;
    if (domain.includes('Resident')) return <Lock size={13} className="text-purple-400" />;
    if (domain.includes('Gruvs')) return <Layers size={13} className="text-indigo-400" />;
    if (domain.includes('Excellency')) return <FileSpreadsheet size={13} className="text-amber-400" />;
    if (domain.includes('Host')) return <Server size={13} className="text-red-400" />;
    if (domain.includes('Cryptography')) return <Cpu size={13} className="text-blue-400" />;
    return <Radio size={13} className="text-pink-400" />;
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'TARPIT':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      case 'ENCLAVE_AIRGAP':
        return 'bg-red-950/80 text-red-300 border-red-800';
      case 'INFINITE_LABYRINTH':
        return 'bg-purple-950/80 text-purple-300 border-purple-800';
      case 'AST_AUTOPATCH':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800';
      case 'FORENSIC_FREEZE':
        return 'bg-indigo-950/80 text-indigo-300 border-indigo-800';
      default:
        return 'bg-slate-900 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="flex flex-col gap-5 max-w-6xl mx-auto w-full">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck size={22} className="text-cyan-400" />
            <h2 className="text-lg font-black tracking-tight text-white uppercase">
              800-Rule Sovereign Security Logics Matrix
            </h2>
            <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold px-2 py-0.5 rounded">
              {totalCount} Total Logics Enforced
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Deterministic defense heuristics protecting V-Gruvs Host and your 3 applications (The Resident, The Gruvs, and Excellency) across 8 specialized security domains.
          </p>
        </div>

        {/* 4 Stats Chips */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-center">
            <span className="text-[9px] text-red-400 block uppercase font-bold">Critical</span>
            <span className="font-bold text-white">240</span>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-center">
            <span className="text-[9px] text-amber-400 block uppercase font-bold">High</span>
            <span className="font-bold text-white">320</span>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-center">
            <span className="text-[9px] text-cyan-400 block uppercase font-bold">Medium</span>
            <span className="font-bold text-white">180</span>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-center">
            <span className="text-[9px] text-slate-400 block uppercase font-bold">Low</span>
            <span className="font-bold text-white">60</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-950/80 border border-slate-800 p-3.5 rounded-xl flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="flex-1 relative">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by ID (e.g. WEB-014, RES-205, VGR-512), Title, CWE, or MITRE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-20 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            type="submit"
            className="absolute right-1.5 top-1/2 -translate-y-1/2 px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-[10px] font-bold font-mono"
          >
            Search
          </button>
        </form>

        {/* Severity Filter */}
        <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs">
          <Filter size={13} className="text-slate-500 ml-1.5" />
          {['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => {
                setSeverityFilter(sev);
                setPage(1);
              }}
              className={`px-2 py-1 rounded text-[10px] font-bold font-mono transition-all ${
                severityFilter === sev
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Domains Horizontal Scroll Chips */}
      <div className="flex gap-1.5 overflow-x-auto pb-1 text-xs">
        {domains.map((dom) => (
          <button
            key={dom}
            onClick={() => {
              setDomainFilter(dom);
              setPage(1);
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold whitespace-nowrap transition-all flex items-center gap-1.5 ${
              domainFilter === dom
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow'
                : 'bg-slate-900/60 text-slate-400 hover:text-white border border-slate-800/80'
            }`}
          >
            {dom !== 'All' && getDomainIcon(dom)}
            {dom === 'All' ? 'All 8 Domains (800)' : dom}
          </button>
        ))}
      </div>

      {/* Results Count and Pagination Bar */}
      <div className="flex justify-between items-center text-xs text-slate-400 font-mono">
        <span>
          Showing <strong>{logics.length}</strong> of <strong>{filteredCount}</strong> security logics (Page {page} of {totalPages})
        </span>

        <div className="flex items-center gap-2">
          <select
            value={limit}
            onChange={(e) => {
              setLimit(Number(e.target.value));
              setPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300 focus:outline-none"
          >
            <option value="25">25 per page</option>
            <option value="50">50 per page</option>
            <option value="100">100 per page</option>
          </select>

          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1 || loading}
            className="p-1.5 bg-slate-900 border border-slate-800 rounded text-slate-400 hover:text-white disabled:opacity-40"
          >
            <ChevronLeft size={14} />
          </button>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages || loading}
            className="p-1.5 bg-slate-900 border border-slate-800 rounded text-slate-400 hover:text-white disabled:opacity-40"
          >
            <ChevronRight size={14} />
          </button>
        </div>
      </div>

      {/* Logics List Table */}
      <div className="bg-slate-950/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-slate-500 text-xs font-mono">
            Loading security logics catalog...
          </div>
        ) : logics.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs font-mono">
            No security logics found matching the specified filters.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {logics.map((item) => {
              const isExpanded = expandedId === item.logicId;
              return (
                <div key={item.logicId} className="p-4 hover:bg-slate-900/40 transition-all">
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : item.logicId)}
                    className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 cursor-pointer"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-xs font-mono font-black text-cyan-400 bg-slate-900 px-2.5 py-1 rounded-md border border-slate-800 shrink-0">
                        {item.logicId}
                      </span>
                      <div className="min-w-0">
                        <span className="text-xs font-bold text-white block truncate">{item.title}</span>
                        <div className="flex items-center gap-2 mt-0.5 text-[10px] text-slate-400 font-mono">
                          <span className="flex items-center gap-1">{getDomainIcon(item.domain)} {item.domain}</span>
                          <span className="text-slate-600">|</span>
                          <span className="text-slate-300">{item.cwe}</span>
                          <span className="text-slate-600">|</span>
                          <span className="text-slate-400">{item.mitre}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getActionBadge(item.enforcementAction)}`}>
                        {item.enforcementAction}
                      </span>

                      <span
                        className={`text-[9px] font-mono font-black px-2 py-0.5 rounded border ${
                          item.severity === 'CRITICAL'
                            ? 'bg-red-950/80 text-red-300 border-red-800'
                            : item.severity === 'HIGH'
                            ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                            : item.severity === 'MEDIUM'
                            ? 'bg-blue-950/80 text-blue-300 border-blue-800'
                            : 'bg-slate-900 text-slate-400 border-slate-800'
                        }`}
                      >
                        {item.severity}
                      </span>
                    </div>
                  </div>

                  {/* Expanded Detail Panel */}
                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t border-slate-850/80 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono bg-slate-900/50 p-3 rounded-xl border border-slate-800">
                      <div>
                        <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Trigger Condition:</span>
                        <p className="text-slate-300 text-[11px] font-sans">{item.triggerCondition}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Mitigation & Countermeasure:</span>
                        <p className="text-cyan-300 text-[11px] font-sans">{item.mitigation}</p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
