import React from 'react';
import type { IFinding } from '../mockData';
import { ShieldAlert, ShieldCheck, Cpu, Activity, AlertTriangle } from 'lucide-react';

interface MetricCardsProps {
  findings: IFinding[];
}

export const MetricCards: React.FC<MetricCardsProps> = ({ findings }) => {
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length;
  const total = findings.length;

  // Calculate percentages for SVG donut chart segments
  const critHighVal = criticalCount + highCount;
  const critPct = total > 0 ? (critHighVal / total) * 100 : 0;
  const medPct = total > 0 ? (mediumCount / total) * 100 : 0;
  const lowPct = total > 0 ? (lowCount / total) * 100 : 0;

  // Donut chart calculations
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  
  const critOffset = circumference - (critPct / 100) * circumference;
  const medOffset = circumference - (medPct / 100) * circumference;
  const lowOffset = circumference - (lowPct / 100) * circumference;

  return (
    <div className="flex flex-col lg:flex-row gap-6">
      {/* SVG Donut Visualizer */}
      <div className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-5 shadow-lg flex items-center gap-6 lg:w-[320px] shrink-0">
        <div className="relative w-24 h-24 shrink-0">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 80 80">
            {/* Background Track */}
            <circle
              cx="40"
              cy="40"
              r={radius}
              className="stroke-slate-800"
              strokeWidth="8"
              fill="transparent"
            />
            {/* Low Severity Segment */}
            {lowPct > 0 && (
              <circle
                cx="40"
                cy="40"
                r={radius}
                className="stroke-blue-500 transition-all duration-500"
                strokeWidth="8"
                fill="transparent"
                strokeDasharray={circumference}
                strokeDashoffset={lowOffset}
                strokeLinecap="round"
              />
            )}
            {/* Medium Severity Segment */}
            {medPct > 0 && (
              <circle
                cx="40"
                cy="40"
                r={radius}
                className="stroke-amber-500 transition-all duration-500"
                strokeWidth="8"
                fill="transparent"
                strokeDasharray={circumference}
                strokeDashoffset={medOffset}
                strokeLinecap="round"
                transform={`rotate(${lowPct * 3.6} 40 40)`}
              />
            )}
            {/* Critical/High Severity Segment */}
            {critPct > 0 && (
              <circle
                cx="40"
                cy="40"
                r={radius}
                className="stroke-red-500 transition-all duration-500"
                strokeWidth="8"
                fill="transparent"
                strokeDasharray={circumference}
                strokeDashoffset={critOffset}
                strokeLinecap="round"
                transform={`rotate(${(lowPct + medPct) * 3.6} 40 40)`}
              />
            )}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="text-xl font-black text-white">{total}</span>
            <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold">Alerts</span>
          </div>
        </div>

        <div className="flex-1 flex flex-col gap-2">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Severity Split</div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-red-400 font-semibold">
              <span className="w-2 h-2 rounded-full bg-red-500"></span> Critical/High
            </span>
            <span className="text-slate-300 font-mono">{critHighVal} ({Math.round(critPct)}%)</span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-amber-400 font-semibold">
              <span className="w-2 h-2 rounded-full bg-amber-500"></span> Medium Risk
            </span>
            <span className="text-slate-300 font-mono">{mediumCount} ({Math.round(medPct)}%)</span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 text-blue-400 font-semibold">
              <span className="w-2 h-2 rounded-full bg-blue-500"></span> Low / Info
            </span>
            <span className="text-slate-300 font-mono">{lowCount} ({Math.round(lowPct)}%)</span>
          </div>
        </div>
      </div>

      {/* Grid Stats Cards */}
      <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Critical Status */}
        <div className="bg-slate-900/30 border border-slate-800/80 rounded-2xl p-4 flex flex-col gap-1 shadow-md shadow-black/10">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400 uppercase tracking-wider">
            <span>Critical/High</span>
            <ShieldAlert className="text-red-400" size={16} />
          </div>
          <div className="text-2xl font-bold text-red-500 mt-1">{critHighVal}</div>
          <div className="text-[10px] text-slate-500 font-semibold mt-1">Requires Immediate Fixes</div>
        </div>

        {/* Medium Status */}
        <div className="bg-slate-900/30 border border-slate-800/80 rounded-2xl p-4 flex flex-col gap-1 shadow-md shadow-black/10">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400 uppercase tracking-wider">
            <span>Medium Risk</span>
            <AlertTriangle className="text-amber-400" size={16} />
          </div>
          <div className="text-2xl font-bold text-amber-500 mt-1">{mediumCount}</div>
          <div className="text-[10px] text-slate-500 font-semibold mt-1">Potential exploit pathways</div>
        </div>

        {/* Low Status */}
        <div className="bg-slate-900/30 border border-slate-800/80 rounded-2xl p-4 flex flex-col gap-1 shadow-md shadow-black/10">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400 uppercase tracking-wider">
            <span>Low / Info</span>
            <ShieldCheck className="text-blue-400" size={16} />
          </div>
          <div className="text-2xl font-bold text-blue-500 mt-1">{lowCount}</div>
          <div className="text-[10px] text-slate-500 font-semibold mt-1">General hygiene checks</div>
        </div>

        {/* System Health */}
        <div className="bg-slate-900/30 border border-slate-800/80 rounded-2xl p-4 flex flex-col gap-1 shadow-md shadow-black/10">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400 uppercase tracking-wider">
            <span>System Engine</span>
            <Cpu className="text-indigo-400" size={16} />
          </div>
          <div className="text-2xl font-bold text-indigo-400 mt-1">ACTIVE</div>
          <div className="text-[10px] text-slate-500 font-semibold mt-1 flex items-center gap-1">
            <Activity size={10} className="text-emerald-400 animate-pulse" /> Mock Queue Active
          </div>
        </div>
      </div>
    </div>
  );
};
