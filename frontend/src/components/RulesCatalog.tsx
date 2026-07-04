import React, { useState } from 'react';
import { ShieldCheck, Laptop, Smartphone, Globe, Code } from 'lucide-react';

interface IRuleInfo {
  ruleId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  platform: 'Web' | 'Mobile' | 'Source Code' | 'Desktop';
  owaspMapping: string;
  description: string;
}

const ruleList: IRuleInfo[] = [
  {
    ruleId: "SQL_INJECTION",
    title: "Unparameterized Database Queries (SQL Injection)",
    severity: "CRITICAL",
    platform: "Web",
    owaspMapping: "A03:2021-Injection",
    description: "Concatenating untrusted user input directly into database query strings allows attackers to manipulate SQL command structures, leading to unauthorized data exposure, alterations, or execution of arbitrary administrative operations."
  },
  {
    ruleId: "HARDCODED_SECRETS",
    title: "Hardcoded Cryptographic Keys or Secrets",
    severity: "HIGH",
    platform: "Source Code",
    owaspMapping: "A02:2021-Cryptographic Failures",
    description: "Plaintext secrets, credentials, API keys, and private keys committed in version-controlled source files can be harvested by malicious actors to compromise downstream services and enclaves."
  },
  {
    ruleId: "ANDROID_DEBUGGABLE",
    title: "Application is Configured as Debuggable",
    severity: "HIGH",
    platform: "Mobile",
    owaspMapping: "A05:2021-Security Misconfiguration",
    description: "Leaving the debuggable flag enabled in production Android/iOS application manifests allows attackers to attach runtime debug tools, inspect active memory space, or inject classes to bypass root detections."
  },
  {
    ruleId: "CSHARP_DESERIALIZATION",
    title: "Insecure Deserialization in BinaryFormatter",
    severity: "CRITICAL",
    platform: "Desktop",
    owaspMapping: "A08:2021-Software and Data Integrity Failures",
    description: "Deserializing untrusted data streams using weak binary serializers allows attackers to trigger arbitrary object graph construction, resulting in remote code execution (RCE) on the local host."
  },
  {
    ruleId: "MISSING_SECURITY_HEADERS",
    title: "Missing HTTP Security Headers",
    severity: "MEDIUM",
    platform: "Web",
    owaspMapping: "A05:2021-Security Misconfiguration",
    description: "Boots without standard HTTP response headers (Helmet, CORS, HSTS) leave clients vulnerable to clickjacking, cross-site scripting (XSS), and MIME-type sniffing."
  }
];

export const RulesCatalog: React.FC = () => {
  const [filterPlatform, setFilterPlatform] = useState<string>('All');
  
  const filteredRules = ruleList.filter(
    (rule) => filterPlatform === 'All' || rule.platform === filterPlatform
  );

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'Web': return <Globe size={14} className="text-cyan-400" />;
      case 'Mobile': return <Smartphone size={14} className="text-purple-400" />;
      case 'Source Code': return <Code size={14} className="text-indigo-400" />;
      default: return <Laptop size={14} className="text-emerald-400" />;
    }
  };

  return (
    <div className="flex flex-col gap-6 overflow-y-auto pr-1 h-full max-w-4xl mx-auto">
      {/* Intro */}
      <div className="border-b border-slate-800 pb-4 flex justify-between items-center">
        <div>
          <h3 className="text-lg font-bold text-slate-200">Security Rules & Compliance Catalog</h3>
          <p className="text-xs text-slate-400 mt-1">
            Rules and heuristics mapped to global security compliance standards like OWASP Top 10.
          </p>
        </div>
        
        {/* Filter controls */}
        <div className="flex gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-850">
          {['All', 'Web', 'Mobile', 'Source Code', 'Desktop'].map((plat) => (
            <button
              key={plat}
              onClick={() => setFilterPlatform(plat)}
              className={`px-2.5 py-1 text-[10px] font-bold rounded transition-all whitespace-nowrap ${
                filterPlatform === plat
                  ? 'bg-slate-800 text-indigo-400 border border-slate-700/60'
                  : 'text-slate-500 hover:text-slate-350'
              }`}
            >
              {plat}
            </button>
          ))}
        </div>
      </div>

      {/* Rules List */}
      <div className="flex flex-col gap-4">
        {filteredRules.map((rule) => (
          <div key={rule.ruleId} className="bg-slate-900/30 border border-slate-800/80 rounded-xl p-5 flex flex-col gap-3 shadow-md shadow-black/10">
            <div className="flex justify-between items-start">
              <div>
                <span className="font-mono text-slate-450 text-[10px] font-bold tracking-wider">{rule.ruleId}</span>
                <h4 className="text-sm font-bold text-slate-200 mt-0.5">{rule.title}</h4>
              </div>
              <div className="flex gap-2">
                <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityStyle(rule.severity)}`}>
                  {rule.severity}
                </span>
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-950 border border-slate-850 text-[10px] font-semibold text-slate-400">
                  {getPlatformIcon(rule.platform)}
                  {rule.platform}
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              {rule.description}
            </p>

            <div className="flex items-center gap-1.5 text-[10px] text-indigo-400 font-semibold mt-1 bg-indigo-500/5 px-2.5 py-1 rounded border border-indigo-500/10 w-fit">
              <ShieldCheck size={12} /> Mapping: <strong className="font-mono text-slate-200">{rule.owaspMapping}</strong>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
