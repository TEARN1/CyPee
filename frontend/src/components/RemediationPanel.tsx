import React, { useState } from 'react';
import type { IFinding } from '../mockData';
import Editor from '@monaco-editor/react';
import { Copy, Check, FileCode, ShieldAlert } from 'lucide-react';

interface RemediationPanelProps {
  finding: IFinding | null;
}

export const RemediationPanel: React.FC<RemediationPanelProps> = ({ finding }) => {
  const [copied, setCopied] = useState(false);

  if (!finding) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 text-center text-slate-500">
        <span className="text-4xl mb-3">🔍</span>
        <p className="font-semibold text-slate-400">No finding selected</p>
        <p className="text-xs text-slate-500 mt-1 max-w-xs">
          Select a vulnerability from the matrix to inspect the engineering risk and access code remediation.
        </p>
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(finding.secureCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getLanguage = (filePath: string) => {
    const ext = filePath.split('.').pop()?.toLowerCase();
    if (ext === 'ts' || ext === 'tsx') return 'typescript';
    if (ext === 'js' || ext === 'jsx') return 'javascript';
    if (ext === 'cs') return 'csharp';
    if (ext === 'java') return 'java';
    if (ext === 'xml') return 'xml';
    return 'typescript';
  };

  return (
    <div className="flex flex-col gap-5 h-full overflow-y-auto pr-1">
      {/* Header Info */}
      <div className="border-b border-slate-800 pb-4">
        <h3 className="text-lg font-bold text-slate-200">{finding.title}</h3>
        <div className="flex flex-wrap gap-2.5 mt-2 items-center text-xs text-slate-400 font-mono">
          <span className="flex items-center gap-1 text-slate-300">
            <FileCode size={14} /> {finding.filePath}
          </span>
          <span className="bg-slate-850 px-2 py-0.5 rounded border border-slate-800">
            Line {finding.lineNumber}
          </span>
          <span className="bg-slate-850 px-2 py-0.5 rounded border border-slate-800">
            Rule: {finding.ruleId}
          </span>
        </div>
      </div>

      {/* Risk explanation */}
      <div className="bg-sky-500/5 border border-sky-500/20 rounded-xl p-4 flex flex-col gap-1.5">
        <div className="text-xs font-bold text-sky-400 uppercase tracking-widest flex items-center gap-1.5">
          <ShieldAlert size={14} /> Threat Analysis & Risk Profile
        </div>
        <p className="text-xs text-slate-300 leading-relaxed mt-1">
          {finding.risk}
        </p>
      </div>

      {/* Side-by-Side Editor Panels */}
      <div className="flex flex-col xl:flex-row gap-4 flex-1 min-h-[350px]">
        {/* Insecure editor */}
        <div className="flex-1 flex flex-col border border-red-500/20 rounded-xl overflow-hidden bg-slate-950/40">
          <div className="flex items-center justify-between px-4 py-2 bg-red-500/5 border-b border-red-500/20 text-xs font-bold text-red-400">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
              🛑 Insecure Vulnerable Implementation
            </span>
          </div>
          <div className="flex-1 min-h-[250px] p-2">
            <Editor
              height="100%"
              language={getLanguage(finding.filePath)}
              theme="vs-dark"
              value={finding.insecureCode}
              options={{
                readOnly: true,
                domReadOnly: true,
                minimap: { enabled: false },
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                fontSize: 12,
                fontFamily: 'JetBrains Mono',
                padding: { top: 8 },
              }}
            />
          </div>
        </div>

        {/* Secure editor */}
        <div className="flex-1 flex flex-col border border-emerald-500/20 rounded-xl overflow-hidden bg-slate-950/40">
          <div className="flex items-center justify-between px-4 py-2 bg-emerald-500/5 border-b border-emerald-500/20 text-xs font-bold text-emerald-400">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              ✅ Secure Remediated Patch
            </span>
            <button
              onClick={handleCopy}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-semibold border transition-all duration-150 ${
                copied
                  ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400 animate-pulse'
                  : 'bg-slate-900 border-slate-700 hover:border-slate-600 hover:bg-slate-800 text-slate-300'
              }`}
            >
              {copied ? (
                <>
                  <Check size={12} /> Copied!
                </>
              ) : (
                <>
                  <Copy size={12} /> Copy Fix
                </>
              )}
            </button>
          </div>
          <div className="flex-1 min-h-[250px] p-2">
            <Editor
              height="100%"
              language={getLanguage(finding.filePath)}
              theme="vs-dark"
              value={finding.secureCode}
              options={{
                readOnly: true,
                domReadOnly: true,
                minimap: { enabled: false },
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                fontSize: 12,
                fontFamily: 'JetBrains Mono',
                padding: { top: 8 },
              }}
            />
          </div>
        </div>
      </div>
      
      <div className="text-[10px] text-slate-500 font-semibold italic text-center pb-2 border-t border-slate-800/40 pt-3">
        Powered by Shield Compliance AI Remediation Engine
      </div>
    </div>
  );
};
