import React, { useState } from 'react';
import { Upload, Link as LinkIcon, Shield, Globe, Code2, PlusCircle, ChevronDown, ChevronUp } from 'lucide-react';

interface DropzoneProps {
  onIngest: (mode: 'Web' | 'Mobile' | 'Source Code' | 'Desktop', fileNameOrUrl: string) => void;
  onManualSubmit: (finding: { filePath: string; lineNumber: number; ruleId: string; severity: string; message: string }) => void;
}

export const Dropzone: React.FC<DropzoneProps> = ({ onIngest, onManualSubmit }) => {
  const [inputValue, setInputValue] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [detectedMode, setDetectedMode] = useState<'Web' | 'Mobile' | 'Source Code' | null>(null);

  // States for manual form expansion
  const [showManualForm, setShowManualForm] = useState(false);
  const [manualFile, setManualFile] = useState('');
  const [manualLine, setManualLine] = useState<number>(1);
  const [manualRule, setManualRule] = useState('SQL_INJECTION');
  const [manualSeverity, setManualSeverity] = useState('CRITICAL');
  const [manualMsg, setManualMsg] = useState('');

  const determineModeFromText = (text: string) => {
    if (!text.trim()) {
      setDetectedMode(null);
      return;
    }
    if (text.includes('github.com') || text.includes('gitlab.com') || text.endsWith('.git')) {
      setDetectedMode('Source Code');
    } else if (text.startsWith('http://') || text.startsWith('https://')) {
      setDetectedMode('Web');
    } else {
      setDetectedMode(null);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setInputValue(val);
    determineModeFromText(val);
  };

  const handleSubmitLink = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;
    const mode = detectedMode || 'Web';
    onIngest(mode, inputValue);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length === 0) return;

    const file = files[0];
    const extension = file.name.split('.').pop()?.toLowerCase();
    
    let mode: 'Web' | 'Mobile' | 'Source Code' | 'Desktop' = 'Desktop';
    if (extension === 'apk' || extension === 'ipa') {
      mode = 'Mobile';
    } else if (['zip', 'gz', 'tar', 'ts', 'js', 'cs', 'java', 'xml'].includes(extension || '')) {
      mode = 'Source Code';
    }

    onIngest(mode, file.name);
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualFile.trim() || !manualMsg.trim()) return;
    
    onManualSubmit({
      filePath: manualFile,
      lineNumber: manualLine,
      ruleId: manualRule,
      severity: manualSeverity,
      message: manualMsg
    });

    // Reset Form
    setManualFile('');
    setManualLine(1);
    setManualMsg('');
    setShowManualForm(false);
  };

  const getModeBadge = () => {
    if (detectedMode === 'Source Code') {
      return (
        <span className="flex items-center gap-1.5 px-3 py-1 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded-full text-xs font-semibold animate-pulse">
          <Code2 size={14} /> Source Code & Dependency Scan Mode
        </span>
      );
    }
    if (detectedMode === 'Web') {
      return (
        <span className="flex items-center gap-1.5 px-3 py-1 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-full text-xs font-semibold animate-pulse">
          <Globe size={14} /> Web Scan Mode
        </span>
      );
    }
    return null;
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Dropzone Area */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center gap-4 transition-all duration-300 ${
          isDragOver 
            ? 'border-indigo-500 bg-indigo-500/5' 
            : 'border-slate-700 bg-slate-800/40 hover:border-slate-600 hover:bg-slate-800/60'
        }`}
      >
        <div className={`p-4 rounded-full bg-slate-900/80 border border-slate-700 text-slate-400 transition-transform ${
          isDragOver ? 'scale-110 text-indigo-400 border-indigo-500/40' : ''
        }`}>
          <Upload size={32} />
        </div>
        
        <div className="text-center">
          <p className="font-semibold text-slate-200">Drag & drop project assets here</p>
          <p className="text-xs text-slate-400 mt-1">Supports binaries (.apk, .ipa) or source archives (.zip)</p>
        </div>

        <div className="absolute top-3 right-3">
          <span className="flex items-center gap-1 px-2.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
            Unified Ingestion
          </span>
        </div>
      </div>

      <div className="flex items-center justify-center gap-2">
        <span className="h-px bg-slate-800 w-full"></span>
        <span className="text-xs text-slate-500 uppercase tracking-widest font-bold">OR</span>
        <span className="h-px bg-slate-800 w-full"></span>
      </div>

      {/* URL or GitHub Form */}
      <form onSubmit={handleSubmitLink} className="flex flex-col gap-2">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="Paste GitHub Repository link or web endpoint URL..."
              value={inputValue}
              onChange={handleInputChange}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg py-2.5 pl-10 pr-4 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 transition-colors placeholder:text-slate-500"
            />
            <div className="absolute left-3.5 top-3.5 text-slate-500">
              <LinkIcon size={16} />
            </div>
          </div>
          <button
            type="submit"
            disabled={!inputValue.trim()}
            className="px-6 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/30 disabled:text-slate-500 text-white rounded-lg text-sm font-semibold transition-colors duration-200 shadow-md shadow-indigo-900/20 flex items-center gap-1.5"
          >
            <Shield size={16} /> Scan
          </button>
        </div>

        <div className="flex items-center justify-between px-1">
          {getModeBadge()}
          
          {/* Manual Drawer Toggle */}
          <button
            type="button"
            onClick={() => setShowManualForm(!showManualForm)}
            className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold flex items-center gap-1 ml-auto"
          >
            {showManualForm ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {showManualForm ? 'Hide Manual Form' : 'Or Report Finding Manually'}
          </button>
        </div>
      </form>

      {/* Collapsible Manual Form */}
      {showManualForm && (
        <form onSubmit={handleFormSubmit} className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
          <div className="text-xs font-bold text-slate-300 flex items-center gap-1.5 mb-1">
            <PlusCircle size={14} className="text-indigo-400" /> Report Individual Vulnerability
          </div>
          
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-400 font-bold uppercase">File Path</label>
              <input
                type="text"
                placeholder="e.g. src/users/users.service.ts"
                value={manualFile}
                onChange={(e) => setManualFile(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                required
              />
            </div>
            
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-400 font-bold uppercase">Line Number</label>
              <input
                type="number"
                min={1}
                value={manualLine}
                onChange={(e) => setManualLine(parseInt(e.target.value) || 1)}
                className="bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                required
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-400 font-bold uppercase">Select Rule ID</label>
              <select
                value={manualRule}
                onChange={(e) => setManualRule(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="SQL_INJECTION">SQL_INJECTION (SQL Injection)</option>
                <option value="HARDCODED_SECRETS">HARDCODED_SECRETS (Hardcoded Secrets)</option>
                <option value="ANDROID_DEBUGGABLE">ANDROID_DEBUGGABLE (Debuggable Android Manifest)</option>
                <option value="CSHARP_DESERIALIZATION">CSHARP_DESERIALIZATION (Insecure Deserialization)</option>
                <option value="MISSING_SECURITY_HEADERS">MISSING_SECURITY_HEADERS (Missing HTTP Security Headers)</option>
              </select>
            </div>
            
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-400 font-bold uppercase">Severity Level</label>
              <select
                value={manualSeverity}
                onChange={(e) => setManualSeverity(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-slate-400 font-bold uppercase">Threat Message Description</label>
            <textarea
              placeholder="Describe the threat and location..."
              value={manualMsg}
              onChange={(e) => setManualMsg(e.target.value)}
              rows={2}
              className="bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 resize-none"
              required
            />
          </div>

          <button
            type="submit"
            className="w-full py-2 bg-indigo-650 hover:bg-indigo-550 text-white rounded-lg text-xs font-bold transition-all shadow-md shadow-indigo-900/20"
          >
            Submit Manual Vulnerability Report
          </button>
        </form>
      )}
    </div>
  );
};
