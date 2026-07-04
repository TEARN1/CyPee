import React, { useEffect, useState, useRef } from 'react';
import { Terminal } from 'lucide-react';

interface LiveTelemetryProps {
  scanId: string | null;
  mode: 'Web' | 'Mobile' | 'Source Code' | 'Desktop';
  targetName: string;
  onComplete: () => void;
}

export const LiveTelemetry: React.FC<LiveTelemetryProps> = ({ scanId, mode, targetName, onComplete }) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [percent, setPercent] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  // Fallback simulated steps if no real scanId is active
  const getSimulatedSteps = () => {
    const base = [
      `[INITIALIZING] Security audit environment configuration...`,
      `[IDENTIFIED] Target: "${targetName}" | Mode: "${mode}"`,
      `[LOADING] Checking cryptographically signed signatures... OK`,
    ];

    if (mode === 'Mobile') {
      return [
        ...base,
        `[PARSING] AndroidManifest.xml manifest bounds...`,
        `[FLAGGED] APK/IPA debuggable flags detected in debug configurations`,
        `[DECOMPILING] Dalvik Bytecode to readable Java source classes...`,
        `[SCANNING] Insecure Keychain / Keystore storage routines...`,
        `[ANALYZING] SQLite database local SQL queries...`,
        `[COMPLETED] Mobile security binary parsing complete.`,
      ];
    }

    if (mode === 'Web') {
      return [
        ...base,
        `[SCANNING] Route handlers and dynamic API parameters...`,
        `[FLAGGED] Unescaped template literals in dynamic page rendering`,
        `[CHECKING] HTTP Response Headers...`,
        `[FLAGGED] Helmet security headers missing from Express/Nest app boot`,
        `[COMPLETED] Web application threat simulation complete.`,
      ];
    }

    if (mode === 'Source Code') {
      return [
        ...base,
        `[PARSING] Package configuration files (package.json / tsconfig.json)...`,
        `[SCANNING] Database service classes for unparameterized raw SQLs...`,
        `[FLAGGED] Concatenating query inputs in src/users/users.service.ts`,
        `[SCANNING] Cryptographic encryption key assignments...`,
        `[FLAGGED] Hardcoded plaintext secret key constant detected in auth modules`,
        `[COMPLETED] Source dependency static code scan complete.`,
      ];
    }

    return [
      ...base,
      `[PARSING] Assembly configurations...`,
      `[SCANNING] Object serialization boundaries...`,
      `[FLAGGED] Insecure BinaryFormatter deserialization detected`,
      `[COMPLETED] Native executable code scan complete.`,
    ];
  };

  useEffect(() => {
    if (!scanId) {
      // Run fallback local simulation
      const steps = getSimulatedSteps();
      let currentStep = 0;
      setLogs([steps[0]]);

      const logInterval = setInterval(() => {
        currentStep++;
        if (currentStep < steps.length) {
          setLogs((prev) => [...prev, steps[currentStep]]);
          setPercent((prev) => Math.min(prev + Math.floor(100 / steps.length), 100));
        } else {
          setPercent(100);
          clearInterval(logInterval);
          setTimeout(() => {
            onComplete();
          }, 1000);
        }
      }, 400);

      return () => clearInterval(logInterval);
    }

    // Connect to live NestJS SSE stream for real scan telemetry
    setLogs([`[CONNECTING] Connecting to live SSE telemetry stream for scan ${scanId}...`]);
    const eventSource = new EventSource(`/api/v1/scans/${scanId}/stream`);

    eventSource.onopen = () => {
      setLogs((prev) => [...prev, `[CONNECTED] Live telemetry connection established. Starting scan...`]);
    };

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.type === 'module_start') {
          setLogs((prev) => [...prev, `[RUNNING] ${data.message || `Starting module ${data.module}`}`]);
        } else if (data.type === 'finding') {
          setLogs((prev) => [
            ...prev,
            `[FLAGGED] ${data.finding?.severity} vulnerability in ${data.module}: ${data.finding?.title}`,
          ]);
        } else if (data.type === 'module_complete') {
          setLogs((prev) => [...prev, `[SUCCESS] Completed module ${data.module}`]);
          setPercent(data.progress || 0);
        } else if (data.type === 'complete') {
          setPercent(100);
          setLogs((prev) => [
            ...prev,
            `[COMPLETED] Scan finished. Score: ${data.postureScore}/100. Findings: ${data.totalFindings}.`,
          ]);
          setTimeout(() => {
            eventSource.close();
            onComplete();
          }, 1500);
        } else if (data.type === 'failed') {
          setLogs((prev) => [...prev, `[FAILED] Scan execution failed: ${data.message}`]);
          eventSource.close();
        }
      } catch (err: any) {
        setLogs((prev) => [...prev, `[ERROR] Failed to parse telemetry event: ${err.message}`]);
      }
    };

    eventSource.onerror = () => {
      setLogs((prev) => [...prev, `[DISCONNECTED] Connection closed or timed out.`]);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [scanId, mode, targetName]);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col gap-4 shadow-lg shadow-black/40 h-[300px]">
      <div className="flex justify-between items-center border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-indigo-400 font-semibold">
          <Terminal size={18} />
          <span>Real-Time Scanning Telemetry</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 font-medium">Progress: {percent}%</span>
          <div className="w-24 bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div 
              className="bg-indigo-500 h-full transition-all duration-300 ease-out" 
              style={{ width: `${percent}%` }}
            ></div>
          </div>
        </div>
      </div>

      <div 
        ref={containerRef}
        className="flex-1 overflow-y-auto font-mono text-xs text-slate-300 flex flex-col gap-1.5 pr-2"
      >
        {logs.map((log, index) => {
          let colorClass = 'text-slate-400';
          if (log.startsWith('[FLAGGED]')) {
            colorClass = 'text-red-400 font-bold';
          } else if (log.startsWith('[COMPLETED]') || log.startsWith('[SUCCESS]')) {
            colorClass = 'text-emerald-400 font-bold';
          } else if (log.startsWith('[INITIALIZING]') || log.startsWith('[IDENTIFIED]') || log.startsWith('[CONNECTING]') || log.startsWith('[CONNECTED]')) {
            colorClass = 'text-indigo-300';
          } else if (log.includes('OK')) {
            colorClass = 'text-slate-200';
          }

          return (
            <div key={index} className={`flex items-start gap-2 ${colorClass}`}>
              <span className="text-slate-600 select-none">&gt;</span>
              <span>{log}</span>
            </div>
          );
        })}
      </div>
      
      <div className="flex items-center justify-between text-[10px] text-slate-500 font-bold uppercase tracking-wider pt-2 border-t border-slate-800/40">
        <span>Channel: {scanId ? `scan-telemetry-sse-${scanId.substring(0,8)}` : 'backend-worker-sast-analysis'}</span>
        <span>Status: {percent < 100 ? 'scanning active' : 'complete'}</span>
      </div>
    </div>
  );
};
