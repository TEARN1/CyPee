import { Injectable, Logger } from '@nestjs/common';
import * as vm from 'vm';
import * as crypto from 'crypto';

export interface MockSinkExecution {
  sinkCategory: 'DATABASE' | 'SHELL' | 'SPREADSHEET' | 'TENANT_BOUNDARY';
  methodName: string;
  argumentsGiven: any[];
  breachConfirmed: boolean;
  breachAnalysis: string;
  timestamp: number;
}

export interface TimeTravelStep {
  step: number;
  label: string;
  variableDeltas: Record<string, any>;
  durationMs: number;
  sinkStatus: 'SAFE' | 'TAINTED' | 'EXPLOITED';
}

export interface SandboxExecutionResult {
  executionId: string;
  success: boolean;
  output?: any;
  error?: string;
  elapsedMs: number;
  interceptedSinks: MockSinkExecution[];
  timeTravelTrace: TimeTravelStep[];
  exploitDetected: boolean;
  exploitCategory?: string;
  exploitDetails?: string;
}

/** Whether this server may run submitted code at all. */
export function codeRunAllowed(): boolean {
  return process.env.CYPEE_ALLOW_CODE_RUN === 'true';
}

@Injectable()
export class EphemeralSandboxService {
  private readonly logger = new Logger(EphemeralSandboxService.name);

  /**
   * Runs candidate code in Node's vm module with mock sinks.
   *
   * vm is NOT a security boundary (Node's own documentation): code can reach
   * the host through any object handed into the context. So this is off
   * unless the owner sets CYPEE_ALLOW_CODE_RUN=true on a machine that holds
   * nothing worth stealing. The safe design is a separate, network-less
   * process or container per run.
   */
  public executeCandidate(
    codeSnippet: string,
    testInput: any,
    timeoutMs = 1000,
  ): SandboxExecutionResult {
    const executionId = `VM-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    if (!codeRunAllowed()) {
      return {
        executionId,
        success: false,
        error: 'Running submitted code is switched off on this server (CYPEE_ALLOW_CODE_RUN).',
        elapsedMs: 0,
        interceptedSinks: [],
        timeTravelTrace: [],
        exploitDetected: false,
      };
    }
    const safeTimeout = Math.min(Math.max(Number(timeoutMs) || 1000, 10), 2000);
    const startTime = performance.now();
    const interceptedSinks: MockSinkExecution[] = [];
    const timeTravelTrace: TimeTravelStep[] = [];

    timeTravelTrace.push({
      step: 1,
      label: 'INGRESS_DISPATCH',
      variableDeltas: { input: testInput },
      durationMs: 0.1,
      sinkStatus: 'TAINTED',
    });

    // Mock Security Sinks
    const mockDb = {
      query: (sql: string, params: any[] = []) => {
        const isBroken = typeof sql === 'string' && (
          sql.includes("' OR '1'='1") ||
          sql.includes("' OR 1=1") ||
          sql.includes("UNION SELECT") ||
          sql.includes("'; DROP TABLE") ||
          /WHERE\s+[^=]+=\s*['"][^'"]*['"]\s*(OR|AND)\s*['"]/i.test(sql)
        );

        interceptedSinks.push({
          sinkCategory: 'DATABASE',
          methodName: 'db.query',
          argumentsGiven: [sql, params],
          breachConfirmed: isBroken,
          breachAnalysis: isBroken
            ? `SQL Breakout Detected: Raw input escaped syntax boundary. Query string: "${sql}"`
            : params.length > 0
              ? `Parameterized query safe: [$1, $2] placeholder used with arguments [${params.join(', ')}]`
              : 'Static query executed safely.',
          timestamp: Date.now(),
        });

        timeTravelTrace.push({
          step: timeTravelTrace.length + 1,
          label: 'DATABASE_SINK_INVOCATION',
          variableDeltas: { sql, paramsCount: params.length },
          durationMs: +(performance.now() - startTime).toFixed(2),
          sinkStatus: isBroken ? 'EXPLOITED' : 'SAFE',
        });

        return isBroken ? [{ id: 1, leaked: 'ATTACKER_ADMIN_ACCOUNT' }] : [{ id: 42, name: 'Normal User' }];
      },
    };

    const mockShell = {
      exec: (command: string, callback?: (err: any, stdout: string) => void) => {
        const isEscaped = typeof command === 'string' && (
          command.includes(';') ||
          command.includes('&') ||
          command.includes('|') ||
          command.includes('$') ||
          command.includes('`')
        );

        interceptedSinks.push({
          sinkCategory: 'SHELL',
          methodName: 'child_process.exec',
          argumentsGiven: [command],
          breachConfirmed: isEscaped,
          breachAnalysis: isEscaped
            ? `Subshell Injection Detected: Shell metacharacter escaped in command: "${command}"`
            : 'Static command executed.',
          timestamp: Date.now(),
        });

        timeTravelTrace.push({
          step: timeTravelTrace.length + 1,
          label: 'SHELL_SINK_INVOCATION',
          variableDeltas: { command },
          durationMs: +(performance.now() - startTime).toFixed(2),
          sinkStatus: isEscaped ? 'EXPLOITED' : 'SAFE',
        });

        if (callback) callback(null, 'mock_shell_output');
        return { pid: 9999 };
      },
      execFile: (file: string, args: string[] = [], callback?: any) => {
        interceptedSinks.push({
          sinkCategory: 'SHELL',
          methodName: 'child_process.execFile',
          argumentsGiven: [file, args],
          breachConfirmed: false,
          breachAnalysis: `Safe: Subshell bypassed via direct binary execution with array args [${args.join(', ')}].`,
          timestamp: Date.now(),
        });
        if (callback) callback(null, 'safe_binary_output');
        return { pid: 9998 };
      },
    };

    const mockSpreadsheet = {
      setCell: (cellRef: string, value: any) => {
        const isFormulaInjection = typeof value === 'string' && /^[=+\-@|]/.test(value) && !value.startsWith("'");
        interceptedSinks.push({
          sinkCategory: 'SPREADSHEET',
          methodName: 'workbook.setCell',
          argumentsGiven: [cellRef, value],
          breachConfirmed: isFormulaInjection,
          breachAnalysis: isFormulaInjection
            ? `DDE Formula Injection: Dynamic Data Exchange formula trigger found without leading single-quote escape: "${value}"`
            : 'Cell value safely quoted or scalar.',
          timestamp: Date.now(),
        });

        timeTravelTrace.push({
          step: timeTravelTrace.length + 1,
          label: 'SPREADSHEET_CELL_WRITE',
          variableDeltas: { cellRef, value },
          durationMs: +(performance.now() - startTime).toFixed(2),
          sinkStatus: isFormulaInjection ? 'EXPLOITED' : 'SAFE',
        });
      },
    };

    const mockTenantContext = {
      getCurrentTenantId: () => 'tenant-corp-alpha-99',
      assertTenantAccess: (recordTenantId: string) => {
        const matches = recordTenantId === 'tenant-corp-alpha-99';
        if (!matches) {
          interceptedSinks.push({
            sinkCategory: 'TENANT_BOUNDARY',
            methodName: 'tenantContext.assertTenantAccess',
            argumentsGiven: [recordTenantId],
            breachConfirmed: true,
            breachAnalysis: `BOLA Tenant Breach: Attempted to access tenant "${recordTenantId}" from session "tenant-corp-alpha-99"`,
            timestamp: Date.now(),
          });
          throw new Error(`Forbidden: Tenant boundary violation for ${recordTenantId}`);
        }
      },
    };

    // Isolated Sandboxed Environment
    const sandboxScope: Record<string, any> = {
      input: testInput,
      userInput: testInput,
      userId: testInput,
      fileName: testInput,
      cellValue: testInput,
      db: mockDb,
      database: mockDb,
      child_process: mockShell,
      exec: mockShell.exec,
      execFile: mockShell.execFile,
      spreadsheet: mockSpreadsheet,
      tenantContext: mockTenantContext,
      console: { log: () => {}, warn: () => {}, error: () => {} },
      result: null,
      path: { basename: (p: string) => (p || '').split(/[/\\]/).pop() || '' },
    };

    // No eval or new Function inside the context (it does not make vm safe; see above).
    const context = vm.createContext(sandboxScope, { codeGeneration: { strings: false, wasm: false } });

    let exploitDetected = false;
    let exploitCategory: string | undefined;
    let exploitDetails: string | undefined;

    try {
      // Wrap code in an immediately-invoked execution block if necessary
      const executableScript = codeSnippet.includes('function') || codeSnippet.includes('=>')
        ? `${codeSnippet}\nif (typeof runBackup === 'function') { result = runBackup(input); }\nelse if (typeof findUser === 'function') { result = findUser(input); }\nelse if (typeof exportCell === 'function') { result = exportCell(input); }`
        : `result = (function() { ${codeSnippet} })();`;

      const script = new vm.Script(executableScript, { filename: 'candidate.vm.js' });
      script.runInContext(context, { timeout: safeTimeout });

      // Audit intercepted sinks for confirmed exploits
      const breached = interceptedSinks.find((s) => s.breachConfirmed);
      if (breached) {
        exploitDetected = true;
        exploitCategory = breached.sinkCategory;
        exploitDetails = breached.breachAnalysis;
      }

      const elapsed = +(performance.now() - startTime).toFixed(2);
      return {
        executionId,
        success: true,
        output: sandboxScope.result,
        elapsedMs: elapsed,
        interceptedSinks,
        timeTravelTrace,
        exploitDetected,
        exploitCategory,
        exploitDetails,
      };
    } catch (err: any) {
      const elapsed = +(performance.now() - startTime).toFixed(2);
      const isBreached = interceptedSinks.some((s) => s.breachConfirmed);

      return {
        executionId,
        success: false,
        error: err.message,
        elapsedMs: elapsed,
        interceptedSinks,
        timeTravelTrace,
        exploitDetected: isBreached || err.message.includes('Tenant boundary violation'),
        exploitCategory: isBreached ? 'SINK_BREACH' : 'RUNTIME_EXCEPTION',
        exploitDetails: err.message,
      };
    }
  }
}
