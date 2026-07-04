import { execFile } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import { Logger } from '@nestjs/common';
import { ScanFindingInput } from './secret-excavator';

const execFileAsync = promisify(execFile);

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  extra: {
    message: string;
    severity: 'ERROR' | 'WARNING' | 'INFO';
    metadata?: {
      cwe?: string[] | string;
      owasp?: string[] | string;
      references?: string[];
    };
  };
}

interface SemgrepOutput {
  results: SemgrepResult[];
  errors: unknown[];
}

const SEVERITY_MAP: Record<SemgrepResult['extra']['severity'], { severity: ScanFindingInput['severity']; cvss: number }> = {
  ERROR: { severity: 'HIGH', cvss: 8.0 },
  WARNING: { severity: 'MEDIUM', cvss: 5.0 },
  INFO: { severity: 'LOW', cvss: 2.5 },
};

/**
 * Real static-analysis engine backed by semgrep (https://semgrep.dev), an
 * open-source multi-language SAST tool. Requires the `semgrep` binary to be
 * resolvable on PATH, or SEMGREP_BIN to point at it directly.
 */
export class SemgrepScanner {
  private readonly logger = new Logger(SemgrepScanner.name);
  private readonly binPath = process.env.SEMGREP_BIN || 'semgrep';
  private readonly rulesets = (process.env.SEMGREP_RULESETS || 'p/security-audit,p/secrets,p/owasp-top-ten')
    .split(',')
    .map((r) => r.trim())
    .filter(Boolean);

  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const args = [
      ...this.rulesets.flatMap((r) => ['--config', r]),
      '--json',
      '--quiet',
      '--metrics=off',
      '--exclude', 'node_modules',
      '--exclude', '.git',
      '--exclude', 'dist',
      '--exclude', '.next',
      dirPath,
    ];

    let stdout: string;
    try {
      const result = await execFileAsync(this.binPath, args, {
        cwd: dirPath,
        maxBuffer: 50 * 1024 * 1024,
        timeout: 5 * 60 * 1000,
      });
      stdout = result.stdout;
    } catch (error: any) {
      // semgrep exits non-zero when findings include blocking rules even on success;
      // stdout still contains valid JSON in that case, so only bail if stdout is empty.
      if (error.stdout) {
        stdout = error.stdout;
      } else {
        this.logger.warn(`Semgrep scan unavailable or failed: ${error.message}`);
        return [];
      }
    }

    let parsed: SemgrepOutput;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      this.logger.warn('Semgrep produced non-JSON output; skipping module.');
      return [];
    }

    return parsed.results.map((r) => this.toFinding(r, dirPath));
  }

  private toFinding(r: SemgrepResult, dirPath: string): ScanFindingInput {
    const mapping = SEVERITY_MAP[r.extra.severity] || SEVERITY_MAP.INFO;
    const cwe = Array.isArray(r.extra.metadata?.cwe) ? r.extra.metadata!.cwe[0] : r.extra.metadata?.cwe;
    const relPath = path.relative(dirPath, r.path).replace(/\\/g, '/');

    return {
      title: `Semgrep: ${r.check_id.split('.').pop()}`,
      description: r.extra.message,
      severity: mapping.severity,
      filePath: relPath,
      lineNumber: r.start.line,
      cweId: cwe || 'CWE-Unknown',
      mitreId: 'N/A',
      remediation: `Review and fix per rule "${r.check_id}". See https://semgrep.dev/r/${r.check_id} for details.`,
      cvssScore: mapping.cvss,
      pesScore: mapping.cvss * 10,
    };
  }
}
