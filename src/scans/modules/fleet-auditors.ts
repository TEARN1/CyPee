import * as fs from 'fs';
import * as path from 'path';
import { ScanFindingInput } from './secret-excavator';

export class FleetVulnerabilityAuditor {
  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];
    const files = this.collectFiles(dirPath);

    for (const filePath of files) {
      const relPath = path.relative(dirPath, filePath).replace(/\\/g, '/');
      let content = '';
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      // 1. THE RESIDENT: Identity, BOLA/IDOR, & Session Security Checks
      this.auditResidentAuth(lines, relPath, findings);

      // 2. THE GRUVS: Concurrency Race Conditions & Operational Integrity
      this.auditGruvsOperations(lines, relPath, findings);

      // 3. EXCELLENCY: Formula Injection (CSV/XLSX) & Unbounded Stream Processing
      this.auditExcelencyData(lines, relPath, findings);

      // 4. V-GRUVS: Host-Level Isolation, Container Breakout & Socket Exposure
      this.auditVGruvsHostIsolation(lines, relPath, findings);
    }

    return findings;
  }

  /**
   * THE RESIDENT: Audits for BOLA/IDOR, weak hashing, and unprotected tenant boundaries
   */
  private auditResidentAuth(lines: string[], relPath: string, findings: ScanFindingInput[]): void {
    if (!relPath.match(/\.(ts|js|jsx|tsx)$/i)) return;

    lines.forEach((line, idx) => {
      // Missing tenant context in resident database queries (IDOR)
      if (line.match(/\.find(Unique|First|One)\s*\(\s*\{\s*where:\s*\{\s*id\b/) && !line.includes('tenantId')) {
        findings.push({
          title: 'The Resident: Potential BOLA / IDOR Query Pattern',
          description: `Query looks up record by identifier without constraining by tenantId. An attacker could access other resident records by incrementing or guessing IDs.`,
          severity: 'HIGH',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-639',
          mitreId: 'T1078',
          remediation: 'Always enforce composite tenant keys in database queries: { where: { id, tenantId: req.user.tenantId } }',
          cvssScore: 8.1,
          pesScore: 81,
        });
      }

      // Weak bcrypt hashing rounds (< 10)
      const bcryptMatch = line.match(/bcrypt\.hash\s*\([^,]+,\s*([0-9]+)\)/);
      if (bcryptMatch && parseInt(bcryptMatch[1], 10) < 10) {
        findings.push({
          title: 'The Resident: Insufficient Password Hash Work Factor',
          description: `bcrypt hash rounds set to ${bcryptMatch[1]}, which is below the OWASP recommendation of 10-12 rounds.`,
          severity: 'MEDIUM',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-916',
          mitreId: 'T1110',
          remediation: 'Increase bcrypt salt rounds to at least 12 to withstand modern GPU brute-force attacks.',
          cvssScore: 5.5,
          pesScore: 55,
        });
      }

      // Insecure session cookie (missing httpOnly or secure)
      if (line.includes('res.cookie(') && (!line.includes('httpOnly: true') || !line.includes('secure: true'))) {
        findings.push({
          title: 'The Resident: Insecure Cookie Flag Configuration',
          description: 'Session or authentication cookie set without httpOnly: true or secure: true, exposing it to Cross-Site Scripting (XSS) extraction.',
          severity: 'HIGH',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-1004',
          mitreId: 'T1539',
          remediation: 'Set httpOnly: true, secure: true, and sameSite: "lax" or "strict" on all authentication cookies.',
          cvssScore: 7.4,
          pesScore: 74,
        });
      }
    });
  }

  /**
   * THE GRUVS: Concurrency, state mutations, and reentrancy audits
   */
  private auditGruvsOperations(lines: string[], relPath: string, findings: ScanFindingInput[]): void {
    if (!relPath.match(/\.(ts|js|jsx|tsx)$/i)) return;

    lines.forEach((line, idx) => {
      // Unsynchronized financial/operational state mutation (Race Condition candidate)
      if (line.match(/(balance\s*\+=|balance\s*-=|status\s*=\s*['"]COMPLETED['"])/) && !line.includes('lock')) {
        findings.push({
          title: 'The Gruvs: Unlocked State Mutation (Race Condition Risk)',
          description: 'Direct operational state change detected without an explicit distributed mutex lock or transaction boundary.',
          severity: 'HIGH',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-362',
          mitreId: 'T1499',
          remediation: 'Wrap operational updates in CyPee SecurityHardeningService acquireLock() or database-level serializable isolation transactions.',
          cvssScore: 7.8,
          pesScore: 78,
        });
      }

      // Dangerous shell execution inside business workflow
      if (line.match(/child_process\.(exec|execSync)\s*\(/)) {
        findings.push({
          title: 'The Gruvs: Dangerous Direct Shell Invocation',
          description: 'Use of child_process.exec() passes strings directly to the system shell, vulnerable to command injection if variables are unescaped.',
          severity: 'CRITICAL',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-78',
          mitreId: 'T1059',
          remediation: 'Replace exec() with execFile() using non-shell array arguments, or use native API libraries.',
          cvssScore: 9.3,
          pesScore: 93,
        });
      }
    });
  }

  /**
   * EXCELLENCY: Formula injection, spreadsheet XXE, and memory exhaustion
   */
  private auditExcelencyData(lines: string[], relPath: string, findings: ScanFindingInput[]): void {
    lines.forEach((line, idx) => {
      // Direct CSV generation without prefix sanitization (Formula Injection)
      if (line.match(/\.toCSV|\.writeCSV|csvContent\s*\+=/) && !line.includes('sanitize') && !line.includes('escape')) {
        findings.push({
          title: 'Excellency: Unsanitized CSV Serialization (Formula Injection / DDE)',
          description: 'CSV or spreadsheet data written directly from user input without escaping dangerous leading formula prefixes (=, +, -, @, |).',
          severity: 'HIGH',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-1236',
          mitreId: 'T1204',
          remediation: 'Prepend a single quote (\') to any cell starting with =, +, -, @, or pipe before writing to CSV.',
          cvssScore: 8.0,
          pesScore: 80,
        });
      }

      // Memory exhaustion via fs.readFileSync on potentially massive spreadsheet uploads
      if (line.match(/fs\.readFileSync\s*\([^)]*upload/i)) {
        findings.push({
          title: 'Excellency: Unbounded Buffer Read on Uploaded Data',
          description: 'Reading uploaded files entirely into memory using readFileSync can cause out-of-memory DoS on large spreadsheet files.',
          severity: 'MEDIUM',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-400',
          mitreId: 'T1499',
          remediation: 'Use chunked streaming pipelines (fs.createReadStream) with a strict max-file-size threshold.',
          cvssScore: 6.2,
          pesScore: 62,
        });
      }
    });
  }

  /**
   * V-GRUVS HOST PLATFORM: Container escape, socket exposure, and host isolation
   */
  private auditVGruvsHostIsolation(lines: string[], relPath: string, findings: ScanFindingInput[]): void {
    const isComposeOrDocker = relPath.match(/(docker-compose|dockerfile|\.ya?ml)$/i);
    if (!isComposeOrDocker) return;

    lines.forEach((line, idx) => {
      // Docker socket mount (Container Escape vector)
      if (line.includes('/var/run/docker.sock')) {
        findings.push({
          title: 'V-Gruvs Host: Dangerous Docker Socket Mount',
          description: 'Mounting /var/run/docker.sock into a container gives the container root-level control over the entire host platform.',
          severity: 'CRITICAL',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-250',
          mitreId: 'T1611',
          remediation: 'Never mount the Docker daemon socket inside application containers. Use rootless Docker or isolated API agents.',
          cvssScore: 9.8,
          pesScore: 98,
        });
      }

      // Privileged container flag
      if (line.match(/privileged:\s*true/i)) {
        findings.push({
          title: 'V-Gruvs Host: Container Running in Privileged Mode',
          description: 'privileged: true disables all Linux namespace isolation, allowing the container full access to host devices and kernel capabilities.',
          severity: 'CRITICAL',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-269',
          mitreId: 'T1611',
          remediation: 'Remove privileged: true. Explicitly grant only the minimal required Linux capabilities (e.g. cap_drop: [ALL]).',
          cvssScore: 9.5,
          pesScore: 95,
        });
      }

      // Host network mode
      if (line.match(/network_mode:\s*["']?host["']?/i)) {
        findings.push({
          title: 'V-Gruvs Host: Insecure Host Network Namespace Mode',
          description: 'network_mode: host removes network isolation between the container and V-Gruvs host, exposing host loopback services.',
          severity: 'HIGH',
          filePath: relPath,
          lineNumber: idx + 1,
          cweId: 'CWE-668',
          mitreId: 'T1046',
          remediation: 'Use user-defined bridge or overlay networks instead of host network mode.',
          cvssScore: 7.7,
          pesScore: 77,
        });
      }
    });
  }

  private collectFiles(dir: string): string[] {
    const results: string[] = [];
    const skip = new Set(['node_modules', '.git', 'dist', '.next', 'build', 'coverage']);

    const walk = (current: string) => {
      let entries: fs.Dirent[] = [];
      try {
        entries = fs.readdirSync(current, { withFileTypes: true });
      } catch {
        return;
      }

      for (const e of entries) {
        if (skip.has(e.name)) continue;
        const full = path.join(current, e.name);
        if (e.isDirectory()) {
          walk(full);
        } else if (e.isFile()) {
          results.push(full);
        }
      }
    };

    walk(dir);
    return results;
  }
}
