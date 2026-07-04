import * as fs from 'fs';
import * as path from 'path';
import { ScanFindingInput } from './secret-excavator';

const ROUTE_DECORATOR = /^@(Get|Post|Put|Delete|Patch)\(/;
const GUARD_DECORATOR = /@UseGuards\(/;
const CLASS_DECLARATION = /^export\s+class\s+(\w+)/;

/**
 * Static auth-guard auditor for NestJS controllers. This does NOT fuzz
 * (no requests are sent) — it statically checks, per route, whether a
 * @UseGuards decorator applies via the class or the individual method.
 */
export class AuthGuardAuditor {
  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];
    await this.walkDirectory(dirPath, (filePath) => {
      if (filePath.includes('node_modules') || filePath.includes('.git') || filePath.includes('dist')) {
        return;
      }

      const filename = path.basename(filePath).toLowerCase();

      try {
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) return;

        if (filename.endsWith('.controller.ts') || filename.endsWith('.controller.js')) {
          this.auditController(filePath, dirPath, findings);
        }
      } catch {
        // Skip unreadable files
      }
    });

    return findings;
  }

  private auditController(filePath: string, dirPath: string, findings: ScanFindingInput[]) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const relPath = path.relative(dirPath, filePath).replace(/\\/g, '/');

    if (relPath.includes('auth.controller.ts')) return; // login/register are naturally public

    const classLevelGuarded = this.isClassLevelGuarded(lines);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      if (ROUTE_DECORATOR.test(line)) {
        const methodGuarded = classLevelGuarded || this.hasPrecedingGuard(lines, i);
        if (!methodGuarded) {
          findings.push({
            title: 'Exposed API Endpoint Without Authentication Guard',
            description: `Route decorator "${line}" has no @UseGuards applied at the class or method level.`,
            severity: 'HIGH',
            filePath: relPath,
            lineNumber: i + 1,
            cweId: 'CWE-306',
            mitreId: 'T1592',
            remediation: 'Apply `@UseGuards(JwtAuthGuard)` to the controller class or this specific route method to restrict access.',
            cvssScore: 8.5,
            pesScore: 85.0,
          });
        }
      }

      if (line.includes('executeRawUnsafe(') || line.includes('$executeRawUnsafe(')) {
        findings.push({
          title: 'Unparameterized Raw Database Query execution',
          description: 'Controller or associated service runs a raw database query using raw unparameterized string inputs, raising SQL injection hazards.',
          severity: 'CRITICAL',
          filePath: relPath,
          lineNumber: i + 1,
          cweId: 'CWE-89',
          mitreId: 'T1190',
          remediation: 'Use parameterized input queries (e.g. Prisma query parameters `$queryRaw` or bound ORM methods) instead of `executeRawUnsafe`.',
          cvssScore: 9.8,
          pesScore: 98.0,
        });
      }
    }
  }

  /** A @UseGuards decorator sitting directly above the class declaration
   * (ignoring other class-level decorators like @Controller/@ApiTags in between)
   * protects every route in the file. */
  private isClassLevelGuarded(lines: string[]): boolean {
    for (let i = 0; i < lines.length; i++) {
      if (CLASS_DECLARATION.test(lines[i].trim())) {
        for (let j = i - 1; j >= 0; j--) {
          const prev = lines[j].trim();
          if (prev === '') continue;
          if (GUARD_DECORATOR.test(prev)) return true;
          if (!prev.startsWith('@')) break; // hit non-decorator code, stop looking
        }
        return false;
      }
    }
    return false;
  }

  /** Looks upward from a route decorator line for a @UseGuards decorator
   * stacked directly above it (decorators can appear in any order), stopping
   * at the previous route decorator, blank line, or non-decorator code. */
  private hasPrecedingGuard(lines: string[], routeLineIndex: number): boolean {
    for (let j = routeLineIndex - 1; j >= 0; j--) {
      const prev = lines[j].trim();
      if (prev === '') break;
      if (GUARD_DECORATOR.test(prev)) return true;
      if (ROUTE_DECORATOR.test(prev)) break; // reached the previous route's decorator stack
      if (!prev.startsWith('@')) break; // hit method signature/body of a prior route
    }
    return false;
  }

  private async walkDirectory(dir: string, callback: (filePath: string) => void): Promise<void> {
    try {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const filepath = path.join(dir, file);
        const stats = fs.statSync(filepath);
        if (stats.isDirectory()) {
          await this.walkDirectory(filepath, callback);
        } else {
          callback(filepath);
        }
      }
    } catch {
      // Directory access issue
    }
  }
}
