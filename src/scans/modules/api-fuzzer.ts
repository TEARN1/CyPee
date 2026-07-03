import * as fs from 'fs';
import * as path from 'path';
import { ScanFindingInput } from './secret-excavator';

export class APIFuzzer {
  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];
    await this.walkDirectory(dirPath, (filePath) => {
      // Exclude dependency folders and logs
      if (filePath.includes('node_modules') || filePath.includes('.git') || filePath.includes('dist')) {
        return;
      }

      const filename = path.basename(filePath).toLowerCase();

      try {
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) return;

        // Audit Controller files
        if (filename.endsWith('.controller.ts') || filename.endsWith('.controller.js')) {
          this.auditController(filePath, findings);
        }
      } catch {
        // Skip unreadable files
      }
    });

    return findings;
  }

  private auditController(filePath: string, findings: ScanFindingInput[]) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');

    let currentControllerClass = '';
    let isGuarded = false;

    // First scan to check if the controller class has a global guard
    const classRegex = /class\s+(\w+Controller)/;
    const classMatch = classRegex.exec(content);
    if (classMatch) {
      currentControllerClass = classMatch[1];
    }

    // Check if controller has class-level UseGuards or specific auth checks
    const classLevelGuardRegex = /@Controller\([\s\S]*?\)\s*@UseGuards\(/;
    if (classLevelGuardRegex.test(content) || content.includes('@UseGuards(')) {
      isGuarded = true;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // Check for exposed routes without authentication guards
      if (line.startsWith('@Get(') || line.startsWith('@Post(') || line.startsWith('@Put(') || line.startsWith('@Delete(')) {
        // Look up preceding decorators for guards, but if there are no @UseGuards annotations anywhere in this file, flag it
        if (!isGuarded) {
          // Exclude auth routes which are naturally public
          if (!relPath.includes('auth.controller.ts')) {
            findings.push({
              title: 'Exposed API Endpoint Without Authentication Guard',
              description: `Controller route "${line}" is missing authorization decorators or authentication guards (e.g. JwtAuthGuard).`,
              severity: 'HIGH',
              filePath: relPath,
              lineNumber: i + 1,
              cweId: 'CWE-306',
              mitreId: 'T1592',
              remediation: 'Apply `@UseGuards(JwtAuthGuard)` to the controller class or individual route methods to restrict access.',
              cvssScore: 8.5,
              pesScore: 85.0,
            });
          }
        }
      }

      // Check for vulnerable parameters in queries
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
