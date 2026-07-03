import * as fs from 'fs';
import * as path from 'path';
import { ScanFindingInput } from './secret-excavator';

export class SupplyChainIntegrity {
  // Popular packages to check typosquatting against
  private readonly popularPackages = [
    'lodash', 'express', 'react', 'react-dom', 'typescript', 'axios', 
    'dotenv', 'prisma', 'helmet', 'bcrypt', 'passport', 'rxjs'
  ];

  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];

    const packageJsonPath = path.join(dirPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) return findings;

    try {
      const pJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      const dependencies = {
        ...(pJson.dependencies || {}),
        ...(pJson.devDependencies || {}),
      };

      const relPath = path.relative(process.cwd(), packageJsonPath).replace(/\\/g, '/');

      // 1. Check Typosquatting
      for (const depName of Object.keys(dependencies)) {
        for (const popName of this.popularPackages) {
          if (depName !== popName && this.levenshteinDistance(depName, popName) === 1) {
            findings.push({
              title: 'Dependency Typosquatting Risk detected',
              description: `Installed package "${depName}" is suspiciously similar to popular package "${popName}". Attackers use typosquatting to trick developers into running remote malicious code.`,
              severity: 'CRITICAL',
              filePath: relPath,
              lineNumber: 1,
              cweId: 'CWE-94',
              mitreId: 'T1195.002',
              remediation: `Verify the package spelling. If it was a typo, remove the dependency (e.g. npm uninstall ${depName}) and install the correct package.`,
              cvssScore: 9.6,
              pesScore: 96.0,
            });
          }
        }

        // 2. Check for dependency reference to git URLs / local tarballs (supply chain hazard)
        const version = dependencies[depName] as string;
        if (version.startsWith('git') || version.includes('github.com') || version.startsWith('file:')) {
          if (!version.includes('dev.db')) { // skip our SQLite url override check
            findings.push({
              title: 'Source Code Dependency supply chain hazard',
              description: `Dependency "${depName}" references a raw git URL or local path instead of a static npm registry package: "${version}". Untracked changes on git repositories can inject malware without changing version flags.`,
              severity: 'MEDIUM',
              filePath: relPath,
              lineNumber: 1,
              cweId: 'CWE-829',
              mitreId: 'T1195',
              remediation: `Lock the dependency to a specific git commit hash reference (e.g. "git+https://...#commit-hash") or publish/use standard scoped npm packages.`,
              cvssScore: 5.3,
              pesScore: 53.0,
            });
          }
        }
      }
    } catch {
      // JSON format error
    }

    return findings;
  }

  /**
   * Helper Levenshtein distance check to match typosquatting patterns.
   */
  private levenshteinDistance(s1: string, s2: string): number {
    const track = Array(s2.length + 1).fill(null).map(() => Array(s1.length + 1).fill(null));
    for (let i = 0; i <= s1.length; i += 1) track[0][i] = i;
    for (let j = 0; j <= s2.length; j += 1) track[j][0] = j;

    for (let j = 1; j <= s2.length; j += 1) {
      for (let i = 1; i <= s1.length; i += 1) {
        const indicator = s1[i - 1] === s2[j - 1] ? 0 : 1;
        track[j][i] = Math.min(
          track[j][i - 1] + 1, // deletion
          track[j - 1][i] + 1, // insertion
          track[j - 1][i - 1] + indicator, // substitution
        );
      }
    }
    return track[s2.length][s1.length];
  }
}
