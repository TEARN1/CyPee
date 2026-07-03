import * as fs from 'fs';
import * as path from 'path';

export interface ScanFindingInput {
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  lineNumber: number;
  cweId: string;
  mitreId: string;
  remediation: string;
  cvssScore: number;
  pesScore: number;
}

export class SecretExcavator {
  private readonly regexes = [
    {
      name: 'AWS Access Key ID',
      regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
      severity: 'CRITICAL' as const,
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Immediately revoke the AWS credential in AWS IAM console and rotate keys.',
      cvssScore: 9.8,
    },
    {
      name: 'Generic Database Connection String with Credentials',
      regex: /(postgresql|mysql|mongodb|mongodb\+srv|redis|sqlite):\/\/[^:]+:[^@]+@/,
      severity: 'CRITICAL' as const,
      cweId: 'CWE-798',
      mitreId: 'T1552.001',
      remediation: 'Move database connection credentials to an external environment variable config (.env) or Secret Vault.',
      cvssScore: 9.8,
    },
    {
      name: 'Private Cryptographic Key PEM Block',
      regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----/,
      severity: 'HIGH' as const,
      cweId: 'CWE-321',
      mitreId: 'T1552.004',
      remediation: 'Remove private keys from source control. Use key management vaults (AWS KMS, HashiCorp Vault) or Environment variables.',
      cvssScore: 8.5,
    },
    {
      name: 'Slack Webhook URL',
      regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
      severity: 'HIGH' as const,
      cweId: 'CWE-522',
      mitreId: 'T1552',
      remediation: 'Revoke the webhook secret and store webhook paths securely outside repository codebase.',
      cvssScore: 7.8,
    },
  ];

  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];
    await this.walkDirectory(dirPath, (filePath) => {
      // Exclude dependency folders and logs
      if (filePath.includes('node_modules') || filePath.includes('.git') || filePath.includes('.next') || filePath.includes('dist')) {
        return;
      }

      try {
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) return;

        // Only scan text-based files
        const ext = path.extname(filePath).toLowerCase();
        const allowedExts = ['.ts', '.js', '.json', '.env', '.yml', '.yaml', '.xml', '.config', '.cs', '.py', '.java', '.go'];
        if (!allowedExts.includes(ext) && !filePath.endsWith('.env')) return;

        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const rule of this.regexes) {
            const match = rule.regex.exec(line);
            if (match) {
              // Get relative path for clean display
              const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
              findings.push({
                title: `Hardcoded ${rule.name}`,
                description: `Exposed credential token found: "${match[0].substring(0, 12)}..." indicating plain-text storage of security parameters in source control.`,
                severity: rule.severity,
                filePath: relPath,
                lineNumber: i + 1,
                cweId: rule.cweId,
                mitreId: rule.mitreId,
                remediation: rule.remediation,
                cvssScore: rule.cvssScore,
                pesScore: rule.cvssScore * 10,
              });
            }
          }
        }
      } catch {
        // Skip unreadable files
      }
    });

    return findings;
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
