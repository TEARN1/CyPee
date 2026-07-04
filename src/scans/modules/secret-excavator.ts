import * as fs from 'fs';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { Logger } from '@nestjs/common';

const execFileAsync = promisify(execFile);

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

interface SecretRule {
  name: string;
  regex: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cweId: string;
  mitreId: string;
  remediation: string;
  cvssScore: number;
}

// Values that commonly trip regex-only rules but aren't real secrets.
const PLACEHOLDER_PATTERNS = [
  /changeme/i,
  /example/i,
  /placeholder/i,
  /your[-_]?(api|secret|key)/i,
  /xxxxx/i,
  /0{10,}/,
  /dummy/i,
  /test[-_]?key/i,
];

function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(value));
}

/** Shannon entropy in bits per character. Real secrets (random tokens, keys)
 * score high; English words, repeated chars, and boilerplate score low. */
function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export class SecretExcavator {
  private readonly logger = new Logger(SecretExcavator.name);

  private readonly regexes: SecretRule[] = [
    {
      name: 'AWS Access Key ID',
      regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Immediately revoke the AWS credential in AWS IAM console and rotate keys.',
      cvssScore: 9.8,
    },
    {
      name: 'AWS Secret Access Key',
      regex: /aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/i,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Immediately revoke the AWS credential in AWS IAM console and rotate keys.',
      cvssScore: 9.8,
    },
    {
      name: 'Generic Database Connection String with Credentials',
      regex: /(postgresql|mysql|mongodb|mongodb\+srv|redis|sqlite):\/\/[^:]+:[^@]+@/,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552.001',
      remediation: 'Move database connection credentials to an external environment variable config (.env) or Secret Vault.',
      cvssScore: 9.8,
    },
    {
      name: 'Private Cryptographic Key PEM Block',
      regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----/,
      severity: 'HIGH',
      cweId: 'CWE-321',
      mitreId: 'T1552.004',
      remediation: 'Remove private keys from source control. Use key management vaults (AWS KMS, HashiCorp Vault) or Environment variables.',
      cvssScore: 8.5,
    },
    {
      name: 'Slack Webhook URL',
      regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
      severity: 'HIGH',
      cweId: 'CWE-522',
      mitreId: 'T1552',
      remediation: 'Revoke the webhook secret and store webhook paths securely outside repository codebase.',
      cvssScore: 7.8,
    },
    {
      name: 'Slack Token',
      regex: /xox[baprs]-[0-9A-Za-z-]{10,72}/,
      severity: 'HIGH',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the Slack token in the Slack app management console and rotate.',
      cvssScore: 8.1,
    },
    {
      name: 'GitHub Personal Access Token',
      regex: /gh[pousr]_[A-Za-z0-9]{36,255}/,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the token at github.com/settings/tokens and rotate immediately.',
      cvssScore: 9.1,
    },
    {
      name: 'GitHub Fine-Grained PAT',
      regex: /github_pat_[A-Za-z0-9_]{20,255}/,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the token at github.com/settings/tokens and rotate immediately.',
      cvssScore: 9.1,
    },
    {
      name: 'GitLab Personal Access Token',
      regex: /glpat-[A-Za-z0-9_-]{20}/,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the token in GitLab user settings and rotate immediately.',
      cvssScore: 9.1,
    },
    {
      name: 'Stripe Live Secret Key',
      regex: /(sk|rk)_live_[A-Za-z0-9]{20,247}/,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Roll the key in the Stripe dashboard immediately; live keys grant real payment access.',
      cvssScore: 9.8,
    },
    {
      name: 'Twilio API Key',
      regex: /SK[0-9a-fA-F]{32}/,
      severity: 'HIGH',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the key in the Twilio console and rotate.',
      cvssScore: 8.6,
    },
    {
      name: 'SendGrid API Key',
      regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
      severity: 'HIGH',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the key in the SendGrid dashboard and rotate.',
      cvssScore: 8.6,
    },
    {
      name: 'Google API Key',
      regex: /AIza[0-9A-Za-z_-]{35}/,
      severity: 'HIGH',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Restrict/revoke the key in Google Cloud Console credentials page.',
      cvssScore: 8.1,
    },
    {
      name: 'Google OAuth Client Secret',
      regex: /GOCSPX-[A-Za-z0-9_-]{20,}/,
      severity: 'HIGH',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke and regenerate the OAuth client secret in Google Cloud Console.',
      cvssScore: 8.1,
    },
    {
      name: 'npm Access Token',
      regex: /npm_[A-Za-z0-9]{36}/,
      severity: 'HIGH',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the token at npmjs.com access tokens settings and rotate.',
      cvssScore: 8.1,
    },
    {
      name: 'Mailgun API Key',
      regex: /key-[0-9a-zA-Z]{32}/,
      severity: 'MEDIUM',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the key in the Mailgun control panel and rotate.',
      cvssScore: 6.5,
    },
    {
      name: 'Twitter/X Bearer Token',
      regex: /A{22}[A-Za-z0-9%]{80,}/,
      severity: 'HIGH',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Revoke the bearer token in the X Developer Portal and rotate.',
      cvssScore: 7.5,
    },
    {
      name: 'JSON Web Token (JWT)',
      regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
      severity: 'MEDIUM',
      cweId: 'CWE-522',
      mitreId: 'T1552',
      remediation: 'Do not hardcode signed tokens in source; if this token grants access, revoke the underlying session/key.',
      cvssScore: 6.0,
    },
    {
      name: 'Azure Storage Account Key',
      regex: /AccountKey=[A-Za-z0-9+/]{80,}={0,2}/,
      severity: 'CRITICAL',
      cweId: 'CWE-798',
      mitreId: 'T1552',
      remediation: 'Regenerate the storage account key in the Azure Portal immediately.',
      cvssScore: 9.1,
    },
  ];

  private readonly allowedExts = ['.ts', '.js', '.json', '.env', '.yml', '.yaml', '.xml', '.config', '.cs', '.py', '.java', '.go'];
  private readonly excludedDirs = ['node_modules', '.git', '.next', 'dist', 'coverage'];

  async scan(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];

    await this.walkDirectory(dirPath, (filePath) => {
      if (this.excludedDirs.some((d) => filePath.includes(d))) return;

      try {
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) return;

        const ext = path.extname(filePath).toLowerCase();
        if (!this.allowedExts.includes(ext) && !filePath.endsWith('.env')) return;

        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        const relPath = path.relative(dirPath, filePath).replace(/\\/g, '/');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          this.applyRules(line, relPath, i + 1, findings);
          this.applyEntropyCheck(line, relPath, i + 1, findings);
        }
      } catch {
        // Skip unreadable files
      }
    });

    const historyFindings = await this.scanGitHistory(dirPath);
    findings.push(...historyFindings);

    return findings;
  }

  private applyRules(line: string, relPath: string, lineNumber: number, findings: ScanFindingInput[]): void {
    for (const rule of this.regexes) {
      const match = rule.regex.exec(line);
      if (match && !looksLikePlaceholder(match[0])) {
        findings.push({
          title: `Hardcoded ${rule.name}`,
          description: `Exposed credential token found: "${match[0].substring(0, 12)}..." indicating plain-text storage of security parameters in source control.`,
          severity: rule.severity,
          filePath: relPath,
          lineNumber,
          cweId: rule.cweId,
          mitreId: rule.mitreId,
          remediation: rule.remediation,
          cvssScore: rule.cvssScore,
          pesScore: rule.cvssScore * 10,
        });
      }
    }
  }

  /** Flags high-entropy quoted strings assigned to secret-sounding variable names,
   * catching bespoke API keys/tokens that don't match any known provider pattern. */
  private applyEntropyCheck(line: string, relPath: string, lineNumber: number, findings: ScanFindingInput[]): void {
    const assignmentPattern = /(secret|token|api[_-]?key|apikey|access[_-]?key|password|passwd|credential)\s*[=:]\s*['"]([A-Za-z0-9+/_.-]{16,})['"]/gi;
    let match: RegExpExecArray | null;
    while ((match = assignmentPattern.exec(line)) !== null) {
      const value = match[2];
      if (looksLikePlaceholder(value)) continue;
      // Skip values already caught by a specific provider rule to avoid duplicate findings
      if (this.regexes.some((r) => r.regex.test(value))) continue;

      const entropy = shannonEntropy(value);
      if (entropy >= 3.5 && value.length >= 16) {
        findings.push({
          title: 'Possible Hardcoded High-Entropy Secret',
          description: `Variable assignment "${match[1]}" holds a high-entropy string (entropy ${entropy.toFixed(2)} bits/char, length ${value.length}), consistent with an API key, token, or password.`,
          severity: 'MEDIUM',
          filePath: relPath,
          lineNumber,
          cweId: 'CWE-798',
          mitreId: 'T1552',
          remediation: 'Verify whether this value is a live secret. If so, revoke/rotate it and move it to environment variables or a secret vault.',
          cvssScore: 6.5,
          pesScore: 65,
        });
      }
    }
  }

  /** Searches the full git history (not just the working tree) for the same
   * provider-specific patterns, since a secret removed from HEAD often still
   * lives in a past commit. Uses `git log -G<regex>` (pickaxe) so git itself
   * does the history walk instead of us diffing every commit in JS. */
  private async scanGitHistory(dirPath: string): Promise<ScanFindingInput[]> {
    const findings: ScanFindingInput[] = [];
    const gitDir = path.join(dirPath, '.git');
    if (!fs.existsSync(gitDir)) return findings;

    for (const rule of this.regexes) {
      try {
        const { stdout } = await execFileAsync(
          'git',
          ['log', '--all', '-p', '--no-color', `-G${rule.regex.source}`, '--', '.'],
          { cwd: dirPath, maxBuffer: 20 * 1024 * 1024, timeout: 30_000 },
        );
        if (!stdout) continue;

        let currentCommit = 'unknown';
        for (const line of stdout.split('\n')) {
          const commitMatch = /^commit ([0-9a-f]{7,40})/.exec(line);
          if (commitMatch) {
            currentCommit = commitMatch[1].substring(0, 10);
            continue;
          }
          if (!line.startsWith('+') || line.startsWith('+++')) continue;

          const match = rule.regex.exec(line);
          if (match && !looksLikePlaceholder(match[0])) {
            findings.push({
              title: `Hardcoded ${rule.name} (git history)`,
              description: `A ${rule.name} was found in git history at commit ${currentCommit}, even if no longer present in the current working tree. Secrets committed to git remain recoverable from history.`,
              severity: rule.severity,
              filePath: `(git history: ${currentCommit})`,
              lineNumber: 0,
              cweId: rule.cweId,
              mitreId: rule.mitreId,
              remediation: `${rule.remediation} Additionally, this secret must be purged from git history (e.g. git filter-repo) since rotation alone does not remove it from past commits.`,
              cvssScore: rule.cvssScore,
              pesScore: rule.cvssScore * 10,
            });
          }
        }
      } catch (error: any) {
        this.logger.debug(`Git history scan skipped for rule "${rule.name}": ${error.message}`);
      }
    }

    return findings;
  }

  private async walkDirectory(dir: string, callback: (filePath: string) => void): Promise<void> {
    try {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const filepath = path.join(dir, file);
        const stats = fs.statSync(filepath);
        if (stats.isDirectory()) {
          if (this.excludedDirs.includes(file)) continue;
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
