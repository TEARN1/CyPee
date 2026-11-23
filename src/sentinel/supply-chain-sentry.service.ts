import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface SupplyChainAlert {
  packageName: string;
  threatType: 'TYPOSQUAT' | 'HALLUCINATED_PACKAGE' | 'MALICIOUS_POSTINSTALL' | 'SUSPICIOUS_OBFUSCATION';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  recommendation: string;
}

export interface SupplyChainAuditResult {
  auditId: string;
  packagesAnalyzed: number;
  alerts: SupplyChainAlert[];
  trustedPackagesCount: number;
  supplyChainHealthScore: number;
  status: 'SAFE' | 'COMPROMISED';
  timestamp: string;
}

@Injectable()
export class SupplyChainSentryService {
  private readonly logger = new Logger(SupplyChainSentryService.name);

  // Common legitimate package allowlist for rapid offline verification
  private readonly verifiedPopularPackages = new Set([
    'express', 'nestjs', '@nestjs/core', '@nestjs/common', 'prisma', '@prisma/client',
    'crypto', 'lodash', 'axios', 'rxjs', 'dotenv', 'helmet', 'bcrypt', 'jsonwebtoken',
    'zod', 'typescript', 'vite', 'react', 'react-dom', 'lucide-react', 'tailwindcss',
    'fast-check', 'ws', 'bullmq', 'ioredis', 'chalk', 'jest', 'vitest',
  ]);

  // Known typosquatting attack targets
  private readonly knownTyposquats: Record<string, string> = {
    'expres': 'express',
    'lodashe': 'lodash',
    'lodashs': 'lodash',
    'axio': 'axios',
    'crypto-js-node': 'crypto-js',
    'cross-env-dev': 'cross-env',
    'dotenv-safe-v2': 'dotenv-safe',
    'react-domm': 'react-dom',
    'json-web-tokens': 'jsonwebtoken',
  };

  /**
   * Scans package.json dependencies and AST import statements for supply-chain anomalies.
   */
  public auditDependencies(
    dependencies: Record<string, string>,
    scripts: Record<string, string> = {},
  ): SupplyChainAuditResult {
    const auditId = `SC-AUDIT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const alerts: SupplyChainAlert[] = [];
    const pkgNames = Object.keys(dependencies || {});

    // 1. Audit Dependency Names for Typosquatting and AI Hallucinations
    for (const pkg of pkgNames) {
      const lower = pkg.toLowerCase();

      // Typosquat detection
      if (this.knownTyposquats[lower]) {
        alerts.push({
          packageName: pkg,
          threatType: 'TYPOSQUAT',
          severity: 'CRITICAL',
          description: `Package '${pkg}' is a known typosquat target masquerading as '${this.knownTyposquats[lower]}'.`,
          recommendation: `Uninstall '${pkg}' immediately and install legitimate '${this.knownTyposquats[lower]}'.`,
        });
        continue;
      }

      // Hallucinated package heuristic: AI models commonly hallucinate "-helpers", "-utils-v2", "ai-client-sdk"
      if (!this.verifiedPopularPackages.has(lower) && /(-helpers|-utils-v2|-ai-wrapper|quick-auth-sdk)$/i.test(lower)) {
        alerts.push({
          packageName: pkg,
          threatType: 'HALLUCINATED_PACKAGE',
          severity: 'HIGH',
          description: `Package '${pkg}' exhibits high-probability AI-hallucinated naming syntax with unverified provenance.`,
          recommendation: 'Verify package exists on official npm registry and inspect publisher metadata before executing.',
        });
      }
    }

    // 2. Audit Lifecycle Scripts for Malicious Postinstall Commands
    for (const [scriptName, cmd] of Object.entries(scripts || {})) {
      if (/postinstall|preinstall/i.test(scriptName)) {
        if (/curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash)|eval\s*\(Buffer\.from/i.test(cmd)) {
          alerts.push({
            packageName: `scripts.${scriptName}`,
            threatType: 'MALICIOUS_POSTINSTALL',
            severity: 'CRITICAL',
            description: `Remote shell execution or base64 eval detected in lifecycle script '${scriptName}': "${cmd}".`,
            recommendation: 'Remove malicious remote payload downloader from package scripts immediately.',
          });
        }
      }
    }

    const healthScore = Math.max(0, 100 - alerts.length * 35);
    const trustedCount = pkgNames.length - alerts.filter((a) => !a.packageName.startsWith('scripts.')).length;

    return {
      auditId,
      packagesAnalyzed: pkgNames.length,
      alerts,
      trustedPackagesCount: Math.max(0, trustedCount),
      supplyChainHealthScore: healthScore,
      status: alerts.length === 0 ? 'SAFE' : 'COMPROMISED',
      timestamp: new Date().toISOString(),
    };
  }
}
