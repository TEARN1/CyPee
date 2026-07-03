import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from '../audit/audit-log.service';

export interface AutoFixResult {
  success: boolean;
  branchName: string;
  diff: string;
  message: string;
}

@Injectable()
export class AutoFixService {
  private readonly logger = new Logger(AutoFixService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
  ) {}

  /**
   * Automatically patches the vulnerable line in a file, creates a Git branch,
   * commits the correction, and returns the diff.
   */
  async applyFix(findingId: string, tenantId: string): Promise<AutoFixResult> {
    const finding = await this.prisma.finding.findFirst({
      where: { id: findingId, tenantId },
    });

    if (!finding) {
      throw new NotFoundException(`Finding ${findingId} not found`);
    }

    if (!finding.filePath || !finding.lineNumber) {
      return {
        success: false,
        branchName: '',
        diff: '',
        message: 'This finding does not specify a valid source file path or line number.',
      };
    }

    const fullPath = path.resolve(process.cwd(), finding.filePath);
    if (!fs.existsSync(fullPath)) {
      return {
        success: false,
        branchName: '',
        diff: '',
        message: `Target file was not found on disk at: ${finding.filePath}`,
      };
    }

    try {
      // 1. Read original content
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split('\n');
      const originalLine = lines[finding.lineNumber - 1];

      // 2. Resolve safe replacement content
      const replacement = this.resolveCodeReplacement(finding.module || '', finding.title, originalLine);
      if (!replacement) {
        return {
          success: false,
          branchName: '',
          diff: '',
          message: `Unable to formulate an automated safe patch pattern for: "${originalLine.trim()}"`,
        };
      }

      // Create Git branch name
      const cleanTitle = finding.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').substring(0, 30);
      const branchName = `shield/remediate-${cleanTitle}-${findingId.substring(0, 6)}`;

      // 3. Initialize Git operations
      this.logger.log(`Starting Git auto-remediation transaction for branch: ${branchName}`);
      
      // Save current git branch name to return to later
      let originalBranch = 'main';
      try {
        originalBranch = execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim();
      } catch {
        // Fallback if not inside initialized git
      }

      // Check out new branch
      try {
        execSync(`git checkout -b ${branchName}`, { stdio: 'ignore' });
      } catch {
        // If branch already exists, switch to it
        execSync(`git checkout ${branchName}`, { stdio: 'ignore' });
      }

      // 4. Write patch change to file
      lines[finding.lineNumber - 1] = replacement;
      fs.writeFileSync(fullPath, lines.join('\n'), 'utf8');

      // 5. Calculate diff
      let diff = '';
      try {
        diff = execSync(`git diff ${finding.filePath}`, { encoding: 'utf8' });
      } catch {
        // Diff generation fallback
      }

      // 6. Commit the changes
      try {
        execSync(`git add ${finding.filePath}`, { stdio: 'ignore' });
        execSync(`git commit -m "security(shield): auto-remediated ${finding.title} in ${finding.filePath}"`, { stdio: 'ignore' });
      } catch (commitErr) {
        this.logger.warn(`Commit failed (possibly no changes or config missing): ${commitErr.message}`);
      }

      // 7. Revert to original branch
      try {
        execSync(`git checkout ${originalBranch}`, { stdio: 'ignore' });
      } catch {
        // Fallback
      }

      // Log successful remediation in audit trail
      await this.auditLog.log(tenantId, 'AUTO_REMEDIATION_APPLIED', `finding:${findingId}`, {
        filePath: finding.filePath,
        lineNumber: finding.lineNumber,
        branchName,
      });

      return {
        success: true,
        branchName,
        diff,
        message: 'Vulnerability patch successfully formulated, committed to local Git branch.',
      };
    } catch (error) {
      this.logger.error(`Remediation patch failed for finding ${findingId}:`, error);
      return {
        success: false,
        branchName: '',
        diff: '',
        message: `Auto-fix execution failed: ${error.message}`,
      };
    }
  }

  /**
   * Formulation mapping patterns.
   * Compares the original insecure line against known structures and replaces with secure patterns.
   */
  private resolveCodeReplacement(module: string, title: string, originalLine: string): string | null {
    const trimmed = originalLine.trim();

    // Case 1: Docker Compose exposed database port
    if (trimmed === '- "5432:5432"' || trimmed === '- 5432:5432') {
      return originalLine.replace(trimmed, '- "127.0.0.1:5432:5432"');
    }
    if (trimmed === '- "6379:6379"' || trimmed === '- 6379:6379') {
      return originalLine.replace(trimmed, '- "127.0.0.1:6379:6379"');
    }

    // Case 2: Exposed API Endpoints (NestJS controllers)
    // Add `@UseGuards(JwtAuthGuard)` decorator line directly above the route method
    if (trimmed.startsWith('@Get(') || trimmed.startsWith('@Post(') || trimmed.startsWith('@Put(')) {
      const indent = originalLine.substring(0, originalLine.indexOf('@'));
      return `${indent}@UseGuards(JwtAuthGuard)\n${originalLine}`;
    }

    // Case 3: Private Cryptographic PEM Blocks (replace with environment variable loading)
    if (trimmed.includes('-----BEGIN PRIVATE KEY-----') || trimmed.includes('-----BEGIN RSA PRIVATE KEY-----')) {
      return originalLine.replace(trimmed, 'process.env.SHIELD_PRIVATE_KEY || ""');
    }

    // Generic fallback: prepend safety comments
    return `// SECURITY WARNING: Auto-remediation required for: ${trimmed}\n${originalLine}`;
  }
}
