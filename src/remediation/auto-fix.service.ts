import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import Anthropic from '@anthropic-ai/sdk';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from '../audit/audit-log.service';

const execFileAsync = promisify(execFile);

export interface AutoFixResult {
  success: boolean;
  branchName: string;
  diff: string;
  message: string;
  /** How the replacement was produced — callers should treat 'ai-suggested'
   * fixes as unverified and require human review before merging. */
  method: 'deterministic' | 'ai-suggested' | 'none';
}

const AI_CONTEXT_LINES = 5;

@Injectable()
export class AutoFixService {
  private readonly logger = new Logger(AutoFixService.name);
  private readonly anthropic: Anthropic | null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
  ) {
    // AI-assisted suggestions are entirely opt-in: without ANTHROPIC_API_KEY set,
    // this service only ever applies the small set of deterministic patterns
    // below, at zero API cost. Set the key to also get AI-suggested patches
    // (clearly labeled as unverified) for findings that don't match a pattern.
    this.anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;
  }

  /**
   * Automatically patches the vulnerable line in a file, creates a Git branch,
   * commits the correction, and returns the diff.
   *
   * Findings come from scans of arbitrary customer repositories (cloned into
   * a temporary workspace that's deleted once the scan finishes), so the
   * target file no longer exists on this server's disk by the time a fix is
   * requested. This re-clones the repository the finding came from into a
   * fresh temp workspace, patches it there, and cleans up afterward — the
   * branch/commit are local-only artifacts used to compute a reviewable diff,
   * not pushed anywhere (this app holds no write credentials to customer repos).
   */
  async applyFix(findingId: string, tenantId: string): Promise<AutoFixResult> {
    const finding = await this.prisma.finding.findFirst({
      where: { id: findingId, tenantId },
      include: { scan: { include: { repository: true } } },
    });

    if (!finding) {
      throw new NotFoundException(`Finding ${findingId} not found`);
    }

    if (!finding.filePath || !finding.lineNumber) {
      return {
        success: false,
        branchName: '',
        diff: '',
        method: 'none',
        message: 'This finding does not specify a valid source file path or line number.',
      };
    }

    const repositoryUrl = finding.scan?.repository?.url;
    if (!repositoryUrl) {
      return {
        success: false,
        branchName: '',
        diff: '',
        method: 'none',
        message: 'This finding is not associated with a repository that can be re-cloned for patching.',
      };
    }

    const workspacePath = path.join(os.tmpdir(), `shield-autofix-${findingId}`);
    await fs.promises.rm(workspacePath, { recursive: true, force: true }).catch(() => {});

    try {
      try {
        await execFileAsync('git', ['clone', '--depth', '1', '--', repositoryUrl, workspacePath], {
          timeout: 3 * 60 * 1000,
          maxBuffer: 20 * 1024 * 1024,
        });
      } catch (cloneErr: any) {
        return {
          success: false,
          branchName: '',
          diff: '',
          method: 'none',
          message: `Could not re-clone repository to apply fix: ${cloneErr.message}`,
        };
      }

      const repoRoot = workspacePath;
      const fullPath = path.resolve(repoRoot, finding.filePath);
      const relPath = path.relative(repoRoot, fullPath);
      if (relPath.startsWith('..') || path.isAbsolute(relPath)) {
        throw new BadRequestException('Finding file path resolves outside the repository root.');
      }

      if (!fs.existsSync(fullPath)) {
        return {
          success: false,
          branchName: '',
          diff: '',
          method: 'none',
          message: `Target file was not found in the repository at: ${finding.filePath}`,
        };
      }

      // 1. Read original content
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split('\n');
      const originalLine = lines[finding.lineNumber - 1];

      // 2. Resolve a replacement: try the known-safe deterministic patterns first,
      // then fall back to an AI-suggested patch only if a key is configured.
      let replacement = this.resolveDeterministicReplacement(originalLine);
      let method: AutoFixResult['method'] = replacement ? 'deterministic' : 'none';

      if (!replacement && this.anthropic) {
        replacement = await this.suggestAiReplacement(lines, finding.lineNumber, finding.title, finding.description);
        if (replacement) method = 'ai-suggested';
      }

      if (!replacement) {
        return {
          success: false,
          branchName: '',
          diff: '',
          method: 'none',
          message: this.anthropic
            ? `No automated fix pattern matched, and the AI-suggested fix attempt did not return a usable patch for: "${originalLine.trim()}"`
            : `No automated fix pattern available for this finding type. Manual review required. (Set ANTHROPIC_API_KEY to enable AI-suggested fixes for cases like this.)`,
        };
      }

      // Create Git branch name
      const cleanTitle = finding.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').substring(0, 30);
      const branchName = `shield/remediate-${cleanTitle}-${findingId.substring(0, 6)}`;

      this.logger.log(`Starting Git auto-remediation transaction for branch: ${branchName} (method=${method})`);

      execFileSync('git', ['checkout', '-b', branchName], { cwd: repoRoot, stdio: 'ignore' });

      // 3. Write patch change to file
      lines[finding.lineNumber - 1] = replacement;
      fs.writeFileSync(fullPath, lines.join('\n'), 'utf8');

      // 4. Calculate diff
      let diff = '';
      try {
        diff = execFileSync('git', ['diff', '--', relPath], { cwd: repoRoot, encoding: 'utf8' });
      } catch {
        // Diff generation fallback
      }

      // 5. Commit the changes (local only — never pushed; this clone is deleted after this call)
      try {
        execFileSync('git', ['add', '--', relPath], { cwd: repoRoot, stdio: 'ignore' });
        execFileSync(
          'git',
          ['commit', '-m', `security(shield): ${method === 'ai-suggested' ? 'AI-suggested' : 'auto'}-remediated ${finding.title} in ${relPath}`],
          { cwd: repoRoot, stdio: 'ignore' },
        );
      } catch (commitErr: any) {
        this.logger.warn(`Commit failed (possibly no changes or config missing): ${commitErr.message}`);
      }

      await this.auditLog.log(tenantId, 'AUTO_REMEDIATION_APPLIED', `finding:${findingId}`, {
        filePath: finding.filePath,
        lineNumber: finding.lineNumber,
        branchName,
        method,
      });

      return {
        success: true,
        branchName,
        diff,
        method,
        message: method === 'ai-suggested'
          ? 'AI-suggested patch generated and committed to a local branch in a scratch clone. UNVERIFIED — review carefully before applying to your repository; the model may misunderstand context.'
          : 'Vulnerability patch formulated and committed to a local branch in a scratch clone. Not pushed — apply this diff to your own repository to keep it.',
      };
    } catch (error: any) {
      this.logger.error(`Remediation patch failed for finding ${findingId}:`, error);
      return {
        success: false,
        branchName: '',
        diff: '',
        method: 'none',
        message: `Auto-fix execution failed: ${error.message}`,
      };
    } finally {
      await fs.promises.rm(workspacePath, { recursive: true, force: true }).catch((err) => {
        this.logger.warn(`Failed to clean up auto-fix workspace ${workspacePath}: ${err.message}`);
      });
    }
  }

  /**
   * Known-safe, deterministic single-line rewrites. Returns null (not a
   * generic comment) when nothing matches — callers must not treat "no match"
   * as a successful fix.
   */
  private resolveDeterministicReplacement(originalLine: string): string | null {
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

    return null;
  }

  /**
   * Asks Claude Haiku (cheapest available model — this is a small single-line
   * patch task, not a large context job) for a corrected replacement of one
   * line, given a few lines of surrounding context and the finding's own
   * description. Returns null on any error, timeout, or unusable response —
   * callers must never treat this as more reliable than it is.
   */
  private async suggestAiReplacement(
    lines: string[],
    lineNumber: number,
    findingTitle: string,
    findingDescription: string,
  ): Promise<string | null> {
    if (!this.anthropic) return null;

    const start = Math.max(0, lineNumber - 1 - AI_CONTEXT_LINES);
    const end = Math.min(lines.length, lineNumber + AI_CONTEXT_LINES);
    const contextBlock = lines
      .slice(start, end)
      .map((l, i) => `${start + i + 1}${start + i + 1 === lineNumber ? ' >> ' : ':   '}${l}`)
      .join('\n');

    try {
      const response = await this.anthropic.messages.create({
        model: 'claude-haiku-4-5',
        max_tokens: 300,
        system:
          'You fix one specific vulnerable line of source code. You are given surrounding context lines (numbered) ' +
          'and the line marked with ">>" is the one to fix. Reply with ONLY the corrected replacement text for that ' +
          'single marked line (it may span multiple lines if needed) — no markdown fences, no explanation, no line numbers.',
        messages: [
          {
            role: 'user',
            content: `Finding: ${findingTitle}\nDescription: ${findingDescription}\n\nContext:\n${contextBlock}\n\nReturn only the corrected version of the marked line.`,
          },
        ],
      });

      const text = response.content.find((b) => b.type === 'text')?.text?.trim();
      if (!text) return null;
      return text;
    } catch (error: any) {
      this.logger.warn(`AI fix suggestion failed: ${error.message}`);
      return null;
    }
  }
}
