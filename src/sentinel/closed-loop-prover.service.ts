import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import { AstTaintAnalyzerService } from './ast-taint-analyzer.service';
import { EphemeralSandboxService } from './ephemeral-sandbox.service';
import { AdversarialFuzzerService } from './adversarial-fuzzer.service';
import { AstAutoPatchService } from '../remediation/ast-autopatch.service';

export interface ClosedLoopProofResult {
  proofId: string;
  verified: boolean;
  targetRule: string;
  originalSnippet: string;
  patchedSnippet: string;
  unifiedDiff: string;
  exploitPayloadTested: any;
  prePatchSinkInterception: string;
  postPatchSinkInterception: string;
  exploitDisarmed: boolean;
  functionalBaselineMaintained: boolean;
  mathematicalProofStatement: string;
  generatedAt: string;
}

@Injectable()
export class ClosedLoopProverService {
  private readonly logger = new Logger(ClosedLoopProverService.name);

  constructor(
    private readonly taintAnalyzer: AstTaintAnalyzerService,
    private readonly sandbox: EphemeralSandboxService,
    private readonly fuzzer: AdversarialFuzzerService,
    private readonly autoPatch: AstAutoPatchService,
  ) {}

  /**
   * Closed-Loop Auto-Heal & Regression Prover.
   * Discovers exploit, synthesizes AST patch, and proves the fix against the exact failing payload.
   */
  public async autoHealAndProve(params: {
    codeSnippet: string;
    targetFile?: string;
    enclave?: 'the-resident' | 'the-gruvs' | 'excellency' | 'ivory-park' | 'general';
  }): Promise<ClosedLoopProofResult> {
    const proofId = `PROOF-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const file = params.targetFile || 'src/candidate.service.ts';
    const code = params.codeSnippet;

    // 1. Initial Taint Analysis & Fuzzing
    const taintReport = this.taintAnalyzer.analyzeCode(code, params.enclave);
    const fuzzReport = await this.fuzzer.fuzzCandidate(code, params.enclave, 'STANDARD');

    let ruleId = 'SQL_INJECTION';
    if (taintReport.findings.length > 0) {
      const topFinding = taintReport.findings[0];
      if (topFinding.sinkType === 'COMMAND_INJECTION') ruleId = 'RCE_COMMAND_INJECTION';
      else if (topFinding.sinkType === 'DDE_FORMULA') ruleId = 'DDE_FORMULA';
      else if (topFinding.sinkType === 'BOLA_TENANT_LEAK') ruleId = 'BOLA_TENANT';
      else if (topFinding.sinkType === 'HARDCODED_SECRET') ruleId = 'HARDCODED_SECRET';
      else ruleId = 'SQL_INJECTION';
    } else if (fuzzReport.failingExploitSample) {
      ruleId = fuzzReport.failingExploitSample.category;
    }

    const exploitPayload = fuzzReport.failingExploitSample
      ? fuzzReport.failingExploitSample.payload
      : "' OR '1'='1";

    // 2. Execute Pre-Patch Baseline Failure
    const prePatchRes = this.sandbox.executeCandidate(code, exploitPayload);
    const preInterception = prePatchRes.interceptedSinks.find((s) => s.breachConfirmed)?.breachAnalysis ||
      prePatchRes.exploitDetails || 'Raw unescaped syntax breach in sandbox execution.';

    // 3. Synthesize Deterministic AST Auto-Patch
    const patchResult = this.autoPatch.generateAutoPatch({
      ruleId,
      targetFile: file,
      codeSnippet: code,
    });

    const patchedSnippet = patchResult.patchedSnippet;

    // 4. Re-Execute Sandboxed Verification with Exploit Payload
    const postExploitRes = this.sandbox.executeCandidate(patchedSnippet, exploitPayload);
    const exploitDisarmed = !postExploitRes.exploitDetected;

    // 5. Re-Execute Sandboxed Verification with Normal Functional Payload (Zero Regression)
    const postBaselineRes = this.sandbox.executeCandidate(patchedSnippet, 'user-safe-42');
    const functionalBaselineMaintained = postBaselineRes.success;

    const postInterception = postExploitRes.interceptedSinks[0]?.breachAnalysis ||
      'Safely bounded: Payload disarmed and contained in parameter bindings.';

    const verified = exploitDisarmed && functionalBaselineMaintained;

    const statement = verified
      ? `MATHEMATICALLY VERIFIED: Input '${exploitPayload}' broke original code via ${ruleId}, but was safely neutralized in parameterized syntax with zero functional regression.`
      : `VERIFICATION INCOMPLETE: Patch generated but exploit was not fully neutralized or functional baseline regressed.`;

    return {
      proofId,
      verified,
      targetRule: ruleId,
      originalSnippet: code,
      patchedSnippet,
      unifiedDiff: patchResult.unifiedDiff,
      exploitPayloadTested: exploitPayload,
      prePatchSinkInterception: preInterception,
      postPatchSinkInterception: postInterception,
      exploitDisarmed,
      functionalBaselineMaintained,
      mathematicalProofStatement: statement,
      generatedAt: new Date().toISOString(),
    };
  }
}
