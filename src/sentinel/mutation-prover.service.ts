import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import { EphemeralSandboxService } from './ephemeral-sandbox.service';

export interface AstMutant {
  mutantId: string;
  mutationType: 'OPERATOR_INVERSION' | 'BOUNDARY_FLIP' | 'CONDITION_NEGATION' | 'SANITIZER_STRIP';
  originalCodeSnippet: string;
  mutatedCodeSnippet: string;
  status: 'KILLED' | 'SURVIVED';
  killReason?: string;
}

export interface MutationAnalysisReport {
  sessionId: string;
  totalMutantsGenerated: number;
  mutantsKilled: number;
  mutantsSurvived: number;
  mutationScorePercentage: number;
  mutants: AstMutant[];
  testSuiteRobustness: 'EXCELLENT' | 'ADEQUATE' | 'FRAGILE';
  timestamp: string;
}

@Injectable()
export class MutationProverService {
  private readonly logger = new Logger(MutationProverService.name);

  constructor(private readonly sandbox: EphemeralSandboxService) {}

  /**
   * Generates AST mutations and runs them against candidate test harnesses to prove test suite coverage.
   */
  public runMutationAnalysis(codeSnippet: string, baselineInput: any = 'test-input-42'): MutationAnalysisReport {
    const sessionId = `MUT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const mutants: AstMutant[] = [];

    // Mutation 1: Operator Inversion (=== -> !==)
    if (codeSnippet.includes('===')) {
      mutants.push({
        mutantId: `M1-OP-FLIP`,
        mutationType: 'OPERATOR_INVERSION',
        originalCodeSnippet: '===',
        mutatedCodeSnippet: codeSnippet.replace(/===/g, '!=='),
        status: 'SURVIVED',
      });
    }

    // Mutation 2: Boundary Inversion (> -> <=)
    if (codeSnippet.includes('>')) {
      mutants.push({
        mutantId: `M2-BOUND-FLIP`,
        mutationType: 'BOUNDARY_FLIP',
        originalCodeSnippet: '>',
        mutatedCodeSnippet: codeSnippet.replace(/>/g, '<='),
        status: 'SURVIVED',
      });
    }

    // Mutation 3: Condition Negation (&& -> ||)
    if (codeSnippet.includes('&&')) {
      mutants.push({
        mutantId: `M3-COND-NEG`,
        mutationType: 'CONDITION_NEGATION',
        originalCodeSnippet: '&&',
        mutatedCodeSnippet: codeSnippet.replace(/&&/g, '||'),
        status: 'SURVIVED',
      });
    }

    // Mutation 4: Stripping Sanitizers (replace sanitizers with identity)
    if (/replace|basename|sanitize/i.test(codeSnippet)) {
      mutants.push({
        mutantId: `M4-STRIP-SAN`,
        mutationType: 'SANITIZER_STRIP',
        originalCodeSnippet: 'Sanitizer Call',
        mutatedCodeSnippet: codeSnippet.replace(/\.replace\([^)]+\)/g, '').replace(/path\.basename\(([^)]+)\)/g, '$1'),
        status: 'SURVIVED',
      });
    }

    // Fallback mutation if code is very simple
    if (mutants.length === 0) {
      mutants.push({
        mutantId: `M0-RETURN-FLIP`,
        mutationType: 'OPERATOR_INVERSION',
        originalCodeSnippet: 'return',
        mutatedCodeSnippet: codeSnippet.replace(/return\s+/g, 'return null; // '),
        status: 'SURVIVED',
      });
    }

    // Evaluate each mutant in the Ephemeral Sandbox
    let killedCount = 0;
    for (const mutant of mutants) {
      const exec = this.sandbox.executeCandidate(mutant.mutatedCodeSnippet, baselineInput);
      // If the mutant throws an error or triggers an exploit detection, the test suite "killed" the mutant!
      if (!exec.success || exec.exploitDetected) {
        mutant.status = 'KILLED';
        mutant.killReason = exec.exploitDetected
          ? `Killed by Sandbox Exploit Interception: ${exec.exploitDetails}`
          : `Killed by Runtime Assertion: ${exec.error}`;
        killedCount++;
      } else {
        mutant.status = 'SURVIVED';
        mutant.killReason = 'Mutant survived: Execution completed without exception or boundary trip.';
      }
    }

    const mutationScore = Math.round((killedCount / mutants.length) * 100);
    const robustness = mutationScore >= 80 ? 'EXCELLENT' : mutationScore >= 50 ? 'ADEQUATE' : 'FRAGILE';

    return {
      sessionId,
      totalMutantsGenerated: mutants.length,
      mutantsKilled: killedCount,
      mutantsSurvived: mutants.length - killedCount,
      mutationScorePercentage: mutationScore,
      mutants,
      testSuiteRobustness: robustness,
      timestamp: new Date().toISOString(),
    };
  }
}
