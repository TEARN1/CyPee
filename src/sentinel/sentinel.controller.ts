import { Controller, Post, Get, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { AstTaintAnalyzerService } from './ast-taint-analyzer.service';
import { EphemeralSandboxService } from './ephemeral-sandbox.service';
import { AdversarialFuzzerService } from './adversarial-fuzzer.service';
import { ClosedLoopProverService } from './closed-loop-prover.service';
import { SentinelSealService } from './sentinel-seal.service';
import { CfgVisualizerService } from './cfg-visualizer.service';
import { SupplyChainSentryService } from './supply-chain-sentry.service';
import { MutationProverService } from './mutation-prover.service';
import { VibeGuardCliService } from './vibe-guard-cli.service';

// Runs submitted code or changes the whole system: owners only (src/auth/guards/owner.guard.ts).
@UseGuards(JwtAuthGuard, OwnerGuard)
@Controller('api/v1/sentinel')
export class SentinelController {
  constructor(
    private readonly taintAnalyzer: AstTaintAnalyzerService,
    private readonly sandbox: EphemeralSandboxService,
    private readonly fuzzer: AdversarialFuzzerService,
    private readonly prover: ClosedLoopProverService,
    private readonly sealService: SentinelSealService,
    private readonly cfgVisualizer: CfgVisualizerService,
    private readonly supplyChain: SupplyChainSentryService,
    private readonly mutationProver: MutationProverService,
    private readonly vibeGuardCli: VibeGuardCliService,
  ) {}

  /**
   * Static AST Source-to-Sink Taint Flow Analysis
   */
  @Post('analyze')
  @HttpCode(HttpStatus.OK)
  async analyzeTaint(@Body() body: { code: string; enclave?: string }) {
    return this.taintAnalyzer.analyzeCode(body.code, body.enclave);
  }

  /**
   * Ephemeral In-Memory V8 Execution with a specific input
   */
  @Post('execute')
  @HttpCode(HttpStatus.OK)
  async executeSandbox(@Body() body: { code: string; testInput: any; timeoutMs?: number }) {
    return this.sandbox.executeCandidate(body.code, body.testInput, body.timeoutMs);
  }

  /**
   * Grammar-Aware Adversarial Fuzzing Bombardment
   */
  @Post('fuzz')
  @HttpCode(HttpStatus.OK)
  async runAdversarialFuzz(
    @Body() body: {
      code: string;
      enclave?: 'the-resident' | 'the-gruvs' | 'excellency' | 'ivory-park' | 'general';
      intensity?: 'STANDARD' | 'HEAVY' | 'EXTREME';
    },
  ) {
    return this.fuzzer.fuzzCandidate(body.code, body.enclave, body.intensity);
  }

  /**
   * Closed-Loop Deterministic Auto-Heal & Zero-Regression Proof
   */
  @Post('auto-heal')
  @HttpCode(HttpStatus.OK)
  async autoHealAndProve(
    @Body() body: {
      codeSnippet: string;
      targetFile?: string;
      enclave?: 'the-resident' | 'the-gruvs' | 'excellency' | 'ivory-park' | 'general';
    },
  ) {
    return this.prover.autoHealAndProve(body);
  }

  /**
   * Generates Post-Quantum Cryptographic Attestation Merkle Seal
   */
  @Post('seal')
  @HttpCode(HttpStatus.OK)
  async generateSeal(
    @Body() body: {
      code: string;
      enclave?: string;
      payloadsTested?: number;
    },
  ) {
    return this.sealService.generateAttestationSeal(body.code, body.enclave, body.payloadsTested);
  }

  /**
   * Control Flow Graph (CFG) Generator
   */
  @Post('cfg')
  @HttpCode(HttpStatus.OK)
  async generateCfg(@Body() body: { code: string; taintedLines?: number[] }) {
    return this.cfgVisualizer.generateCfg(body.code, body.taintedLines);
  }

  /**
   * Supply-Chain & Dependency Typosquatting / Hallucination Sentry
   */
  @Post('supply-chain')
  @HttpCode(HttpStatus.OK)
  async auditSupplyChain(@Body() body: { dependencies: Record<string, string>; scripts?: Record<string, string> }) {
    return this.supplyChain.auditDependencies(body.dependencies, body.scripts);
  }

  /**
   * AST Mutation Analysis (Stryker-style robustness scoring)
   */
  @Post('mutation')
  @HttpCode(HttpStatus.OK)
  async runMutation(@Body() body: { code: string; testInput?: any }) {
    return this.mutationProver.runMutationAnalysis(body.code, body.testInput);
  }

  /**
   * Property-Based Test Synthesis (*.spec.ts generator)
   */
  @Post('property-test')
  @HttpCode(HttpStatus.OK)
  async generatePropertyTest(@Body() body: { functionName: string; enclave: string }) {
    return this.vibeGuardCli.generatePropertyTestSuite(body.functionName, body.enclave);
  }

  /**
   * Automated Pull Request Review Markdown Generator
   */
  @Post('pr-review')
  @HttpCode(HttpStatus.OK)
  async generatePrReview(@Body() body: { codeDiff: string; prNumber?: number; branch?: string }) {
    return this.vibeGuardCli.generatePrReview(body.codeDiff, body.prNumber, body.branch);
  }

  /**
   * Real-Time Telemetry and Operational Status
   */
  @Get('telemetry')
  getTelemetry() {
    return {
      status: 'ONLINE',
      engine: 'CyPee Hyper-Sentinel Autonomous Verifier v2.0',
      pqcMode: 'NIST FIPS 203 ML-KEM-768 & FIPS 204 ML-DSA',
      sandboxHarness: 'V8 Ephemeral Micro-Sandbox with Mock Sinks',
      supportedEnclaves: ['the-resident', 'the-gruvs', 'excellency', 'ivory-park', 'vgruvs'],
      activeLogicsCoverage: 800,
      timestamp: new Date().toISOString(),
    };
  }
}
