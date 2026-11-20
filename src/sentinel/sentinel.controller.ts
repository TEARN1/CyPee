import { Controller, Post, Get, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { AstTaintAnalyzerService } from './ast-taint-analyzer.service';
import { EphemeralSandboxService } from './ephemeral-sandbox.service';
import { AdversarialFuzzerService } from './adversarial-fuzzer.service';
import { ClosedLoopProverService } from './closed-loop-prover.service';
import { SentinelSealService } from './sentinel-seal.service';

@Controller('api/v1/sentinel')
export class SentinelController {
  constructor(
    private readonly taintAnalyzer: AstTaintAnalyzerService,
    private readonly sandbox: EphemeralSandboxService,
    private readonly fuzzer: AdversarialFuzzerService,
    private readonly prover: ClosedLoopProverService,
    private readonly sealService: SentinelSealService,
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
