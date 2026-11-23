import { Module } from '@nestjs/common';
import { AstTaintAnalyzerService } from './ast-taint-analyzer.service';
import { EphemeralSandboxService } from './ephemeral-sandbox.service';
import { AdversarialFuzzerService } from './adversarial-fuzzer.service';
import { ClosedLoopProverService } from './closed-loop-prover.service';
import { SentinelSealService } from './sentinel-seal.service';
import { CfgVisualizerService } from './cfg-visualizer.service';
import { SupplyChainSentryService } from './supply-chain-sentry.service';
import { MutationProverService } from './mutation-prover.service';
import { VibeGuardCliService } from './vibe-guard-cli.service';
import { SentinelController } from './sentinel.controller';
import { RemediationModule } from '../remediation/remediation.module';

@Module({
  imports: [RemediationModule],
  controllers: [SentinelController],
  providers: [
    AstTaintAnalyzerService,
    EphemeralSandboxService,
    AdversarialFuzzerService,
    ClosedLoopProverService,
    SentinelSealService,
    CfgVisualizerService,
    SupplyChainSentryService,
    MutationProverService,
    VibeGuardCliService,
  ],
  exports: [
    AstTaintAnalyzerService,
    EphemeralSandboxService,
    AdversarialFuzzerService,
    ClosedLoopProverService,
    SentinelSealService,
    CfgVisualizerService,
    SupplyChainSentryService,
    MutationProverService,
    VibeGuardCliService,
  ],
})
export class SentinelModule {}
