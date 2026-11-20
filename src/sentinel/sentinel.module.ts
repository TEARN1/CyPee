import { Module } from '@nestjs/common';
import { AstTaintAnalyzerService } from './ast-taint-analyzer.service';
import { EphemeralSandboxService } from './ephemeral-sandbox.service';
import { AdversarialFuzzerService } from './adversarial-fuzzer.service';
import { ClosedLoopProverService } from './closed-loop-prover.service';
import { SentinelSealService } from './sentinel-seal.service';
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
  ],
  exports: [
    AstTaintAnalyzerService,
    EphemeralSandboxService,
    AdversarialFuzzerService,
    ClosedLoopProverService,
    SentinelSealService,
  ],
})
export class SentinelModule {}
