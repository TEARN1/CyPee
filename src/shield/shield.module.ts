import { Module, Global } from '@nestjs/common';
import { ShieldService } from './shield.service';
import { FederatedDefenseService } from './federated-defense.service';

@Global()
@Module({
  providers: [ShieldService, FederatedDefenseService],
  exports: [ShieldService, FederatedDefenseService],
})
export class ShieldModule {}
