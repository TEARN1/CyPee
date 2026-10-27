import 'reflect-metadata';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { BreachResponseController } from './breach-response.controller';
import { FleetController } from './fleet.controller';
import { GatewayController } from './gateway.controller';
import { FederatedDefenseController } from './federated-defense.controller';
import { AttackerReconController } from './attacker-recon.controller';
import { SecurityHardeningController } from './security-hardening.controller';

// These actions change or reveal the whole system. They were once open to
// anyone who could reach CyPee; keep a sign-in, and an owner, in front of them.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Ctor = { prototype: any };
const guardsOf = (controller: Ctor, method: string): unknown[] => [
  ...(Reflect.getMetadata(GUARDS_METADATA, controller) ?? []),
  ...(Reflect.getMetadata(GUARDS_METADATA, controller.prototype[method]) ?? []),
];

const OWNER_ONLY: [Ctor, string][] = [
  [BreachResponseController, 'shredKeys'],
  [BreachResponseController, 'restoreKeys'],
  [BreachResponseController, 'engageTarpit'],
  [BreachResponseController, 'triggerBreachDrill'],
  [BreachResponseController, 'resetDefcon'],
  [FleetController, 'quarantineEntity'],
  [FleetController, 'restoreEntity'],
  [GatewayController, 'registerApp'],
  [FederatedDefenseController, 'shareThreat'],
  [AttackerReconController, 'simulateBeaconPing'],
  [SecurityHardeningController, 'triggerBackup'],
];

const SIGNED_IN: [Ctor, string][] = [
  [BreachResponseController, 'getStatus'],
  [FleetController, 'getFleetPosture'],
  [GatewayController, 'getGatewayStatus'],
  [FederatedDefenseController, 'getFeed'],
  [AttackerReconController, 'getAllDossiers'],
  [AttackerReconController, 'exportDossierReport'],
  [SecurityHardeningController, 'getDatabasePosture'],
];

describe('system-wide actions need a signed-in owner', () => {
  it.each(OWNER_ONLY)('%p.%s needs sign-in and an owner', (controller, method) => {
    expect(guardsOf(controller, method)).toEqual(expect.arrayContaining([JwtAuthGuard, OwnerGuard]));
  });

  it.each(SIGNED_IN)('%p.%s needs sign-in', (controller, method) => {
    expect(guardsOf(controller, method)).toContain(JwtAuthGuard);
  });

  it('leaves the canary beacon and the app proxy open, as they must be', () => {
    expect(guardsOf(AttackerReconController, 'handleBeaconPingGet')).toEqual([]);
    expect(guardsOf(GatewayController, 'proxyRoot')).toEqual([]);
  });
});
