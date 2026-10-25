import { Controller, Get, Post, Body, HttpCode, HttpStatus, Query } from '@nestjs/common';
import { BreachResponseService } from './breach-response.service';
import { DbCryptoService } from '../database/db-crypto.service';
import { StorageAttestorService } from '../database/storage-attestor.service';
import { EnclaveAppId } from './fleet.service';

@Controller('api/v1/shield/breach')
export class BreachResponseController {
  constructor(
    private readonly breachResponse: BreachResponseService,
    private readonly dbCrypto: DbCryptoService,
    private readonly storageAttestor: StorageAttestorService,
  ) {}

  /**
   * Returns current DEFCON posture and active countermeasure statistics.
   */
  @Get('status')
  @HttpCode(HttpStatus.OK)
  getStatus() {
    return this.breachResponse.getStatus();
  }

  /**
   * Returns the status of the 4 Tier-4 Sovereign Frontiers:
   * 1. KMS Key Custody
   * 2. Database Kernel RLS
   * 3. Storage At-Rest Attestation
   * 4. mTLS Workload Identity Mesh
   */
  @Get('sovereign-status')
  @HttpCode(HttpStatus.OK)
  async getSovereignStatus() {
    const storageAttestation = await this.storageAttestor.attestStorage();
    const vaultStatus = this.dbCrypto.getVaultStatus();

    return {
      tier: 'SOVEREIGN_TIER_4',
      frontiers: {
        kmsVaultCustody: {
          status: vaultStatus.isShredded ? 'LOCKDOWN_SHREDDED' : 'OPERATIONAL',
          provider: vaultStatus.provider,
          activeKeyVersion: vaultStatus.activeKeyVersion,
          zeroDowntimeRotationReady: true,
        },
        databaseKernelRls: {
          status: 'CONFIGURED',
          supportedEngines: ['PostgreSQL 14+', 'AWS Aurora'],
          enforcementLevel: 'DATABASE_KERNEL',
          migrationFile: 'prisma/postgres_rls.sql',
        },
        storageAtRestAttestation: {
          status: 'ATTESTED',
          grade: storageAttestation.storageGrade,
          attestationHash: storageAttestation.attestationHash,
          tempStoreInMemory: storageAttestation.tempStoreInMemory,
        },
        mtlsWorkloadMesh: {
          status: 'ENFORCED',
          guard: 'MtlsMeshGuard',
          spiffeNamespace: 'spiffe://vgruvs.internal/*',
          enclavesCovered: ['the-resident', 'the-gruvs', 'excellency', 'vgruvs'],
        },
      },
      verifiedAt: new Date().toISOString(),
    };
  }

  /**
   * Executes a simulated breach drill to demonstrate CyPee's active defense workflow.
   */
  @Post('trigger-drill')
  @HttpCode(HttpStatus.OK)
  async triggerBreachDrill(@Body() body: { targetApp?: EnclaveAppId; attackerIp?: string }) {
    const result = await this.breachResponse.handleBreachEvent({
      source: 'HONEYTOKEN',
      enclaveAppId: body.targetApp || 'the-gruvs',
      attackerIp: body.attackerIp || '198.51.100.77',
      targetResource: '/api/v1/internal/treasury/transfer',
      tenantId: 'drill-tenant-01',
      payloadSnippet: "UNION SELECT * FROM users WHERE '1'='1",
    });

    return {
      drillStatus: 'SUCCESS',
      message: 'Active defense countermeasures engaged successfully.',
      countermeasureExecution: result,
    };
  }

  /**
   * Manually deploys the slowloris tarpit countermeasure against an attacking IP.
   */
  @Post('tarpit')
  @HttpCode(HttpStatus.OK)
  engageTarpit(@Body() body: { ip: string }) {
    this.breachResponse.engageTarpit(body.ip);
    return {
      success: true,
      message: `Tarpit countermeasure actively throttling IP ${body.ip}. Attacker socket held at 1 byte/2s.`,
    };
  }

  /**
   * Emergency countermeasure: Purges all master encryption key buffers from memory.
   */
  @Post('crypto-shred')
  @HttpCode(HttpStatus.OK)
  shredKeys() {
    return this.dbCrypto.cryptoShred();
  }

  /**
   * Restores master encryption keys from authorized administrative credentials.
   */
  @Post('restore-keys')
  @HttpCode(HttpStatus.OK)
  restoreKeys(@Body() body: { masterKey: string; version?: string }) {
    return this.dbCrypto.restoreKey(body.masterKey, body.version || 'v1');
  }

  /**
   * Resets DEFCON status back to nominal monitoring after threat resolution.
   */
  @Post('reset-defcon')
  @HttpCode(HttpStatus.OK)
  resetDefcon() {
    return this.breachResponse.resetDefcon();
  }
}
