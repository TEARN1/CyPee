import { Injectable } from '@nestjs/common';

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  commonThreatGroups: string[];
  mitigation: string;
}

@Injectable()
export class MitreAttackService {
  private readonly matrix: Record<string, MitreTechnique> = {
    'T1552': {
      id: 'T1552',
      name: 'Unsecured Credentials',
      tactic: 'Credential Access',
      description: 'Adversaries may search local file systems and databases to find insecurely stored credentials.',
      commonThreatGroups: ['APT29 (Cozy Bear)', 'APT41 (Double Dragon)', 'Lazarus Group'],
      mitigation: 'Implement static secret scanners (like SecretExcavator) and move all parameters to secure key vaults.',
    },
    'T1552.001': {
      id: 'T1552.001',
      name: 'Credentials in Files',
      tactic: 'Credential Access',
      description: 'Adversaries may search local files (like .env, config, docker-compose) for hardcoded database connection strings.',
      commonThreatGroups: ['FIN7', 'MuddyWater', 'Wizard Spider'],
      mitigation: 'Audit lockfiles and configuration specifications; use ephemeral runtime injection.',
    },
    'T1190': {
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      description: 'Adversaries may attempt to exploit vulnerabilities in public endpoints (like SQL Injections or SSRFs) to run remote code.',
      commonThreatGroups: ['APT39', 'Sandworm Team', 'UNC2452 (Nobelium)'],
      mitigation: 'Use parameterization, upgrade dependencies containing known CVEs, and run local fuzzer guard checks.',
    },
    'T1611': {
      id: 'T1611',
      name: 'Escape to Host',
      tactic: 'Privilege Escalation',
      description: 'Adversaries may attempt to escape containerized environments (like Docker containers running as root or privileged modes) to compromise the host system.',
      commonThreatGroups: ['APT33', 'Kimsuky'],
      mitigation: 'Remove privileged flags from Docker compose configurations and define explicit non-root USER directives.',
    },
    'T1046': {
      id: 'T1046',
      name: 'Network Service Discovery',
      tactic: 'Discovery',
      description: 'Adversaries may scan network ports to find active services (like exposed database ports) that are open for connection.',
      commonThreatGroups: ['APT38', 'Fancy Bear (APT28)'],
      mitigation: 'Bind internal database ports to localhost loopback interface (127.0.0.1) instead of exposing them.',
    },
  };

  /**
   * Retrieves technique details by ID.
   */
  getTechniqueDetails(id: string): MitreTechnique | null {
    // Standardize sub-technique lookups if any
    const normalized = id.trim().toUpperCase();
    return this.matrix[normalized] || null;
  }

  /**
   * Returns the entire MITRE ATT&CK lookup matrix.
   */
  getMatrix(): Record<string, MitreTechnique> {
    return this.matrix;
  }
}
