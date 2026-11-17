import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface LabyrinthTrappedSession {
  ip: string;
  firstTrappedAt: string;
  lastProbeAt: string;
  requestsTrapped: number;
  totalTimeBurnedSeconds: number;
  syntheticTablesEnumerated: string[];
  inferredAttackerTool: string;
  lastInjectedPayload: string;
  status: 'TRAPPED_IN_MAZE' | 'STALLED' | 'EXHAUSTED';
}

@Injectable()
export class InfiniteLabyrinthService {
  private readonly logger = new Logger(InfiniteLabyrinthService.name);

  // Tracks trapped automated attacker sessions
  private trappedAttackers = new Map<string, LabyrinthTrappedSession>();
  private readonly salt = crypto.randomBytes(16).toString('hex');

  // Realistic synthetic table templates for procedural generation (20 enterprise schemas)
  private readonly tableSchemas = [
    { prefix: 'sys_auth_credentials', cols: ['id', 'username', 'password_hash_bcrypt', 'salt', 'mfa_totp_seed', 'role', 'created_at'] },
    { prefix: 'ledger_financial_reserves', cols: ['transaction_uuid', 'source_account', 'target_iban', 'amount_cents', 'currency', 'status', 'approved_by'] },
    { prefix: 'customer_vault_tokens', cols: ['token_id', 'ssn_encrypted', 'credit_card_last4', 'billing_address', 'api_key_secret', 'updated_at'] },
    { prefix: 'vgruvs_hypervisor_config', cols: ['node_id', 'kernel_param', 'root_mount', 'privkey_fingerprint', 'debug_flag', 'last_boot'] },
    { prefix: 'resident_identity_registry', cols: ['resident_id', 'full_name', 'national_id', 'biometric_hash', 'access_tier', 'verified_flag'] },
    { prefix: 'gruvs_workflow_orchestration', cols: ['task_id', 'worker_pid', 'shell_command', 'concurrency_mutex', 'reentrancy_token', 'exit_code'] },
    { prefix: 'excellency_balance_sheets', cols: ['sheet_id', 'workbook_name', 'dde_macro_enabled', 'cell_range', 'author_email', 'checksum'] },
    { prefix: 'oauth_access_grants', cols: ['grant_id', 'client_id', 'refresh_token_sha256', 'scope_mask', 'tenant_boundary', 'expires_at'] },
    { prefix: 'aws_iam_secret_keys', cols: ['access_key_id', 'secret_key_encrypted', 'arn_resource', 'policy_document', 'rotation_due'] },
    { prefix: 'k8s_service_account_tokens', cols: ['namespace_id', 'sa_name', 'jwt_signature_prefix', 'cluster_ca_cert', 'issued_epoch'] },
    { prefix: 'crypto_wallet_seed_phrases', cols: ['wallet_uuid', 'bip39_checksum', 'derivation_path', 'multisig_threshold', 'last_sweep'] },
    { prefix: 'payment_gateway_pci_tokens', cols: ['pan_token', 'cvv_vault_ref', 'issuer_bin', 'settlement_batch_id', 'pci_dss_tier'] },
    { prefix: 'the_resident_biometric_templates', cols: ['resident_uuid', 'iris_embedding_vector', 'fingerprint_minutiae', 'fido2_credential_id'] },
    { prefix: 'the_gruvs_distributed_locks', cols: ['lock_key', 'holder_worker_node', 'lease_duration_ms', 'fencing_token', 'acquired_timestamp'] },
    { prefix: 'excellency_payroll_records', cols: ['employee_hash', 'gross_salary_cents', 'tax_deduction_code', 'direct_deposit_routing', 'pay_period'] },
    { prefix: 'cloud_metadata_v2_tokens', cols: ['instance_id', 'role_arn', 'imds_session_header', 'mac_address', 'security_group_list'] },
    { prefix: 'tenants_isolation_keys', cols: ['tenant_slug', 'kms_key_arn', 'data_encryption_key', 'pqc_kyber_public_key', 'created_timestamp'] },
    { prefix: 'api_gateway_rate_limits', cols: ['ip_prefix', 'quota_max', 'current_burst_count', 'blacklisted_boolean', 'bypass_token_hash'] },
    { prefix: 'internal_security_audit_trails', cols: ['event_id', 'actor_identity', 'event_action', 'risk_score_numeric', 'siem_forwarded_flag'] },
    { prefix: 'pqc_lattice_transit_vault', cols: ['key_id', 'algorithm_name', 'ring_dimension_n', 'modulus_q', 'attestation_digest'] },
  ];

  /**
   * Generates a deterministic, endless procedural database response for an injection attempt.
   * Traps tools like sqlmap into testing thousands of synthetic columns and boolean delays.
   */
  async generateProceduralResponse(ip: string, query: string, rawPayload?: string): Promise<{
    queryEcho: string;
    elapsedMs: number;
    rowsCount: number;
    schema: { table: string; columns: string[] };
    results: Record<string, any>[];
  }> {
    const startTime = Date.now();

    // 1. Update or initialize trapped attacker profile
    let session = this.trappedAttackers.get(ip);
    if (!session) {
      if (this.trappedAttackers.size >= 2000) {
        const oldestIp = this.trappedAttackers.keys().next().value;
        if (oldestIp !== undefined) this.trappedAttackers.delete(oldestIp);
      }
      session = {
        ip,
        firstTrappedAt: new Date().toISOString(),
        lastProbeAt: new Date().toISOString(),
        requestsTrapped: 0,
        totalTimeBurnedSeconds: 0,
        syntheticTablesEnumerated: [],
        inferredAttackerTool: this.inferTool(rawPayload || query),
        lastInjectedPayload: rawPayload || query,
        status: 'TRAPPED_IN_MAZE',
      };
      this.trappedAttackers.set(ip, session);
      this.logger.warn(`🌀 [INFINITE LABYRINTH] Attacker from IP ${ip} entered procedural honeypot maze.`);
    }

    session.requestsTrapped++;
    session.lastProbeAt = new Date().toISOString();
    session.lastInjectedPayload = rawPayload || query;

    // 2. Select procedural schema using HMAC seed from IP + request count
    const seed = crypto.createHmac('sha256', this.salt).update(`${ip}:${session.requestsTrapped}:${query}`).digest('hex');
    const tableIndex = parseInt(seed.substring(0, 2), 16) % this.tableSchemas.length;
    const baseSchema = this.tableSchemas[tableIndex];
    const suffix = parseInt(seed.substring(2, 6), 16);
    const tableName = `${baseSchema.prefix}_${suffix}`;

    if (!session.syntheticTablesEnumerated.includes(tableName)) {
      session.syntheticTablesEnumerated.push(tableName);
      if (session.syntheticTablesEnumerated.length > 20) session.syntheticTablesEnumerated.shift();
    }

    // 3. Generate procedural rows
    const numRows = (parseInt(seed.substring(6, 8), 16) % 7) + 3;
    const results: Record<string, any>[] = [];

    for (let r = 0; r < numRows; r++) {
      const rowSeed = crypto.createHash('sha256').update(`${seed}:row:${r}`).digest('hex');
      const row: Record<string, any> = {};
      baseSchema.cols.forEach((col, cIdx) => {
        row[col] = this.generateSyntheticValue(col, rowSeed, cIdx);
      });
      results.push(row);
    }

    // 4. Inject intentional Gaussian mathematical latency jitter (120ms - 650ms) to confound automated SQL fuzzers
    const u1 = Math.max(0.0001, (parseInt(seed.substring(8, 10), 16) + 1) / 257);
    const u2 = (parseInt(seed.substring(10, 12), 16) + 1) / 257;
    const z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
    const delayMs = Math.floor(Math.max(120, Math.min(650, 280 + z0 * 75)));
    await new Promise((resolve) => setTimeout(resolve, delayMs));

    const elapsed = Date.now() - startTime;
    session.totalTimeBurnedSeconds += elapsed / 1000;

    return {
      queryEcho: query.substring(0, 100),
      elapsedMs: elapsed,
      rowsCount: results.length,
      schema: {
        table: tableName,
        columns: baseSchema.cols,
      },
      results,
    };
  }

  private generateSyntheticValue(col: string, seed: string, idx: number): any {
    const slice = seed.substring(idx * 4, idx * 4 + 8);
    if (col.includes('id') || col.includes('uuid')) {
      return `rec-${slice}`;
    }
    if (col.includes('hash') || col.includes('seed') || col.includes('key')) {
      return `$2b$12$${crypto.createHash('sha256').update(slice).digest('base64url').substring(0, 28)}`;
    }
    if (col.includes('amount') || col.includes('cents')) {
      return parseInt(slice, 16) % 1000000;
    }
    if (col.includes('currency')) {
      return ['ZAR', 'USD', 'EUR', 'GBP'][parseInt(slice, 16) % 4];
    }
    if (col.includes('date') || col.includes('at')) {
      return new Date(Date.now() - (parseInt(slice, 16) % 100000000)).toISOString();
    }
    if (col.includes('flag') || col.includes('enabled')) {
      return parseInt(slice, 16) % 2 === 1;
    }
    if (col.includes('username') || col.includes('author')) {
      return `operator_${slice.substring(0, 4)}@enclave.internal`;
    }
    return `synthetic_val_${slice}`;
  }

  private inferTool(payload: string): string {
    const lower = payload.toLowerCase();
    if (lower.includes('sqlmap') || lower.includes('substring') || lower.includes('ascii(substr')) return 'Sqlmap (Automated DB Fuzzer)';
    if (lower.includes('union select') || lower.includes('order by')) return 'Interactive SQL Injection Script';
    if (lower.includes('exec') || lower.includes('cmd')) return 'RCE Exploitation Bot';
    return 'Automated Threat Probe';
  }

  /**
   * Returns live labyrinth surveillance metrics for the SOC dashboard.
   */
  getLabyrinthStats() {
    const trappedList = Array.from(this.trappedAttackers.values());
    const totalRequestsTrapped = trappedList.reduce((acc, curr) => acc + curr.requestsTrapped, 0);
    const totalHoursBurned = (trappedList.reduce((acc, curr) => acc + curr.totalTimeBurnedSeconds, 0) / 3600).toFixed(2);

    return {
      status: 'ACTIVE_HONEYPOT_MAZE',
      activeTrappedAttackers: trappedList.length,
      totalRequestsTrapped,
      totalHoursBurned: `${totalHoursBurned} hours`,
      attackers: trappedList.slice(0, 10),
    };
  }

  /**
   * Resets trapped session for testing/admin purposes.
   */
  clearTrappedSession(ip: string) {
    this.trappedAttackers.delete(ip);
  }
}
