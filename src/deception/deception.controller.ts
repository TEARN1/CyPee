import { Controller, Get, Post, Body, Req, Headers, HttpCode, HttpStatus, UseGuards, Query } from '@nestjs/common';
import { Public } from '../auth/public.decorator';
import { Request } from 'express';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OwnerGuard } from '../auth/guards/owner.guard';
import { DeceptionService } from './deception.service';
import { DeceptionAdvancedService } from './deception-advanced.service';

@Controller('api/v1')
export class DeceptionController {
  constructor(
    private readonly deceptionService: DeceptionService,
    private readonly advancedDeception: DeceptionAdvancedService,
  ) {}

  /**
   * Admin endpoint to create decoy honeytokens. This is a real management
   * action (unlike the trap endpoints below) so it requires authentication.
   */
  @Post('deception/honeytoken')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async generateToken(
    @Body() body: { label: string; type: 'AWS' | 'DB' | 'SSH' },
    @Req() req: any,
  ) {
    return this.deceptionService.generateHoneytoken(req.user.tenantId, body.label, body.type);
  }

  /**
   * Decoy Path 1: Database backup portal trap.
   * Deliberately unauthenticated — it exists to be found and hit by an
   * attacker probing the app, which is what triggers the alert below.
   */
  @Get('admin/db-backup')
  @Public()
  async databaseBackupTrap(@Req() req: Request, @Headers() headers: Record<string, string>) {
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const tenantId = headers['x-tenant-id'] || 'default-dev-tenant-uuid';

    // Trigger security alert asynchronously
    await this.deceptionService.handleDeceptionHit(tenantId, 'DECOY_DB_BACKUP_URL', ip, headers, '/api/v1/admin/db-backup');

    // Return fake realistic database timeout error to keep attacker guessing
    return {
      status: 'error',
      code: 'DB_CONNECTION_TIMEOUT',
      message: 'Failed to establish connection to cluster replica-0.production.internal:5432. Connection timed out.',
      requestId: Math.random().toString(36).substring(2, 15),
    };
  }

  /**
   * Decoy Path 2: AWS credentials trap.
   * Also deliberately unauthenticated for the same reason as above.
   */
  @Get('config/aws-credentials')
  @Public()
  async awsCredentialsTrap(@Req() req: Request, @Headers() headers: Record<string, string>) {
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const tenantId = headers['x-tenant-id'] || 'default-dev-tenant-uuid';

    await this.deceptionService.handleDeceptionHit(tenantId, 'DECOY_AWS_CONFIG_KEY', ip, headers, '/api/v1/config/aws-credentials');

    return {
      aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE',
      aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      region: 'us-east-1',
      output: 'json',
    };
  }

  /**
   * Decoy Path 3: Synthetic Robots.txt Honeypot Generator.
   * Lures crawlers and automated discovery scanners into probing canary URLs.
   */
  @Get('deception/robots.txt')
  @Public()
  getRobotsTxt() {
    return `User-agent: *\nDisallow: /api/v1/admin/db-backup\nDisallow: /api/v1/config/aws-credentials\nDisallow: /api/v1/internal/k8s-tokens\nDisallow: /api/v1/enclave/vault-dump\n`;
  }

  /**
   * Decoy Path 4: Kubernetes Cluster Service Account Tokens.
   */
  @Get('internal/k8s-tokens')
  @Public()
  async k8sTokensTrap(@Req() req: Request, @Headers() headers: Record<string, string>) {
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const tenantId = headers['x-tenant-id'] || 'default-dev-tenant-uuid';

    await this.deceptionService.handleDeceptionHit(tenantId, 'DECOY_K8S_TOKENS', ip, headers, '/api/v1/internal/k8s-tokens');

    return {
      serviceAccount: 'cluster-admin-privileged',
      token: 'eyJhbGciOiJSUzI1NiIsImtpZCI6InB2LWtpZC05OTE4In0.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmNsdXN0ZXItYWRtaW4ifQ.decoy',
      ca_crt: '-----BEGIN CERTIFICATE-----\nMIICyDCCAbCgAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwprdWJl\n-----END CERTIFICATE-----',
    };
  }

  /**
   * Procedural Reverse Shell Honeypot Execution
   */
  @Post('deception/honeypot/shell')
  @Public()
  @HttpCode(HttpStatus.OK)
  executeHoneypotShell(
    @Body() body: { sessionId?: string; command: string },
    @Req() req: Request,
  ) {
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const sessId = body.sessionId || `SESSION-${ip.replace(/[^a-zA-Z0-9]/g, '_')}`;
    return this.advancedDeception.handleHoneypotCommand(sessId, ip, body.command);
  }

  /**
   * Canary File Drop Generator
   */
  @Get('deception/canary/template')
  @Public()
  getCanaryTemplate(@Query('type') type: 'AWS_ENV' | 'SSH_KEY' | 'LEDGER_CSV' = 'AWS_ENV') {
    return this.advancedDeception.generateCanaryFileTemplate(type);
  }

  /**
   * Automated Forensic Threat Dossier Generator
   */
  @Post('deception/forensics/dossier')
  @UseGuards(JwtAuthGuard, OwnerGuard)
  @HttpCode(HttpStatus.OK)
  generateDossier(
    @Body() body: { targetIp: string; ja4?: string; payloads?: string[] },
  ) {
    return this.advancedDeception.generateForensicDossier(body.targetIp, body.ja4, body.payloads);
  }

  /**
   * Synthetic GraphQL Introspection Schema Trap
   */
  @Post('graphql')
  @Public()
  @HttpCode(HttpStatus.OK)
  graphQlTrap() {
    return this.advancedDeception.getSyntheticGraphQlSchemaTrap();
  }

  /**
   * Autonomous Breach Simulation Drill Run
   */
  @Post('deception/drill/run')
  @UseGuards(JwtAuthGuard, OwnerGuard)
  @HttpCode(HttpStatus.OK)
  runBreachDrill() {
    return this.advancedDeception.runAutonomousBreachDrill();
  }
}
