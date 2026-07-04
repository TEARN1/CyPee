import { Controller, Get, Post, Body, Req, Headers, HttpCode, HttpStatus } from '@nestjs/common';
import { Request } from 'express';
import { DeceptionService } from './deception.service';

@Controller('api/v1')
export class DeceptionController {
  constructor(private readonly deceptionService: DeceptionService) {}

  /**
   * Admin endpoint to create decoy honeytokens.
   */
  @Post('deception/honeytoken')
  @HttpCode(HttpStatus.CREATED)
  async generateToken(
    @Body() body: { label: string; type: 'AWS' | 'DB' | 'SSH' },
    @Headers('x-tenant-id') tenantIdHeader?: string,
  ) {
    const tenantId = tenantIdHeader || 'default-dev-tenant-uuid';
    return this.deceptionService.generateHoneytoken(tenantId, body.label, body.type);
  }

  /**
   * Decoy Path 1: Database backup portal trap.
   */
  @Get('admin/db-backup')
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
   */
  @Get('config/aws-credentials')
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
}
