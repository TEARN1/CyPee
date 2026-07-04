import { Controller, Get, Post, Body, Query, Req, UseGuards, HttpStatus, HttpCode, BadRequestException, ForbiddenException } from '@nestjs/common';
import { SecurityHardeningService } from './security-hardening.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('api/v1/shield/hardening')
export class SecurityHardeningController {
  constructor(private readonly hardeningService: SecurityHardeningService) {}

  /**
   * Endpoint to verify timing-safe comparison.
   */
  @Post('compare')
  @HttpCode(HttpStatus.OK)
  async verifyCompare(@Body() body: { secret1: string; secret2: string }) {
    const match = this.hardeningService.timingSafeCompare(body.secret1, body.secret2);
    return { match };
  }

  /**
   * Endpoint simulating a critical financial transfer transaction
   * hardened against race condition attacks using the lock manager.
   */
  @Post('transaction')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async executeTransaction(@Body() body: { userId: string; amount: number }, @Req() req: any) {
    if (req.user?.id !== body.userId) {
      throw new ForbiddenException('Cannot execute a transaction on behalf of another user.');
    }
    if (typeof body.amount !== 'number' || !Number.isFinite(body.amount) || body.amount <= 0) {
      throw new BadRequestException('Amount must be a positive number.');
    }

    const lockKey = `lock:user-transfer:${body.userId}`;

    // Acquire concurrency lock
    const lockAcquired = this.hardeningService.acquireLock(lockKey);
    if (!lockAcquired) {
      throw new BadRequestException('Transaction blocked. Concurrent request active.');
    }

    try {
      // Simulate database IO latency where standard race conditions occur
      await new Promise(r => setTimeout(r, 100));

      return {
        success: true,
        message: `Successfully transferred $${body.amount} for user ${body.userId}.`,
      };
    } finally {
      // Always release concurrency lock
      this.hardeningService.releaseLock(lockKey);
    }
  }

  /**
   * Endpoint demonstrating HTTP Parameter Pollution (HPP) flattening.
   */
  @Get('query')
  @HttpCode(HttpStatus.OK)
  async parseQuery(@Req() req: any) {
    // req.query might contain arrays if HPP query was sent
    const sanitized = this.hardeningService.sanitizeHpp(req.query);
    return { sanitized };
  }
}
