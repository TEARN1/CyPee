import { Controller, Get, Post, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { MtdEngineService } from './mtd-engine.service';
import { OperatorGuard } from '../auth/guards/operator.guard';
import { ApiKeyGuard } from '../compliance/guards/api-key.guard';

@Controller('api/v1/shield/mtd')
export class MtdEngineController {
  constructor(private readonly mtdService: MtdEngineService) {}

  /**
   * Returns live Polymorphic Moving-Target Defense status and rolling countdown.
   */
  @Get('status')
  @UseGuards(OperatorGuard)
  getStatus() {
    return this.mtdService.getStatus();
  }

  /**
   * Computes polymorphic headers for a given enclave.
   */
  @Post('headers')
  @UseGuards(OperatorGuard)
  @HttpCode(HttpStatus.OK)
  getHeaders(@Body('appId') appId?: string) {
    return {
      appId: appId || 'vgruvs',
      headers: this.mtdService.getPolymorphicHeaders(appId || 'vgruvs'),
    };
  }

  /**
   * Validates a polymorphic token for an enclave.
   */
  @Post('validate')
  @UseGuards(ApiKeyGuard)
  @HttpCode(HttpStatus.OK)
  validateToken(@Body() body: { token: string; appId: string }) {
    const valid = this.mtdService.validateMtdToken(body.token, body.appId);
    return {
      valid,
      appId: body.appId,
      tokenEvaluated: body.token,
    };
  }
}
