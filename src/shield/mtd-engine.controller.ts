import { Controller, Get, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { MtdEngineService } from './mtd-engine.service';

@Controller('api/v1/shield/mtd')
export class MtdEngineController {
  constructor(private readonly mtdService: MtdEngineService) {}

  /**
   * Returns live Polymorphic Moving-Target Defense status and rolling countdown.
   */
  @Get('status')
  getStatus() {
    return this.mtdService.getStatus();
  }

  /**
   * Computes polymorphic headers for a given enclave.
   */
  @Post('headers')
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
