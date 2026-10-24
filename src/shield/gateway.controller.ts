import { Controller, All, Get, Post, Body, Param, Req, Res, HttpStatus, HttpCode } from '@nestjs/common';
import { Request, Response } from 'express';
import { GatewayService, UpstreamApp } from './gateway.service';

@Controller('api/v1/gateway')
export class GatewayController {
  constructor(private readonly gatewayService: GatewayService) {}

  @Get('status')
  async getGatewayStatus(): Promise<{ status: string; protectedAppsCount: number; apps: UpstreamApp[] }> {
    const apps = await this.gatewayService.listApps();
    return {
      status: 'OPERATIONAL',
      protectedAppsCount: apps.length,
      apps,
    };
  }

  @Post('register')
  @HttpCode(HttpStatus.OK)
  registerApp(
    @Body() body: { id: string; targetUrl: string; name?: string },
  ): { success: boolean; app: UpstreamApp } {
    const app = this.gatewayService.registerApp(body.id, body.targetUrl, body.name);
    return {
      success: true,
      app,
    };
  }

  // Catch-all route for the root of the app: /api/v1/gateway/:appId
  @All(':appId')
  async proxyRoot(
    @Param('appId') appId: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    await this.gatewayService.proxyRequest(appId, '', req, res);
  }

  // Catch-all route for any subpath: /api/v1/gateway/:appId/*
  @All(':appId/*')
  async proxySubpath(
    @Param('appId') appId: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const prefix = `/api/v1/gateway/${appId}`;
    const idx = req.path.indexOf(prefix);
    const subPath = idx !== -1 ? req.path.substring(idx + prefix.length) : '';
    await this.gatewayService.proxyRequest(appId, subPath, req, res);
  }
}
