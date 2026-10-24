import { Controller, Get, Post, Body, BadRequestException, HttpStatus, HttpCode } from '@nestjs/common';
import { FleetService, FleetEntityStatus } from './fleet.service';

@Controller('api/v1/shield/fleet')
export class FleetController {
  constructor(private readonly fleetService: FleetService) {}

  @Get('posture')
  async getFleetPosture(): Promise<{ fleet: FleetEntityStatus[]; globalPostureScore: number; totalScans: number }> {
    return this.fleetService.getFleetPosture();
  }

  @Post('quarantine')
  @HttpCode(HttpStatus.OK)
  async quarantineEntity(
    @Body() body: { id: string; reason?: string },
  ): Promise<{ success: boolean; entity: FleetEntityStatus }> {
    if (!body.id) throw new BadRequestException('Target entity id is required.');
    const entity = await this.fleetService.quarantineEntity(
      body.id,
      body.reason || 'Manual security quarantine triggered from CyPee Enclave Console.',
    );
    return { success: true, entity };
  }

  @Post('restore')
  @HttpCode(HttpStatus.OK)
  async restoreEntity(
    @Body() body: { id: string },
  ): Promise<{ success: boolean; entity: FleetEntityStatus }> {
    if (!body.id) throw new BadRequestException('Target entity id is required.');
    const entity = await this.fleetService.restoreEntity(body.id);
    return { success: true, entity };
  }
}
