import { Controller, Get, Param, Query, NotFoundException } from '@nestjs/common';
import { SecurityLogicsService } from './security-logics.service';

@Controller('api/v1/compliance/logics')
export class SecurityLogicsController {
  constructor(private readonly logicsService: SecurityLogicsService) {}

  /**
   * Returns paginated, searchable catalog of the 800 Active Security Logics.
   */
  @Get()
  getLogics(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('domain') domain?: string,
    @Query('severity') severity?: string,
    @Query('search') search?: string,
  ) {
    return this.logicsService.queryLogics({
      page: page ? parseInt(page, 10) : 1,
      limit: limit ? parseInt(limit, 10) : 25,
      domain,
      severity,
      search,
    });
  }

  /**
   * Retrieves a specific security logic by its ID (e.g., WEB-001, RES-204, VGR-508).
   */
  @Get(':id')
  getLogicById(@Param('id') id: string) {
    const item = this.logicsService.getLogicById(id);
    if (!item) {
      throw new NotFoundException(`Security logic "${id}" not found in the 800-Rule defense catalog.`);
    }
    return item;
  }
}
