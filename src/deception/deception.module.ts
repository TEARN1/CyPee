import { Module } from '@nestjs/common';
import { DeceptionService } from './deception.service';
import { DeceptionController } from './deception.controller';
import { DeceptionAdvancedService } from './deception-advanced.service';

@Module({
  controllers: [DeceptionController],
  providers: [DeceptionService, DeceptionAdvancedService],
  exports: [DeceptionService, DeceptionAdvancedService],
})
export class DeceptionModule {}
