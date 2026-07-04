import { Module } from '@nestjs/common';
import { DeceptionService } from './deception.service';
import { DeceptionController } from './deception.controller';

@Module({
  controllers: [DeceptionController],
  providers: [DeceptionService],
  exports: [DeceptionService],
})
export class DeceptionModule {}
