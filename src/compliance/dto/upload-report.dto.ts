import { IsArray, ValidateNested, ArrayMinSize } from 'class-validator';
import { Type } from 'class-transformer';
import { SastFindingDto } from './sast-finding.dto';

export class UploadReportDto {
  @IsArray()
  @ArrayMinSize(1, { message: 'The report must contain at least one static analysis finding' })
  @ValidateNested({ each: true })
  @Type(() => SastFindingDto)
  findings: SastFindingDto[];
}
