import { IsString, IsNotEmpty, IsInt, Min, IsEnum, IsOptional } from 'class-validator';
import { SeverityLevel } from '../interfaces/finding.interface';

export class SastFindingDto {
  @IsString()
  @IsNotEmpty({ message: 'filePath is required and cannot be empty' })
  filePath: string;

  @IsInt({ message: 'lineNumber must be an integer' })
  @Min(1, { message: 'lineNumber must be a positive integer starting at 1' })
  lineNumber: number;

  @IsString()
  @IsNotEmpty({ message: 'ruleId is required and cannot be empty' })
  ruleId: string;

  @IsEnum(SeverityLevel, {
    message: 'severity must be one of: LOW, MEDIUM, HIGH, CRITICAL',
  })
  severity: SeverityLevel;

  @IsString()
  @IsOptional()
  message?: string;
}
