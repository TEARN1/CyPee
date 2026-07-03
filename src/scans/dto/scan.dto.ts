import { IsOptional, IsString, IsUUID, IsUrl } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Provider } from '../types';

export class CreateScanDto {
  @ApiProperty({ example: 'https://github.com/org/repo', description: 'Repository URL to scan' })
  @IsUrl({}, { message: 'repositoryUrl must be a valid URL' })
  repositoryUrl: string;

  @ApiPropertyOptional({ example: 'my-project', description: 'Friendly repository name' })
  @IsOptional()
  @IsString()
  repositoryName?: string;

  @ApiPropertyOptional({ example: 'GITHUB', description: 'Repository provider: GITHUB | GITLAB | BITBUCKET | OTHER' })
  @IsOptional()
  @IsString()
  provider?: Provider;
}

export class GetScanParamsDto {
  @ApiProperty({ example: 'uuid-here' })
  @IsUUID()
  id: string;
}
