import { IsEmail, IsNotEmpty, IsOptional, IsString, Length } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'dev@shield.io' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'ShieldPassword2025!' })
  @IsString()
  @IsNotEmpty()
  password: string;

  @ApiPropertyOptional({ example: '123456', description: 'TOTP 6-digit MFA code' })
  @IsOptional()
  @IsString()
  @Length(6, 6)
  mfaCode?: string;
}

export class RegisterDto {
  @ApiProperty({ example: 'dev@shield.io' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'ShieldPassword2025!' })
  @IsString()
  @Length(8, 64)
  password: string;

  @ApiProperty({ example: 'My Security Tenant' })
  @IsString()
  @IsNotEmpty()
  tenantName: string;
}

export class VerifyMfaDto {
  @ApiProperty({ example: '123456' })
  @IsString()
  @Length(6, 6)
  code: string;
}
