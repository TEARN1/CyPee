import { Controller, Post, Body, Req, UseGuards, HttpCode, HttpStatus, Ip } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto, VerifyMfaDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@ApiTags('Authentication')
@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new enterprise tenant and admin user' })
  @ApiResponse({ status: 201, description: 'Tenant and admin user successfully registered.' })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login authentication' })
  @ApiResponse({ status: 200, description: 'Authenticated successfully or MFA required.' })
  async login(
    @Body() dto: LoginDto,
    @Ip() ip: string,
    @Req() req: any,
  ) {
    const userAgent = req.headers['user-agent'] || 'Unknown Device';
    return this.authService.login(dto, ip, userAgent);
  }

  @Post('mfa/setup')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Initiate Google Authenticator MFA setup' })
  async setupMfa(@Req() req: any) {
    return this.authService.enableMfaSetup(req.user.id, req.user.tenantId);
  }

  @Post('mfa/confirm')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Confirm and activate MFA setup' })
  async confirmMfa(@Req() req: any, @Body() dto: VerifyMfaDto) {
    return this.authService.confirmMfa(req.user.id, req.user.tenantId, dto.code);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Terminate active user session' })
  async logout(@Req() req: any) {
    await this.authService.logout(req.user.sessionId, req.user.tenantId);
    return { success: true, message: 'Logged out successfully' };
  }
}
