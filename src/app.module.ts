import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BullModule } from '@nestjs/bullmq';
import { ComplianceModule } from './compliance/compliance.module';
import { QueueModule } from './queue/queue.module';
import { RemediationModule } from './remediation/remediation.module';
import { DatabaseModule } from './database/database.module';
import { AuditModule } from './audit/audit.module';
import { ScansModule } from './scans/scans.module';
import { AuthModule } from './auth/auth.module';
import { ShieldModule } from './shield/shield.module';
import { DeceptionModule } from './deception/deception.module';
import { ShieldMiddleware } from './shield/shield.middleware';
import { SecurityHeadersMiddleware } from './compliance/middlewares/security-headers.middleware';

@Module({
  imports: [
    // Register Configuration globally
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    // Global Database, Audit, and AI Shield Modules
    DatabaseModule,
    AuditModule,
    ShieldModule,

    // BullMQ Connection Configuration
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        connection: {
          host: configService.get<string>('REDIS_HOST', 'localhost'),
          port: configService.get<number>('REDIS_PORT', 6379),
        },
      }),
    }),

    // Feature Modules
    ComplianceModule,
    QueueModule,
    RemediationModule,
    ScansModule,
    AuthModule,
    DeceptionModule,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      // Run AI Shield pre-route validation filters on all endpoints
      .apply(ShieldMiddleware)
      .forRoutes('*')
      // Apply secondary security headers
      .apply(SecurityHeadersMiddleware)
      .forRoutes('*');
  }
}
