import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, { bodyParser: false });

  // The dashboard is served from this same address, so no other site needs
  // CORS. Extra origins can be listed in CORS_ORIGINS (comma-separated).
  const corsOrigins = (process.env.CORS_ORIGINS ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  app.enableCors({
    origin: corsOrigins.length > 0 ? corsOrigins : false,
    credentials: true,
    exposedHeaders: ['x-shield-challenge', 'x-cypee-shield-version', 'x-cypee-proxy-time'],
  });

  // Enable global validations for requests
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Capture raw body buffer for secure cryptographic signature validation with strict 1MB payload cap
  const express = require('express');
  const path = require('path');
  
  app.use(
    express.json({
      limit: '1mb',
      verify: (req: any, res: any, buf: Buffer) => {
        req.rawBody = buf;
      },
    }),
  );
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // Serve static dashboard UI from frontend/dist build directory
  app.use(express.static(path.join(process.cwd(), 'frontend', 'dist')));

  const configService = app.get(ConfigService);
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : configService.get<number>('PORT', 3000);

  await app.listen(port, '127.0.0.1');
  logger.log(`SAST Ingestion Engine successfully running on: http://localhost:${port}`);
  logger.log(`Accepting uploads at POST http://localhost:${port}/api/v1/compliance/upload`);
}
bootstrap();
