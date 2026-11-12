import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, { bodyParser: false });

  // Enable CORS with exposed challenge headers for PoW handshakes
  app.enableCors({
    origin: true,
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
  const frontendDist = path.join(process.cwd(), 'frontend', 'dist');
  app.use(express.static(frontendDist));
  app.use((req: any, res: any, next: any) => {
    if (req.method === 'GET' && !req.path.startsWith('/api')) {
      return res.sendFile(path.join(frontendDist, 'index.html'));
    }
    next();
  });

  const configService = app.get(ConfigService);
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : configService.get<number>('PORT', 3050);

  await app.listen(port);
  logger.log(`CyPee Sovereign Enclave successfully running on: http://localhost:${port}`);
  logger.log(`Accepting uploads at POST http://localhost:${port}/api/v1/compliance/upload`);
}
bootstrap();
