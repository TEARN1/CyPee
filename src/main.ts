import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, { bodyParser: false });

  // Enable CORS for local cross-origin frontend queries
  app.enableCors();

  // Set global API prefix (optional, but highly recommended)
  // Our route is already /api/v1/compliance/upload in the controller, so we can keep it as is.
  
  // Enable global validations for requests
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Capture raw body buffer for secure cryptographic signature validation
  const express = require('express');
  const path = require('path');
  
  app.use(
    express.json({
      verify: (req: any, res: any, buf: Buffer) => {
        req.rawBody = buf;
      },
    }),
  );
  app.use(express.urlencoded({ extended: true }));

  // Serve static dashboard UI from frontend/dist build directory
  app.use(express.static(path.join(process.cwd(), 'frontend', 'dist')));

  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT', 3000);

  await app.listen(port);
  logger.log(`SAST Ingestion Engine successfully running on: http://localhost:${port}`);
  logger.log(`Accepting uploads at POST http://localhost:${port}/api/v1/compliance/upload`);
}
bootstrap();
