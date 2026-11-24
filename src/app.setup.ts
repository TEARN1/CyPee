import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const express = require('express');

/** Everything main.ts sets on the app, shared with the HTTP tests so they test the real thing. */
export function configureApp(app: INestApplication): void {
  // Don't announce the server software.
  app.getHttpAdapter().getInstance().disable('x-powered-by');

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

}
