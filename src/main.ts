import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { configureApp } from './app.setup';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, { bodyParser: false });

  configureApp(app);

  const configService = app.get(ConfigService);
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : configService.get<number>('PORT', 3050);

  await app.listen(port);
  logger.log(`CyPee Sovereign Enclave successfully running on: http://localhost:${port}`);
  logger.log(`Accepting uploads at POST http://localhost:${port}/api/v1/compliance/upload`);
}
bootstrap();
