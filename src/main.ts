import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // If deployed behind a reverse proxy/LB (common in enterprise), enable this with correct hop count.
  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: false, // enable once you finalize front/back origins and allowed IdP redirects
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(cookieParser());

  // CORS: allow frontend origin; credentials needed for HttpOnly cookies.
  const appUrl = process.env.APP_PUBLIC_URL;
  if (appUrl) {
    app.enableCors({
      origin: appUrl,
      credentials: true,
    });
  }

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
