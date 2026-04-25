import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

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

  // Swagger (dev-only, gated by env flag). In prod we do not expose docs at all.
  const enableSwagger = process.env.ENABLE_SWAGGER === 'true';
  const nodeEnv = process.env.NODE_ENV ?? 'development';
  if (enableSwagger && nodeEnv === 'development') {
    const apiPublicUrl = process.env.API_PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? 3000}`;
    const config = new DocumentBuilder()
      .setTitle('IAM Core Service')
      .setDescription('Dev-only API docs (must be authenticated).')
      .setVersion('1.0')
      .addCookieAuth(process.env.SESSION_COOKIE_NAME ?? '__Host-iam_session', { type: 'apiKey', in: 'cookie' })
      .addBearerAuth(
        { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        'bearer',
      )
      .addServer(apiPublicUrl)
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document, {
      swaggerOptions: {
        persistAuthorization: true,
      },
    });
  }

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
